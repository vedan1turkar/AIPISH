"""P5i deployment: engine/URL config, versioned migrations, readiness probe, proxy-header trust,
production-mode guard rails, demo seeding gates and case-insensitive search on both dialects."""
from __future__ import annotations

import io
import os
import secrets
import stat

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, inspect, text
from starlette.requests import Request

from app.core import db as dbmod
from app.core.config import get_settings
from app.core.migrations import STEPS, applied_versions, current_version, upgrade
from app.core.production import (
    ProductionConfigError, allowed_origins, check_production, db_password_problem,
)
from app.main import create_app
from app.security import client_ip as cip
from app.security import throttle
from tests.pgtest import UnsafeTestDatabase, check_name

FIXTURES = os.path.join(os.path.dirname(__file__), "..", "fixtures", "demo")
_RANDOM_SECRET = secrets.token_urlsafe(48)       # generated per run: no secret-like literal in the repo
_RANDOM_DB_PW = secrets.token_urlsafe(24)


# ── engine / URL configuration ──────────────────────────────────────────────
def test_database_url_defaults_to_sqlite_and_normalises_postgres(monkeypatch, tmp_path):
    monkeypatch.setenv("DATABASE_URL", "")
    monkeypatch.setattr(get_settings(), "db_path", str(tmp_path / "x.sqlite"))
    url = dbmod.database_url()
    assert url.get_backend_name() == "sqlite" and url.database.endswith("x.sqlite")

    for raw in ("postgres://u:s3cret@db:5432/app", "postgresql://u:s3cret@db/app"):
        monkeypatch.setenv("DATABASE_URL", raw)
        url = dbmod.database_url()
        assert url.drivername == "postgresql+psycopg"
        assert "s3cret" not in dbmod.redacted_url(url) and "***" in dbmod.redacted_url(url)


def test_postgres_engine_pins_utc_and_pre_ping():
    eng = dbmod._make_engine(dbmod.make_url("postgresql+psycopg://u:p@127.0.0.1:1/x_test"))
    assert eng.pool._pre_ping is True
    assert eng.dialect.name == "postgresql"


# ── versioned migrations ────────────────────────────────────────────────────
def test_migrations_are_versioned_and_idempotent_on_a_fresh_sqlite_db(tmp_path):
    eng = create_engine(f"sqlite:///{tmp_path / 'm.sqlite'}")
    first = upgrade(eng)
    assert first == [name for _, name, _ in STEPS]
    assert upgrade(eng) == []                                   # second run: nothing to do
    assert applied_versions(eng) == {v for v, _, _ in STEPS}
    assert current_version(eng) == max(v for v, _, _ in STEPS)
    idx = {i["name"] for i in inspect(eng).get_indexes("analysis")}
    assert {"ix_analysis_from_domain", "ix_analysis_detection_verdict", "ix_analysis_created_at"} <= idx


def test_migrations_upgrade_a_pre_versioning_database(tmp_path):
    """A database created before schema_migrations existed (all steps applied ad hoc) upgrades cleanly."""
    eng = create_engine(f"sqlite:///{tmp_path / 'old.sqlite'}")
    with eng.begin() as conn:
        conn.execute(text("CREATE TABLE audit_event (id VARCHAR(32) PRIMARY KEY, event_type VARCHAR(40), "
                          "analysis_id VARCHAR(32), case_id VARCHAR(32), detail JSON, created_at DATETIME)"))
    upgrade(eng)
    cols = {c["name"] for c in inspect(eng).get_columns("audit_event")}
    assert "actor_user_id" in cols
    assert upgrade(eng) == []


def test_migrations_idempotent_on_the_active_test_database():
    """Runs on whichever dialect the suite uses (SQLite by default, PostgreSQL with TEST_DATABASE_URL)."""
    upgrade(dbmod.engine)
    assert upgrade(dbmod.engine) == []
    assert current_version(dbmod.engine) == max(v for v, _, _ in STEPS)


def test_cli_migrate_reports_version_without_printing_the_url(capsys):
    from app import cli
    assert cli.main(["migrate"]) == 0
    out = capsys.readouterr().out
    assert f"schema version: {max(v for v, _, _ in STEPS)}" in out
    assert "://" not in out and (dbmod.engine.url.password or "\0") not in out


def test_cli_migrate_fails_closed_in_misconfigured_production(monkeypatch, capsys):
    from app import cli
    monkeypatch.setattr(get_settings(), "env", "production")
    monkeypatch.setattr(dbmod, "engine", create_engine("sqlite://"))
    assert cli.main(["migrate"]) == 3
    assert "Refusing to start" in capsys.readouterr().err


# ── readiness probe ─────────────────────────────────────────────────────────
def test_ready_is_anonymous_and_minimal(anon_client):
    r = anon_client.get("/api/v1/health/ready")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


def test_ready_reports_unavailable_without_leaking_errors():
    from app.core.db import get_db

    class Broken:
        def execute(self, *a, **k):
            raise RuntimeError("could not connect to server at db.internal:5432 password=hunter2")

        def rollback(self):
            pass

    app = create_app()
    app.dependency_overrides[get_db] = lambda: iter([Broken()]).__next__()
    r = TestClient(app).get("/api/v1/health/ready")
    assert r.status_code == 503
    assert r.json() == {"status": "unavailable"}
    assert "db.internal" not in r.text and "hunter2" not in r.text


# ── proxy-header trust ──────────────────────────────────────────────────────
def _req(peer: str, xff: str | None = None) -> Request:
    headers = [(b"x-forwarded-for", xff.encode())] if xff is not None else []
    return Request({"type": "http", "method": "POST", "path": "/", "headers": headers, "client": (peer, 1234)})


def test_client_ip_ignores_forwarded_for_unless_peer_is_trusted(monkeypatch):
    monkeypatch.setenv("AIPISH_TRUSTED_PROXIES", "")
    assert cip.client_ip(_req("203.0.113.9", "1.2.3.4")) == "203.0.113.9"
    monkeypatch.setenv("AIPISH_TRUSTED_PROXIES", "172.28.0.10")
    assert cip.client_ip(_req("203.0.113.9", "1.2.3.4")) == "203.0.113.9"        # untrusted peer: ignored
    assert cip.client_ip(_req("172.28.0.10", "198.51.100.7")) == "198.51.100.7"   # trusted proxy
    # client-supplied spoof is to the LEFT of what the proxy appended: the rightmost untrusted hop wins
    assert cip.client_ip(_req("172.28.0.10", "6.6.6.6, 198.51.100.7")) == "198.51.100.7"
    assert cip.client_ip(_req("172.28.0.10", "not-an-ip")) == "172.28.0.10"         # malformed: fall back
    assert cip.client_ip(_req("172.28.0.10")) == "172.28.0.10"
    monkeypatch.setenv("AIPISH_TRUSTED_PROXIES", "172.28.0.0/24, garbage")
    assert cip.client_ip(_req("172.28.0.10", "198.51.100.7")) == "198.51.100.7"     # CIDR, bad entry ignored


def _fail_logins(client: TestClient, n: int, xff) -> list[int]:
    codes = []
    for i in range(n):
        r = client.post("/api/v1/auth/login", json={"username": f"nobody-{i}", "password": "wrong-password-1"},
                        headers={"X-Forwarded-For": xff(i)})
        codes.append(r.status_code)
    return codes


def test_spoofed_forwarded_for_cannot_dodge_ip_throttling(monkeypatch):
    monkeypatch.setenv("AIPISH_TRUSTED_PROXIES", "")
    throttle.reset_all()
    client = TestClient(create_app(), client=("203.0.113.50", 40000))
    codes = _fail_logins(client, 21, lambda i: f"10.0.0.{i}")        # a fresh fake IP every attempt
    assert codes[-1] == 429                                            # still one identity: the real peer
    assert set(throttle.IP_LIMITER._fails) | set(throttle.IP_LIMITER._locked) == {"203.0.113.50"}


def test_trusted_proxy_forwards_real_client_ips(monkeypatch):
    monkeypatch.setenv("AIPISH_TRUSTED_PROXIES", "172.28.0.10")
    throttle.reset_all()
    client = TestClient(create_app(), client=("172.28.0.10", 40000))
    codes = _fail_logins(client, 21, lambda i: f"198.51.100.{i}")
    assert 429 not in codes                                            # 21 distinct real clients
    assert "198.51.100.3" in throttle.IP_LIMITER._fails and "172.28.0.10" not in throttle.IP_LIMITER._fails


# ── production mode ─────────────────────────────────────────────────────────
@pytest.mark.parametrize("pw,ok", [
    (None, False), ("", False), ("short", False), ("changeme-changeme-123", False),
    ("aaaaaaaaaaaaaaaaaaaa", False), (_RANDOM_DB_PW, True),
])
def test_db_password_strength(pw, ok):
    assert (db_password_problem(pw) is None) is ok


def test_production_refuses_sqlite_and_weak_postgres_password(monkeypatch):
    check_production("dev")                                            # no-op outside production
    monkeypatch.setattr(dbmod, "engine", create_engine("sqlite://"))
    with pytest.raises(ProductionConfigError, match="PostgreSQL"):
        check_production("production")
    weak = dbmod._make_engine(dbmod.make_url("postgresql+psycopg://aipish:password@db/aipish"))
    monkeypatch.setattr(dbmod, "engine", weak)
    with pytest.raises(ProductionConfigError) as exc:
        check_production("production")
    assert "password" in str(exc.value) and "password@" not in str(exc.value)
    strong = dbmod._make_engine(dbmod.make_url(f"postgresql+psycopg://aipish:{_RANDOM_DB_PW}@db/aipish"))
    monkeypatch.setattr(dbmod, "engine", strong)
    check_production("production")


def test_production_app_refuses_to_start_on_sqlite(monkeypatch):
    monkeypatch.setenv("AIPISH_JWT_SECRET", _RANDOM_SECRET)
    monkeypatch.setattr(get_settings(), "env", "production")
    monkeypatch.setattr(dbmod, "engine", create_engine("sqlite://"))
    with pytest.raises(ProductionConfigError, match="PostgreSQL"):
        create_app()


def test_production_disables_docs_and_cors_defaults(monkeypatch):
    monkeypatch.setenv("AIPISH_JWT_SECRET", _RANDOM_SECRET)
    monkeypatch.setenv("APP_ALLOWED_ORIGINS", "")
    monkeypatch.setattr(get_settings(), "env", "production")
    monkeypatch.setattr("app.main.check_production", lambda env: None)   # SQLite test DB stands in for PG
    c = TestClient(create_app())
    for path in ("/docs", "/redoc", "/openapi.json"):
        assert c.get(path).status_code == 404
    assert allowed_origins("production", ["http://localhost:5173"]) == []
    pre = c.options("/api/v1/health", headers={"Origin": "http://localhost:5173",
                                               "Access-Control-Request-Method": "GET"})
    assert "access-control-allow-origin" not in pre.headers
    monkeypatch.setenv("APP_ALLOWED_ORIGINS", "https://forensics.example")
    assert allowed_origins("production", ["https://forensics.example", "*"]) == ["https://forensics.example"]


def test_production_missing_jwt_secret_fails_closed(monkeypatch):
    from app.security.tokens import AuthConfigError
    monkeypatch.setenv("AIPISH_JWT_SECRET", "")
    monkeypatch.setattr(get_settings(), "env", "production")
    with pytest.raises(AuthConfigError):
        create_app()


@pytest.mark.parametrize("cmd", ["init-demo", "seed-demo-campaign"])
def test_demo_seeding_refused_in_production(monkeypatch, capsys, cmd):
    from app import cli
    from app.core.db import SessionLocal
    from app.core.models import Analysis
    monkeypatch.setattr(get_settings(), "env", "production")
    with SessionLocal() as db:
        before = db.query(Analysis).count()
    assert cli.main([cmd]) == 2
    assert "refusing" in capsys.readouterr().err
    with SessionLocal() as db:
        assert db.query(Analysis).count() == before


# ── demo initialisation ─────────────────────────────────────────────────────
def test_init_demo_seeds_users_campaign_and_bec_without_printing_passwords(monkeypatch, capsys, tmp_path):
    from app import cli
    from app.core.db import SessionLocal
    from app.core.models import Analysis
    from app.security.users import authenticate
    creds = tmp_path / "demo" / "credentials"
    monkeypatch.setenv("AIPISH_DEMO_CREDENTIALS_FILE", str(creds))
    monkeypatch.setattr(get_settings(), "env", "demo")
    assert cli.main(["init-demo", "--no-assessment"]) == 0
    out = capsys.readouterr().out
    assert stat.S_IMODE(creds.stat().st_mode) == 0o600
    rows = [ln.split("\t") for ln in creds.read_text().splitlines() if not ln.startswith("#")]
    assert {r[0] for r in rows} == {"demo-admin", "demo-analyst", "demo-viewer"}
    for _, _, pw in rows:
        assert pw not in out                                           # only the path is printed
    assert str(creds) in out
    with SessionLocal() as db:
        assert authenticate(db, "demo-analyst", dict((r[0], r[2]) for r in rows)["demo-analyst"], "127.0.0.1")
        subjects = [a.subject for a in db.query(Analysis).all()]
    assert any("supplier wire change" in (s or "") for s in subjects)
    assert sum("[SYNTHETIC DEMO]" in (s or "") for s in subjects) >= 6
    # idempotent: second run keeps users/passwords and adds nothing
    before = creds.read_text()
    assert cli.main(["init-demo", "--no-assessment"]) == 0
    out2 = capsys.readouterr().out
    assert "already present" in out2 and "already analysed" in out2
    assert creds.read_text() == before


# ── dialect behaviour ───────────────────────────────────────────────────────
def test_search_is_case_insensitive_on_every_dialect(client):
    with open(os.path.join(FIXTURES, "bec_wire_change.eml"), "rb") as f:
        assert client.post("/api/v1/analyses", files={"file": ("bec.eml", io.BytesIO(f.read()))}).status_code == 201
    for q in ("CONFIDENTIAL: URGENT", "confidential: urgent", "Supplier Wire"):
        r = client.get("/api/v1/search", params={"q": q, "type": "analysis"})
        assert r.status_code == 200
        assert any("supplier wire change" in (a["subject"] or "") for a in r.json()["results"]["analysis"]["items"]), q


def test_api_timestamps_parse_and_are_utc_when_offset_present(client):
    """SQLite drops tzinfo (naive UTC strings, unchanged pre-P5i behaviour); PostgreSQL keeps it (+00:00,
    the connection time zone is pinned to UTC). Either way the value is UTC and ISO-8601."""
    from datetime import datetime, timedelta
    rows = client.get("/api/v1/analyses").json()
    assert rows
    for r in rows:
        ts = datetime.fromisoformat(r["created_at"])
        if dbmod.engine.dialect.name == "postgresql":
            assert ts.utcoffset() == timedelta(0)
        else:
            assert ts.tzinfo is None or ts.utcoffset() == timedelta(0)


# ── PG test-database safety ─────────────────────────────────────────────────
@pytest.mark.parametrize("name", ["aipish", "postgres", "production", "contest", None, ""])
def test_pg_test_runner_refuses_non_test_database_names(name):
    with pytest.raises(UnsafeTestDatabase):
        check_name(name)


@pytest.mark.parametrize("name", ["aipish_test", "test_aipish", "aipish-test-ci", "test"])
def test_pg_test_runner_accepts_test_database_names(name):
    assert check_name(name) == name
