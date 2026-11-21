"""P5b access-control tests: route inventory, login/lockout, JWT validation, RBAC, admin, fail-closed startup."""
from __future__ import annotations

import base64
import json
import logging
import os
import re
import stat
from datetime import datetime, timedelta, timezone
from pathlib import Path

import jwt
import pytest
from fastapi.routing import iter_route_contexts
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.config import get_settings
from app.core.db import Base, SessionLocal, get_db
from app.core.models import AuditEvent, User
from app.main import create_app
from app.security import throttle
from app.security.passwords import generate_password, hash_password, password_problems, verify_password
from app.security.permissions import (
    PUBLIC, ROLES, ROUTE_PERMISSIONS, role_allows,
)
from app.security.tokens import (
    AuthConfigError, create_access_token, decode_access_token, get_auth_config, secret_problem,
)
from tests.authutil import auth_headers, authed_client, make_user, token_for

EML = Path(__file__).resolve().parents[1] / "fixtures" / "eml"
STRONG_SECRET = "Tq7mW2pXv9LcR4nZb8KdF3hJs6YgE1uA0oQiN5"
# /health/ready (P5i): container readiness probe; anonymous by necessity (Docker/LB health checks carry
# no token) and returns only {"status": "ok"|"unavailable"} — no version, host, path or DB error.
PUBLIC_ALLOWLIST = {("GET", "/api/v1/health"), ("GET", "/api/v1/health/ready"), ("POST", "/api/v1/auth/login")}


# ── fixtures ─────────────────────────────────────────────────────────────
@pytest.fixture
def iso():
    """App bound to an isolated in-memory DB (for last-admin and counting tests)."""
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    app = create_app()
    app.dependency_overrides[get_db] = lambda: session
    yield app, session
    session.close()


@pytest.fixture
def db():
    s = SessionLocal()
    yield s
    s.close()


def _fresh(db, user: User) -> User:
    db.expire_all()
    return db.get(User, user.id)


def _login(c: TestClient, username: str, password: str):
    return c.post("/api/v1/auth/login", json={"username": username, "password": password})


def _upload(c: TestClient, name: str = "phishing_multipart.eml"):
    return c.post("/api/v1/analyses", files={"file": (name, (EML / name).read_bytes(), "message/rfc822")})


def _concrete(path: str) -> str:
    return re.sub(r"\{[^}]+\}", "doesnotexist0000", path)


def _inventory(app) -> list[tuple[str, str]]:
    out = set()
    for rc in iter_route_contexts(app.routes):
        path = getattr(rc, "path_format", None) or rc.path
        for m in rc.methods or ():
            if m != "HEAD":
                out.add((m, path))
    return sorted(out)


# ── route inventory ──────────────────────────────────────────────────────
def test_every_route_is_mapped_in_the_permission_map():
    app = create_app()
    routes = _inventory(app)
    assert len(routes) >= 30
    unmapped = [r for r in routes if r not in ROUTE_PERMISSIONS]
    assert unmapped == [], f"routes missing from ROUTE_PERMISSIONS (add a permission): {unmapped}"
    public = {r for r in routes if ROUTE_PERMISSIONS[r] == PUBLIC}
    assert public == PUBLIC_ALLOWLIST


def test_every_non_public_route_rejects_anonymous_with_401():
    app = create_app()
    c = TestClient(app)
    for method, path in _inventory(app):
        r = c.request(method, _concrete(path))
        if (method, path) in PUBLIC_ALLOWLIST:
            assert r.status_code != 401, (method, path)
            continue
        assert r.status_code == 401, (method, path, r.status_code)
        assert r.headers.get("www-authenticate", "").startswith("Bearer"), (method, path)


def test_role_matrix_over_every_route(db, monkeypatch):
    import app.llm.service as llm_service
    monkeypatch.setattr(llm_service, "status", lambda: {"status": "unavailable"})   # no Ollama call
    app = create_app()
    c = TestClient(app)
    users = {role: make_user(db, role)[0] for role in ROLES}
    for method, path in _inventory(app):
        perm = ROUTE_PERMISSIONS[(method, path)]
        if perm == PUBLIC:
            continue
        for role, u in users.items():
            u = _fresh(db, u)                        # logout bumps token_version; re-issue each time
            r = c.request(method, _concrete(path), headers=auth_headers(u))
            if role_allows(role, perm):
                assert r.status_code not in (401, 403), (role, method, path, r.status_code, r.text)
            else:
                assert r.status_code == 403, (role, method, path, r.status_code)
                assert r.json()["error"]["code"] == "FORBIDDEN"


def test_new_unmapped_route_is_denied_and_detected():
    app = create_app()

    @app.get("/api/v1/brand-new-endpoint")
    def brand_new() -> dict:
        return {"secret": "data"}

    assert ("GET", "/api/v1/brand-new-endpoint") in [r for r in _inventory(app) if r not in ROUTE_PERMISSIONS]
    assert TestClient(app).get("/api/v1/brand-new-endpoint").status_code == 401
    r = authed_client(app, "admin").get("/api/v1/brand-new-endpoint")
    assert r.status_code == 403 and r.json()["error"]["code"] == "ROUTE_NOT_PERMITTED"


# ── login ────────────────────────────────────────────────────────────────
def test_login_success_returns_token_and_no_hash(anon_client, db):
    u, pw = make_user(db, "analyst")
    r = _login(anon_client, u.username.upper(), pw)            # usernames are case-insensitive
    assert r.status_code == 200
    body = r.json()
    assert body["token_type"] == "bearer" and body["user"]["role"] == "analyst"
    assert "password" not in json.dumps(body).lower().replace("must_change_password", "")
    assert "scrypt$" not in r.text
    claims = decode_access_token(body["access_token"])
    assert claims["sub"] == u.id and claims["role"] == "analyst" and claims["tv"] == 0
    assert claims["iss"] == "aipish" and claims["aud"] == "aipish-api" and claims["jti"]
    assert claims["exp"] - claims["iat"] == 60 * 60
    me = anon_client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {body['access_token']}"})
    assert me.status_code == 200 and me.json()["username"] == u.username


def test_login_failures_are_generic(anon_client, db):
    u, pw = make_user(db, "viewer")
    d, dpw = make_user(db, "viewer", is_active=False)
    bodies = [
        _login(anon_client, "no-such-user-xyz", "whatever-password-1"),
        _login(anon_client, u.username, "wrong-password-123"),
        _login(anon_client, d.username, dpw),                    # disabled, correct password
    ]
    for r in bodies:
        assert r.status_code == 401
        assert r.json() == {"error": {"code": "INVALID_CREDENTIALS", "message": "invalid credentials"}}


def test_lockout_after_repeated_failures_hides_password_correctness(anon_client, db):
    u, pw = make_user(db, "analyst")
    for _ in range(4):
        assert _login(anon_client, u.username, "wrong-password-123").status_code == 401
    r = _login(anon_client, u.username, "wrong-password-123")      # 5th failure triggers lockout
    assert r.status_code == 401
    wrong = _login(anon_client, u.username, "wrong-password-123")
    right = _login(anon_client, u.username, pw)
    for r in (wrong, right):
        assert r.status_code == 429
        assert int(r.headers["Retry-After"]) > 0
        assert r.json()["error"]["code"] == "TOO_MANY_ATTEMPTS"
    assert wrong.json() == right.json()
    assert _fresh(db, u).locked_until is not None
    events = {e.event_type for e in db.query(AuditEvent).filter(AuditEvent.event_type.like("login%")).all()}
    assert {"login_failed", "login_lockout", "login_throttled"} <= events


def test_lockout_persists_in_db_after_memory_reset(anon_client, db):
    u, pw = make_user(db, "analyst")
    for _ in range(5):
        _login(anon_client, u.username, "wrong-password-123")
    throttle.reset_all()                                          # simulate a restart
    assert _login(anon_client, u.username, pw).status_code == 429


def test_per_ip_throttle_across_usernames(anon_client, db):
    u, pw = make_user(db, "viewer")
    for i in range(20):
        _login(anon_client, f"spray-{i}", "wrong-password-123")
    r = _login(anon_client, u.username, pw)
    assert r.status_code == 429 and "Retry-After" in r.headers


def test_throttle_is_bounded():
    lim = throttle.FailureLimiter(max_failures=3, window=60, lockout=60, max_keys=50)
    for i in range(500):
        lim.fail(f"k{i}")
    assert len(lim) <= 50 and len(lim._locked) <= 50


def test_successful_login_resets_user_failures(anon_client, db):
    u, pw = make_user(db, "viewer")
    for _ in range(4):
        _login(anon_client, u.username, "wrong-password-123")
    assert _login(anon_client, u.username, pw).status_code == 200
    for _ in range(4):
        _login(anon_client, u.username, "wrong-password-123")
    assert _login(anon_client, u.username, pw).status_code == 200


# ── JWT validation ───────────────────────────────────────────────────────
def _b64(obj) -> str:
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()


def _get(c, token):
    return c.get("/api/v1/analyses", headers={"Authorization": f"Bearer {token}"})


def test_expired_token_rejected(anon_client, db):
    u, _ = make_user(db, "viewer")
    tok, _ = create_access_token(u, now=datetime.now(timezone.utc) - timedelta(hours=2))
    r = _get(anon_client, tok)
    assert r.status_code == 401 and r.json()["error"]["code"] == "TOKEN_EXPIRED"
    assert 'error="invalid_token"' in r.headers["www-authenticate"]


def test_bad_tokens_rejected(anon_client, db):
    u, _ = make_user(db, "viewer")
    cfg = get_auth_config()
    now = int(datetime.now(timezone.utc).timestamp())
    base = {"sub": u.id, "role": "viewer", "tv": 0, "jti": "x", "iat": now, "exp": now + 600,
            "iss": cfg.issuer, "aud": cfg.audience}
    good = token_for(u)
    h, p, s = good.split(".")
    tampered_payload = _b64({**json.loads(base64.urlsafe_b64decode(p + "==")), "role": "admin"})
    cases = {
        "wrong_signature": jwt.encode(base, "another-secret-that-is-long-enough-0123456789", algorithm="HS256"),
        "alg_none": f"{_b64({'alg': 'none', 'typ': 'JWT'})}.{_b64(base)}.",
        "alg_hs512": jwt.encode(base, cfg.secret, algorithm="HS512"),
        "wrong_iss": jwt.encode({**base, "iss": "evil"}, cfg.secret, algorithm="HS256"),
        "wrong_aud": jwt.encode({**base, "aud": "other"}, cfg.secret, algorithm="HS256"),
        "missing_exp": jwt.encode({k: v for k, v in base.items() if k != "exp"}, cfg.secret, algorithm="HS256"),
        "tampered_claims": f"{h}.{tampered_payload}.{s}",
        "garbage": "not-a-jwt",
        "unknown_user": jwt.encode({**base, "sub": "nouser"}, cfg.secret, algorithm="HS256"),
    }
    for name, tok in cases.items():
        r = _get(anon_client, tok)
        assert r.status_code == 401, name
        assert tok not in r.text and cfg.secret not in r.text
    assert _get(anon_client, good).status_code == 200
    assert anon_client.get("/api/v1/analyses", headers={"Authorization": f"Basic {good}"}).status_code == 401


def test_token_version_invalidation(anon_client, db):
    admin = authed_client(role="admin")
    # password change
    u, pw = make_user(db, "analyst")
    old = token_for(u)
    r = anon_client.post("/api/v1/auth/change-password", headers={"Authorization": f"Bearer {old}"},
                         json={"current_password": pw, "new_password": "Fresh-Orchid-Lantern-42"})
    assert r.status_code == 200
    assert _get(anon_client, old).status_code == 401
    assert _get(anon_client, r.json()["access_token"]).status_code == 200
    assert _login(anon_client, u.username, "Fresh-Orchid-Lantern-42").status_code == 200
    # role change
    u, _ = make_user(db, "analyst")
    old = token_for(u)
    assert admin.patch(f"/api/v1/admin/users/{u.id}", json={"role": "viewer"}).status_code == 200
    r = _get(anon_client, old)
    assert r.status_code == 401 and r.json()["error"]["code"] == "SESSION_REVOKED"
    # disable
    u, _ = make_user(db, "analyst")
    old = token_for(u)
    assert admin.patch(f"/api/v1/admin/users/{u.id}", json={"is_active": False}).status_code == 200
    assert _get(anon_client, old).status_code == 401
    # logout (all sessions of the user)
    u, _ = make_user(db, "viewer")
    t1, t2 = token_for(u), token_for(u)
    assert anon_client.post("/api/v1/auth/logout", headers={"Authorization": f"Bearer {t1}"}).status_code == 200
    assert _get(anon_client, t1).status_code == 401 and _get(anon_client, t2).status_code == 401
    # deleted user
    u, _ = make_user(db, "viewer")
    tok = token_for(u)
    db.delete(_fresh(db, u))
    db.commit()
    assert _get(anon_client, tok).status_code == 401


# ── role matrix (explicit, with real data) ───────────────────────────────
def test_viewer_reads_and_downloads_but_cannot_act(db):
    analyst = authed_client(role="analyst")
    viewer = authed_client(role="viewer")
    up = _upload(analyst)
    assert up.status_code == 201
    aid = up.json()["id"]
    case = analyst.post(f"/api/v1/investigations/from-analysis/{aid}")
    assert case.status_code == 201
    cid = case.json()["id"]

    for r in (
        _upload(viewer),
        viewer.post(f"/api/v1/analyses/{aid}/threat-intel", json={"consent": False}),
        viewer.post(f"/api/v1/analyses/{aid}/forensic-summary"),
        viewer.post(f"/api/v1/investigations/from-analysis/{aid}"),
        viewer.post("/api/v1/ml/classify", files={"file": ("a.eml", b"Subject: x\n\nhi", "message/rfc822")}),
        viewer.post("/api/v1/llm/forensic-summary", files={"file": ("a.eml", b"Subject: x\n\nhi", "message/rfc822")}),
        viewer.get("/api/v1/admin/users"),
        viewer.get("/api/v1/intel/status"),
    ):
        assert r.status_code == 403, r.text

    assert viewer.get("/api/v1/analyses").status_code == 200
    assert viewer.get(f"/api/v1/analyses/{aid}").status_code == 200
    assert viewer.get(f"/api/v1/investigations/{cid}").status_code == 200
    assert viewer.get(f"/api/v1/analyses/{aid}/assessments").status_code == 200
    pdf = viewer.get(f"/api/v1/investigations/{cid}/report/{aid}")
    assert pdf.status_code == 200 and pdf.content.startswith(b"%PDF")
    assert pdf.headers["cache-control"] == "no-store"


def test_analyst_acts_but_cannot_administer(db):
    analyst = authed_client(role="analyst")
    up = _upload(analyst)
    assert up.status_code == 201
    aid = up.json()["id"]
    run = analyst.post(f"/api/v1/analyses/{aid}/threat-intel", json={"consent": False})
    assert run.status_code == 201 and run.json()["consent"]["granted"] is False
    for r in (analyst.get("/api/v1/admin/users"),
              analyst.post("/api/v1/admin/users", json={"username": "x-new", "role": "admin"}),
              analyst.get("/api/v1/intel/status"), analyst.get("/api/v1/llm/status"),
              analyst.get("/openapi.json")):
        assert r.status_code == 403


def test_admin_can_administer_and_view_config():
    admin = authed_client(role="admin")
    assert admin.get("/api/v1/admin/users").status_code == 200
    assert admin.get("/api/v1/intel/status").status_code == 200
    assert admin.get("/openapi.json").status_code == 200


# ── docs ─────────────────────────────────────────────────────────────────
def test_docs_require_admin(anon_client):
    for path in ("/docs", "/redoc", "/openapi.json"):
        assert anon_client.get(path).status_code == 401
        assert authed_client(role="viewer").get(path).status_code == 403
        assert authed_client(role="admin").get(path).status_code == 200


def test_docs_absent_outside_dev(monkeypatch):
    monkeypatch.setattr(get_settings(), "env", "prod")
    monkeypatch.setenv("AIPISH_JWT_SECRET", STRONG_SECRET)
    app = create_app()
    c = authed_client(app, "admin")
    for path in ("/docs", "/redoc", "/openapi.json"):
        assert c.get(path).status_code == 404


# ── admin user management ────────────────────────────────────────────────
def test_admin_create_user_must_change_flow(anon_client):
    admin = authed_client(role="admin")
    sfx = os.urandom(3).hex()
    r = admin.post("/api/v1/admin/users", json={"username": f"New.Person-{sfx}", "role": "analyst"})
    assert r.status_code == 201
    body = r.json()
    temp = body["temporary_password"]
    assert body["user"]["username"] == f"new.person-{sfx}" and body["user"]["must_change_password"] is True
    assert "password_hash" not in r.text and "scrypt$" not in r.text
    dup = admin.post("/api/v1/admin/users", json={"username": f"NEW.PERSON-{sfx}", "role": "viewer"})
    assert dup.status_code == 409

    tok = _login(anon_client, f"new.person-{sfx}", temp).json()["access_token"]
    h = {"Authorization": f"Bearer {tok}"}
    blocked = anon_client.get("/api/v1/analyses", headers=h)
    assert blocked.status_code == 403 and blocked.json()["error"]["code"] == "PASSWORD_CHANGE_REQUIRED"
    assert anon_client.get("/api/v1/auth/me", headers=h).status_code == 200
    r = anon_client.post("/api/v1/auth/change-password", headers=h,
                         json={"current_password": temp, "new_password": "Quiet-River-Stone-77"})
    assert r.status_code == 200 and r.json()["user"]["must_change_password"] is False
    assert _get(anon_client, r.json()["access_token"]).status_code == 200


def test_admin_reset_password_revokes_and_returns_once(anon_client, db):
    admin = authed_client(role="admin")
    u, pw = make_user(db, "viewer")
    old = token_for(u)
    r = admin.post(f"/api/v1/admin/users/{u.id}/reset-password")
    assert r.status_code == 200
    temp = r.json()["temporary_password"]
    assert _get(anon_client, old).status_code == 401
    assert _login(anon_client, u.username, pw).status_code == 401
    assert _login(anon_client, u.username, temp).json()["user"]["must_change_password"] is True
    listing = admin.get("/api/v1/admin/users").text
    assert temp not in listing and "scrypt$" not in listing and "password_hash" not in listing
    assert admin.post("/api/v1/admin/users/nope/reset-password").status_code == 404


def test_last_admin_protection(iso):
    app, session = iso
    a, _ = make_user(session, "admin")
    c = TestClient(app)
    h = lambda: auth_headers(_fresh(session, a))  # noqa: E731
    for body in ({"role": "analyst"}, {"is_active": False}):
        r = c.patch(f"/api/v1/admin/users/{a.id}", json=body, headers=h())
        assert r.status_code == 409 and r.json()["error"]["code"] == "LAST_ADMIN"
    b, _ = make_user(session, "admin")
    assert c.patch(f"/api/v1/admin/users/{a.id}", json={"role": "analyst"}, headers=h()).status_code == 200
    # b is now the last admin; a (analyst) cannot act, b cannot demote itself
    r = c.patch(f"/api/v1/admin/users/{b.id}", json={"is_active": False}, headers=auth_headers(_fresh(session, b)))
    assert r.status_code == 409
    assert c.patch(f"/api/v1/admin/users/{b.id}", json={"role": "viewer"}, headers=h()).status_code == 403


def test_admin_validation_errors():
    admin = authed_client(role="admin")
    assert admin.post("/api/v1/admin/users", json={"username": "ok-name", "role": "root"}).status_code == 400
    assert admin.post("/api/v1/admin/users", json={"username": "bad name!", "role": "viewer"}).status_code == 400
    assert admin.patch("/api/v1/admin/users/nope", json={"role": "viewer"}).status_code == 404


# ── password policy & hashing ────────────────────────────────────────────
def test_password_policy():
    assert password_problems("short-1A") != []
    assert password_problems("x" * 129 + "Ab1") != []
    assert password_problems("aaaaaaaaaaaaaaaa") != []
    assert password_problems("Password123!") != []
    assert password_problems("abcdefghijklmnop") != []
    assert password_problems("analyst-analyst", "analyst") != []
    assert password_problems("Gentle-Harbor-Kite-9") == []
    assert password_problems(generate_password()) == []


def test_hashing_salted_and_verifiable():
    h1, h2 = hash_password("Gentle-Harbor-Kite-9"), hash_password("Gentle-Harbor-Kite-9")
    assert h1 != h2 and h1.startswith("scrypt$")
    assert verify_password("Gentle-Harbor-Kite-9", h1) and not verify_password("gentle-harbor-kite-9", h1)
    assert not verify_password("anything", "malformed")


def test_change_password_policy_and_wrong_current(anon_client, db):
    u, pw = make_user(db, "viewer")
    h = {"Authorization": f"Bearer {token_for(u)}"}
    r = anon_client.post("/api/v1/auth/change-password", headers=h,
                         json={"current_password": "wrong-password-1", "new_password": "Gentle-Harbor-Kite-9"})
    assert r.status_code == 400 and r.json()["error"]["code"] == "INVALID_CURRENT_PASSWORD"
    for new in ("short", u.username, pw):
        r = anon_client.post("/api/v1/auth/change-password", headers=h,
                             json={"current_password": pw, "new_password": new})
        assert r.status_code == 400
        assert new not in r.json()["error"]["message"] or new == "short"


# ── no secrets in logs, responses or audit ───────────────────────────────
def test_no_password_token_or_secret_in_logs_or_audit(anon_client, db, caplog):
    caplog.set_level(logging.DEBUG)
    u, pw = make_user(db, "analyst")
    _login(anon_client, u.username, "Wrong-Guess-Value-1")
    tok = _login(anon_client, u.username, pw).json()["access_token"]
    anon_client.get("/api/v1/analyses", headers={"Authorization": f"Bearer {tok}"})
    anon_client.get("/api/v1/analyses", headers={"Authorization": "Bearer forged.token.value"})
    anon_client.post("/api/v1/auth/logout", headers={"Authorization": f"Bearer {tok}"})
    audit = json.dumps([e.detail for e in db.query(AuditEvent).all()])
    blob = caplog.text + audit
    for s in (pw, "Wrong-Guess-Value-1", tok, get_auth_config().secret, "forged.token.value"):
        assert s not in blob


def test_audit_records_actor(db):
    analyst = authed_client(role="analyst")
    viewer = authed_client(role="viewer")
    me_a = analyst.get("/api/v1/auth/me").json()["id"]
    me_v = viewer.get("/api/v1/auth/me").json()["id"]
    aid = _upload(analyst).json()["id"]
    cid = analyst.post(f"/api/v1/investigations/from-analysis/{aid}").json()["id"]
    analyst.post(f"/api/v1/analyses/{aid}/threat-intel", json={"consent": False})
    viewer.get(f"/api/v1/investigations/{cid}/report/{aid}")
    db.expire_all()
    ev = {e.event_type: e.actor_user_id for e in db.query(AuditEvent).filter(AuditEvent.analysis_id == aid).all()}
    assert ev["analysis_created"] == me_a
    assert ev["threat_intel_lookup"] == me_a
    assert ev["report_generated"] == me_v


# ── headers / CORS ───────────────────────────────────────────────────────
def test_security_headers_and_cors(anon_client):
    r = anon_client.get("/api/v1/health")
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["x-frame-options"] == "DENY"
    assert "frame-ancestors 'none'" in r.headers["content-security-policy"]
    assert r.headers["referrer-policy"] == "no-referrer"
    assert r.headers["cache-control"] == "no-store"
    pre = {"Access-Control-Request-Method": "GET", "Access-Control-Request-Headers": "authorization"}
    ok = anon_client.options("/api/v1/analyses", headers={"Origin": "http://localhost:5173", **pre})
    assert ok.headers.get("access-control-allow-origin") == "http://localhost:5173"
    assert ok.headers.get("access-control-allow-credentials") is None
    bad = anon_client.options("/api/v1/analyses", headers={"Origin": "https://evil.example", **pre})
    assert "access-control-allow-origin" not in bad.headers


def test_wildcard_origin_is_dropped(monkeypatch):
    monkeypatch.setattr(get_settings(), "allowed_origins", ["*", "http://localhost:5173"])
    c = TestClient(create_app())
    r = c.get("/api/v1/health", headers={"Origin": "https://evil.example"})
    assert r.headers.get("access-control-allow-origin") is None


# ── fail-closed startup ──────────────────────────────────────────────────
@pytest.mark.parametrize("value", ["", "short-secret", "change-me-please-change-me-please-123456",
                                   "a" * 64, "your-jwt-secret-goes-here-0123456789abcdef"])
@pytest.mark.parametrize("app_env", ["dev", "prod", "offline"])
def test_startup_fails_closed_without_strong_secret(monkeypatch, value, app_env):
    monkeypatch.setattr(get_settings(), "env", app_env)
    monkeypatch.setenv("AIPISH_JWT_SECRET", value)
    with pytest.raises(AuthConfigError) as ei:
        create_app()
    if value:
        assert value not in str(ei.value)


def test_startup_ok_with_strong_secret(monkeypatch):
    monkeypatch.setattr(get_settings(), "env", "dev")
    monkeypatch.setenv("AIPISH_JWT_SECRET", STRONG_SECRET)
    assert create_app() is not None
    assert secret_problem(STRONG_SECRET) is None


# ── CLI ──────────────────────────────────────────────────────────────────
def test_cli_create_user_reads_env_password(monkeypatch, capsys, db):
    from app import cli
    monkeypatch.setenv("AIPISH_NEW_USER_PASSWORD", "Calm-Valley-Ember-31")
    name = f"cli-made-{os.urandom(3).hex()}"
    assert cli.main(["create-user", "--username", name, "--role", "viewer"]) == 0
    out = capsys.readouterr()
    assert "Calm-Valley-Ember-31" not in out.out + out.err
    u = db.query(User).filter_by(username=name).one()
    assert verify_password("Calm-Valley-Ember-31", u.password_hash)
    monkeypatch.setenv("AIPISH_NEW_USER_PASSWORD", "weak")
    assert cli.main(["create-user", "--username", "cli-weak-user", "--role", "viewer"]) == 2
    with pytest.raises(SystemExit):           # no --password option exists
        cli.main(["create-user", "--username", "x-y-z", "--role", "viewer", "--password", "P"])


def test_cli_seed_refuses_outside_dev(capsys):
    from app import cli
    assert cli.main(["seed-dev-users"]) == 2        # APP_ENV=test in the test run


def test_cli_seed_dev_writes_private_file_and_prints_only_path(monkeypatch, tmp_path, capsys, db):
    from app import cli
    monkeypatch.setattr(get_settings(), "env", "dev")
    target = tmp_path / ".dev_credentials"
    monkeypatch.setattr(cli, "DEV_CREDENTIALS", target)
    assert cli.main(["seed-dev-users"]) == 0
    out = capsys.readouterr().out
    assert str(target) in out
    assert stat.S_IMODE(os.stat(target).st_mode) == 0o600
    rows = [ln.split("\t") for ln in target.read_text().splitlines() if not ln.startswith("#")]
    assert {r[0] for r in rows} == {"demo-admin", "demo-analyst", "demo-viewer"}
    for username, role, pw in rows:
        assert pw not in out
        db.expire_all()
        u = db.query(User).filter_by(username=username).one()
        assert u.role == role and verify_password(pw, u.password_hash)


def test_dev_credentials_file_is_gitignored():
    root = Path(__file__).resolve().parents[3]
    assert ".dev_credentials" in (root / ".gitignore").read_text().split()


def test_migrate_audit_actor_upgrades_pre_p5b_database(tmp_path):
    from sqlalchemy import inspect, text
    from app.core.models import migrate_audit_actor
    eng = create_engine(f"sqlite:///{tmp_path / 'old.sqlite'}")
    with eng.begin() as conn:     # the pre-P5b audit_event schema
        conn.execute(text("CREATE TABLE audit_event (id VARCHAR(32) PRIMARY KEY, event_type VARCHAR(40), "
                          "analysis_id VARCHAR(32), case_id VARCHAR(32), detail JSON, created_at DATETIME)"))
        conn.execute(text("INSERT INTO audit_event (id, event_type) VALUES ('e1', 'report_generated')"))
    assert migrate_audit_actor(eng) is True
    assert migrate_audit_actor(eng) is False            # idempotent
    assert "actor_user_id" in {c["name"] for c in inspect(eng).get_columns("audit_event")}
    with eng.connect() as conn:
        assert conn.execute(text("SELECT event_type, actor_user_id FROM audit_event")).all() == [("report_generated", None)]


def test_cli_disable_user_revokes_and_protects_last_admin(monkeypatch, iso, capsys):
    from app import cli
    app, session = iso
    monkeypatch.setattr(cli, "_session", lambda: session)
    monkeypatch.setattr(session, "close", lambda: None)
    u, _ = make_user(session, "viewer")
    tok = token_for(u)
    assert cli.main(["disable-user", "--username", u.username]) == 0
    assert TestClient(app).get("/api/v1/analyses", headers={"Authorization": f"Bearer {tok}"}).status_code == 401
    a, _ = make_user(session, "admin")
    assert cli.main(["disable-user", "--username", a.username]) == 2          # last active admin
    assert cli.main(["disable-user", "--username", "nobody-here"]) == 2
    assert session.query(AuditEvent).filter_by(event_type="user_disabled").count() == 1
