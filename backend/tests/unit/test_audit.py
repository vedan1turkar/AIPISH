"""P5e: tamper-evident audit chain, audit coverage, retention/legal holds/erasure and PII masking.

Runs on SQLite by default and on PostgreSQL with TEST_DATABASE_URL (make test-pg)."""
from __future__ import annotations

import json
import os
import re
import stat
import threading
from datetime import timedelta

import pytest
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import Session, sessionmaker

from app.audit import GUARANTEE
from app.audit.chain import GENESIS_PREV, compute_hash, ensure_triggers, verify
from app.cases.service import record_audit
from app.core import db as dbmod
from app.core.config import get_settings
from app.core.migrations import upgrade
from app.core.models import (
    Analysis, AuditEvent, Campaign, CampaignMember, CaseAnalysisLink, Entity, LegalHold, Observation, utcnow,
)
from app.main import create_app
from app.retention import service as retention
from tests.authutil import authed_client

FIX = os.path.join(os.path.dirname(__file__), "..", "fixtures", "demo")
BEC = os.path.join(FIX, "bec_wire_change.eml")
BODY_PHRASE = "please action before end of day"
DISPLAY = "Dana Finance Director"
EMAILS = ("dana@internal-corp.example", "finance-team@internal-corp.example",
          "dana.doe.personal+urgent@fastmail-temp.net")
SUBJECT = "Confidential: urgent supplier wire change"


def _upload(client, path=BEC, name="m.eml") -> str:
    with open(path, "rb") as f:
        r = client.post("/api/v1/analyses", files={"file": (name, f.read())})
    assert r.status_code == 201, r.text
    return r.json()["id"]


def _unique_bec() -> str:
    """A BEC copy with a unique Message-ID so each test gets its own analysis (sha differs)."""
    import secrets
    data = open(BEC, "rb").read().replace(b"Subject:", f"X-Test-Nonce: {secrets.token_hex(6)}\r\nSubject:".encode(), 1)
    path = os.path.join(os.environ.get("TMPDIR", "/tmp"), f"bec-{secrets.token_hex(4)}.eml")
    with open(path, "wb") as f:
        f.write(data)
    return path


@pytest.fixture
def admin():
    return authed_client(create_app(), "admin")


@pytest.fixture
def analyst():
    return authed_client(create_app(), "analyst")


@pytest.fixture
def viewer():
    return authed_client(create_app(), "viewer")


def _events(db: Session, **flt) -> list[AuditEvent]:
    return db.query(AuditEvent).filter_by(**flt).order_by(AuditEvent.seq).all()


# ── chain: append / verify on the active database (SQLite or PostgreSQL) ───────
def test_chain_appends_and_verifies(admin):
    _upload(admin, _unique_bec())
    r = admin.get("/api/v1/audit/verify")
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True and body["first_broken_seq"] is None and body["checked"] > 0
    assert "not tamper-proof" in body["guarantee"] and "immutable" not in body["guarantee"].lower()
    with dbmod.SessionLocal() as db:
        rows = db.query(AuditEvent).order_by(AuditEvent.seq).all()
        assert [r.seq for r in rows] == list(range(1, len(rows) + 1))
        assert rows[0].prev_hash == GENESIS_PREV
        assert all(rows[i].prev_hash == rows[i - 1].event_hash for i in range(1, len(rows)))
        assert any(r.event_type == "chain_genesis" for r in rows)


def test_triggers_block_update_and_delete_on_active_dialect():
    with dbmod.SessionLocal() as db:
        record_audit(db, "test_event", target_type="test")
        db.commit()
    for stmt in ("UPDATE audit_event SET event_type = 'forged' WHERE seq = 1", "DELETE FROM audit_event WHERE seq = 1"):
        with pytest.raises(Exception) as exc:
            with dbmod.engine.begin() as conn:
                conn.execute(text(stmt))
        assert "append-only" in str(exc.value)
    with dbmod.SessionLocal() as db:
        assert verify(db)["ok"] is True


@pytest.mark.skipif(dbmod.engine.dialect.name != "postgresql", reason="PostgreSQL-only: trigger disable + rollback")
def test_pg_tamper_detected_inside_rolled_back_transaction():
    with dbmod.SessionLocal() as db:
        record_audit(db, "test_event", target_type="test", detail={"n": 1})
        db.commit()
        target = db.query(AuditEvent).order_by(AuditEvent.seq.desc()).first().seq
    with dbmod.engine.connect() as conn:
        trans = conn.begin()
        conn.execute(text("ALTER TABLE audit_event DISABLE TRIGGER USER"))
        conn.execute(text("UPDATE audit_event SET detail = CAST(:d AS JSON) WHERE seq = :s"),
                     {"d": json.dumps({"n": 2}), "s": target})
        res = verify(Session(bind=conn))
        trans.rollback()
    assert res["ok"] is False and res["first_broken_seq"] == target and "content was changed" in res["reason"]
    with dbmod.SessionLocal() as db:
        assert verify(db)["ok"] is True                         # rolled back: intact again


# ── chain: tampering on an isolated SQLite database (triggers dropped by the harness) ──
@pytest.fixture
def iso(tmp_path):
    eng = create_engine(f"sqlite:///{tmp_path / 'audit.sqlite'}")
    upgrade(eng)
    S = sessionmaker(bind=eng)
    with S() as db:
        for i in range(6):
            record_audit(db, "test_event", target_type="test", detail={"i": i})
        db.commit()
    yield eng, S
    eng.dispose()


def _drop_triggers(eng):
    with eng.begin() as conn:
        conn.execute(text("DROP TRIGGER IF EXISTS audit_event_no_update"))
        conn.execute(text("DROP TRIGGER IF EXISTS audit_event_no_delete"))


def test_isolated_chain_ok(iso):
    eng, S = iso
    with S() as db:
        r = verify(db)
    assert r["ok"] and r["checked"] == 7                      # genesis + 6


@pytest.mark.parametrize("attack,expect_seq,reason", [
    ("modify", 4, "content was changed"),
    ("delete_middle", 4, "missing"),
    ("delete_last", 7, "head mismatch"),
    ("reorder", 3, "prev_hash"),
    ("insert", 8, "content was changed"),
])
def test_tamper_detection(iso, attack, expect_seq, reason):
    eng, S = iso
    _drop_triggers(eng)
    with eng.begin() as conn:
        if attack == "modify":
            conn.execute(text("UPDATE audit_event SET detail = '{\"i\": 99}' WHERE seq = 4"))
        elif attack == "delete_middle":
            conn.execute(text("DELETE FROM audit_event WHERE seq = 4"))
        elif attack == "delete_last":
            conn.execute(text("DELETE FROM audit_event WHERE seq = 7"))
        elif attack == "reorder":
            conn.execute(text("UPDATE audit_event SET seq = -1 WHERE seq = 3"))
            conn.execute(text("UPDATE audit_event SET seq = 3 WHERE seq = 4"))
            conn.execute(text("UPDATE audit_event SET seq = 4 WHERE seq = -1"))
        elif attack == "insert":
            conn.execute(text("INSERT INTO audit_event (id, event_type, detail, created_at, seq, prev_hash, event_hash) "
                              "SELECT 'forged', 'admin_backdoor', '{}', created_at, 8, event_hash, :h "
                              "FROM audit_event WHERE seq = 7"), {"h": "f" * 64})
            conn.execute(text("UPDATE audit_chain_head SET seq = 8, last_hash = :h"), {"h": "f" * 64})
    with S() as db:
        r = verify(db)
    assert r["ok"] is False
    assert r["first_broken_seq"] == expect_seq, r
    assert reason in r["reason"]


def test_wrong_key_fails_verification(iso):
    eng, S = iso
    with S() as db:
        assert verify(db, key=b"x" * 48)["ok"] is False


def test_triggers_on_isolated_sqlite(iso):
    eng, _ = iso
    for stmt in ("UPDATE audit_event SET event_type='x'", "DELETE FROM audit_event"):
        with pytest.raises(Exception, match="append-only"):
            with eng.begin() as conn:
                conn.execute(text(stmt))


def test_concurrent_appends_keep_a_valid_chain(iso):
    eng, S = iso
    errors: list[BaseException] = []

    def worker(n: int):
        try:
            for i in range(8):
                with S() as db:
                    record_audit(db, "concurrent", target_type="test", detail={"w": n, "i": i})
                    db.commit()
        except BaseException as exc:      # noqa: BLE001
            errors.append(exc)

    eng.dispose()
    threads = [threading.Thread(target=worker, args=(n,)) for n in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors, errors
    with S() as db:
        r = verify(db)
        assert r["ok"] and r["checked"] == 7 + 32


def test_concurrent_appends_on_active_dialect():
    errors = []

    def worker(n):
        try:
            for i in range(5):
                with dbmod.SessionLocal() as db:
                    record_audit(db, "concurrent", target_type="test", detail={"w": n, "i": i})
                    db.commit()
        except BaseException as exc:      # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(3)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert not errors
    with dbmod.SessionLocal() as db:
        assert verify(db)["ok"] is True


def test_genesis_backfill_is_idempotent_and_never_rewrites_content(tmp_path):
    eng = create_engine(f"sqlite:///{tmp_path / 'legacy.sqlite'}")
    with eng.begin() as conn:
        conn.execute(text("CREATE TABLE audit_event (id VARCHAR(32) PRIMARY KEY, event_type VARCHAR(40), "
                          "analysis_id VARCHAR(32), case_id VARCHAR(32), detail JSON, created_at DATETIME)"))
        for i in range(3):
            conn.execute(text("INSERT INTO audit_event VALUES (:id, 'legacy_event', NULL, NULL, :d, :t)"),
                         {"id": f"L{i}", "d": json.dumps({"i": i}), "t": f"2025-01-0{i + 1} 10:00:00.000000"})
    upgrade(eng)
    S = sessionmaker(bind=eng)
    with S() as db:
        rows = db.query(AuditEvent).order_by(AuditEvent.seq).all()
        assert [(r.id, r.seq) for r in rows[:3]] == [("L0", 1), ("L1", 2), ("L2", 3)]
        assert [r.detail for r in rows[:3]] == [{"i": 0}, {"i": 1}, {"i": 2}]      # content untouched
        gen = rows[3]
        assert gen.event_type == "chain_genesis" and gen.detail["legacy_events"] == 3
        assert "pre-date" in gen.detail["note"]
        assert verify(db)["ok"]
    upgrade(eng)
    with S() as db:
        assert db.query(AuditEvent).filter_by(event_type="chain_genesis").count() == 1
        assert verify(db)["ok"]
    eng.dispose()


# ── key handling ─────────────────────────────────────────────────────────────
def test_audit_key_fails_closed_outside_dev(monkeypatch):
    from app.audit import keys
    for env_name in ("production", "demo"):
        monkeypatch.setattr(get_settings(), "env", env_name)
        for bad in ("", "short", "changeme-changeme-changeme-changeme-1234"):
            monkeypatch.setenv("AIPISH_AUDIT_KEY", bad)
            keys.reset_audit_key_cache()
            with pytest.raises(keys.AuditKeyError):
                keys.audit_key()
    keys.reset_audit_key_cache()


def test_dev_generates_key_into_env_file_without_printing(monkeypatch, tmp_path, capsys):
    from app.audit import keys
    envf = tmp_path / ".env"
    envf.write_text("APP_ENV=dev\n")
    monkeypatch.setattr(keys, "ENV_FILE", envf)
    monkeypatch.setattr(get_settings(), "env", "dev")
    monkeypatch.setenv("AIPISH_AUDIT_KEY", "")
    keys.reset_audit_key_cache()
    k = keys.audit_key()
    text_ = envf.read_text()
    assert f"AIPISH_AUDIT_KEY={k.decode()}" in text_ and text_.startswith("APP_ENV=dev\n")
    assert k.decode() not in capsys.readouterr().out
    keys.reset_audit_key_cache()
    monkeypatch.delenv("AIPISH_AUDIT_KEY", raising=False)


def test_production_requires_audit_key(monkeypatch):
    from app.core.production import ProductionConfigError, check_production
    strong = dbmod._make_engine(dbmod.make_url("postgresql+psycopg://aipish:Zq8-xLp2_vRt9mWk4nBc@db/aipish"))
    monkeypatch.setattr(dbmod, "engine", strong)
    monkeypatch.setenv("AIPISH_AUDIT_KEY", "")
    with pytest.raises(ProductionConfigError, match="AIPISH_AUDIT_KEY"):
        check_production("production")


# ── coverage: each action → exactly one event with actor / target / outcome ──
def _count(db, event_type, **flt):
    return db.query(AuditEvent).filter_by(event_type=event_type, **flt).count()


def test_coverage_upload_view_dedupe_search_report(admin, monkeypatch):
    aid = _upload(admin, _unique_bec())
    with dbmod.SessionLocal() as db:
        ev = _events(db, event_type="analysis_uploaded", analysis_id=aid)
        assert len(ev) == 1 and ev[0].actor_user_id and ev[0].target_type == "analysis" and ev[0].outcome == "success"
        assert ev[0].source_ip
    admin.get(f"/api/v1/analyses/{aid}")
    admin.get(f"/api/v1/analyses/{aid}")                          # deduplicated (15-minute window)
    with dbmod.SessionLocal() as db:
        assert _count(db, "analysis_viewed", analysis_id=aid) == 1
        v = _events(db, event_type="analysis_viewed", analysis_id=aid)[0]
        assert v.detail == {"masked": False}
    q = "x" * 100
    admin.get("/api/v1/search", params={"q": q, "type": "analysis", "verdict": "suspicious"})
    with dbmod.SessionLocal() as db:
        s = _events(db, event_type="search_performed")[-1]
        assert s.detail["query"] == "x" * 64 and s.detail["query_truncated"] is True
        assert s.detail["filters"] == {"verdict": "suspicious"} and s.target_type == "search"
    cid = admin.post(f"/api/v1/investigations/from-analysis/{aid}").json()["id"]
    with dbmod.SessionLocal() as db:
        c = _events(db, event_type="analysis_created", case_id=cid)
        assert len(c) == 1 and c[0].target_type == "case" and c[0].target_id == cid
    assert admin.get(f"/api/v1/investigations/{cid}/report/{aid}").status_code == 200
    with dbmod.SessionLocal() as db:
        rep = _events(db, event_type="report_generated", analysis_id=aid)
        assert len(rep) == 1 and rep[0].detail["masked"] is False and "assessment_version" in rep[0].detail


def test_coverage_assessment_and_ml_runs(admin):
    from app.api.llm_router import _store
    aid = _upload(admin, _unique_bec())
    with dbmod.SessionLocal() as db:
        _store(db, aid, "stored_analysis", {"status": "ok"}, {"status": "unavailable"}, {"status": "unavailable"})
        ev = _events(db, event_type="assessment_run", analysis_id=aid)
        assert len(ev) == 1 and ev[0].detail["ml_status"] == "ok" and ev[0].detail["llm_status"] == "unavailable"
    with open(BEC, "rb") as f:
        admin.post("/api/v1/ml/classify", files={"file": ("m.eml", f.read())})
    with dbmod.SessionLocal() as db:
        ml = _events(db, event_type="ml_run")[-1]
        assert ml.target_type == "file" and ml.detail["endpoint"] == "classify"


def test_coverage_verify_checkpoint_export(admin):
    admin.get("/api/v1/audit/verify")
    cp = admin.post("/api/v1/audit/checkpoint").json()
    assert cp["checkpoint"]["seq"] > 0 and len(cp["checkpoint"]["event_hash"]) == 64
    assert admin.get("/api/v1/audit/checkpoint").json()["latest"]["seq"] == cp["checkpoint"]["seq"]
    r = admin.get("/api/v1/audit/export", params={"format": "csv"})
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/csv")
    assert r.text.splitlines()[0].startswith("seq,at,action")
    j = admin.get("/api/v1/audit/export", params={"format": "json"}).json()
    assert j["exported"] <= 10_000 and "not tamper-proof" in j["guarantee"]
    with dbmod.SessionLocal() as db:
        for t in ("audit_verified", "audit_checkpoint", "audit_exported"):
            assert _count(db, t) >= 1


def test_passive_verify_is_deduplicated(admin):
    first = admin.get("/api/v1/audit/verify").json()
    with dbmod.SessionLocal() as db:
        n = _count(db, "audit_verified")
    second = admin.get("/api/v1/audit/verify").json()
    assert first["ok"] and second["ok"] and second["recorded"] is False
    with dbmod.SessionLocal() as db:
        assert _count(db, "audit_verified") == n


def test_audit_events_filters_and_pagination(admin):
    _upload(admin, _unique_bec())
    r = admin.get("/api/v1/audit/events", params={"page_size": 5}).json()
    assert len(r["items"]) == 5 and r["total"] >= 5
    seqs = [i["seq"] for i in r["items"]]
    assert seqs == sorted(seqs, reverse=True) and all(len(i["hash_prefix"]) == 12 for i in r["items"])
    f = admin.get("/api/v1/audit/events", params={"action": "analysis_uploaded", "outcome": "success"}).json()
    assert f["items"] and all(i["action"] == "analysis_uploaded" for i in f["items"])
    assert admin.get("/api/v1/audit/events", params={"page_size": 101}).status_code == 400


def test_audit_details_never_contain_forbidden_content(admin, viewer):
    aid = _upload(admin, _unique_bec())
    admin.get(f"/api/v1/analyses/{aid}")
    viewer.get(f"/api/v1/analyses/{aid}")
    admin.get("/api/v1/search", params={"q": "dana@internal-corp.example"})
    record_audit_detail = {"password": "hunter2", "subject": SUBJECT, "note": "contact dana@internal-corp.example",
                           "token": "eyJabc.def.ghi", "body_text": BODY_PHRASE}
    with dbmod.SessionLocal() as db:
        record_audit(db, "test_forbidden", target_type="test", detail=record_audit_detail)
        db.commit()
        details = json.dumps([e.detail for e in db.query(AuditEvent).all()])
    from app.audit.keys import audit_key
    for bad in (BODY_PHRASE, SUBJECT, "hunter2", "eyJabc", audit_key().decode(), DISPLAY, *EMAILS):
        assert bad not in details, bad
    assert not re.search(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", details)


# ── custody ──────────────────────────────────────────────────────────────────
def test_custody_timeline_and_permissions(admin, analyst, viewer, anon_client):
    aid = _upload(analyst, _unique_bec())
    analyst.get(f"/api/v1/analyses/{aid}")
    r = analyst.get(f"/api/v1/analyses/{aid}/custody")
    assert r.status_code == 200
    body = r.json()
    actions = [t["action"] for t in body["timeline"]]
    assert actions[:2] == ["analysis_uploaded", "analysis_viewed"]
    assert all("hash" not in json.dumps(t) for t in body["timeline"])
    assert body["integrity_note"] == "SHA-256 detects change to the stored file; it does not make storage tamper-proof."
    assert viewer.get(f"/api/v1/analyses/{aid}/custody").status_code == 403
    assert anon_client.get(f"/api/v1/analyses/{aid}/custody").status_code == 401


@pytest.mark.parametrize("method,path", [
    ("GET", "/api/v1/audit/events"), ("GET", "/api/v1/audit/export"), ("GET", "/api/v1/audit/verify"),
    ("GET", "/api/v1/audit/checkpoint"), ("POST", "/api/v1/audit/checkpoint"),
    ("GET", "/api/v1/admin/retention/status"), ("POST", "/api/v1/admin/retention/run"),
    ("GET", "/api/v1/admin/holds"), ("POST", "/api/v1/admin/holds"), ("POST", "/api/v1/admin/holds/x/clear"),
    ("DELETE", "/api/v1/admin/analyses/x"),
])
def test_admin_only_routes(method, path, analyst, viewer, anon_client):
    assert anon_client.request(method, path).status_code == 401
    assert viewer.request(method, path).status_code == 403
    assert analyst.request(method, path).status_code == 403


# ── retention ────────────────────────────────────────────────────────────────
def _age(aid: str, days: int) -> None:
    with dbmod.SessionLocal() as db:
        db.get(Analysis, aid).created_at = utcnow() - timedelta(days=days)
        db.commit()


def _policy(monkeypatch, days=30, mode="redact", evidence=0, grace=0):
    monkeypatch.setenv("RETENTION_ANALYSIS_DAYS", str(days))
    monkeypatch.setenv("RETENTION_EVIDENCE_DAYS", str(evidence))
    monkeypatch.setenv("RETENTION_MODE", mode)
    monkeypatch.setenv("RETENTION_GRACE_DAYS", str(grace))


def test_retention_disabled_by_default_and_dry_run_changes_nothing(admin, monkeypatch):
    for k in ("RETENTION_ANALYSIS_DAYS", "RETENTION_EVIDENCE_DAYS", "RETENTION_MODE", "RETENTION_GRACE_DAYS"):
        monkeypatch.delenv(k, raising=False)
    aid = _upload(admin, _unique_bec())
    _age(aid, 4000)
    assert retention.get_policy().enabled is False
    res = admin.post("/api/v1/admin/retention/run", json={"dry_run": False}).json()
    assert res["redacted"] == [] and res["deleted"] == []
    _policy(monkeypatch, days=30)
    res = admin.post("/api/v1/admin/retention/run", json={}).json()           # dry run by default
    assert res["dry_run"] is True and aid in res["eligible_analyses"] and res["redacted"] == []
    with dbmod.SessionLocal() as db:
        rec = db.get(Analysis, aid)
        assert rec.subject == SUBJECT and rec.retention_state is None
    assert "subject" not in json.dumps(res).lower() or SUBJECT not in json.dumps(res)


def test_redact_mode_keeps_record_and_removes_personal_content(admin, analyst, monkeypatch):
    aid = _upload(admin, _unique_bec())
    with dbmod.SessionLocal() as db:
        sha, score = db.get(Analysis, aid).raw_sha256, db.get(Analysis, aid).detection_score
        assert db.query(Observation).filter_by(analysis_id=aid).count() > 0
    _age(aid, 400)
    _policy(monkeypatch, days=30, mode="redact")
    res = admin.post("/api/v1/admin/retention/run", json={"dry_run": False}).json()
    assert aid in res["redacted"]
    with dbmod.SessionLocal() as db:
        rec = db.get(Analysis, aid)
        assert rec.retention_state == "redacted" and rec.redacted_at is not None
        assert rec.subject is None and rec.body_text is None and rec.from_email is None and rec.to_emails is None
        assert rec.from_display_name is None and rec.reply_to_emails is None
        assert rec.raw_sha256 == sha and rec.detection_score == score and rec.from_domain == "internal-corp.example"
        assert rec.urls is not None and db.query(Observation).filter_by(analysis_id=aid).count() > 0
        ents = {e.type for e in db.query(Entity).join(Observation, Observation.entity_id == Entity.id)
                .filter(Observation.analysis_id == aid)}
        assert "display_name_alias" not in ents
        assert json.dumps(rec.detection_json).find("dana.doe.personal") == -1
        assert _count(db, "retention_purge", analysis_id=aid) == 1
    d = analyst.get(f"/api/v1/analyses/{aid}").json()
    assert d["retention_state"] == "redacted" and d["redaction_note"] == "content redacted per retention policy"
    assert d["subject"] is None and d["body_text"] is None
    cid = analyst.post(f"/api/v1/investigations/from-analysis/{aid}").json()["id"]
    pdf = analyst.get(f"/api/v1/investigations/{cid}/report/{aid}")
    assert pdf.status_code == 200 and pdf.content[:5] == b"%PDF-"
    again = admin.post("/api/v1/admin/retention/run", json={"dry_run": False}).json()
    assert aid not in again["redacted"] and aid not in again["eligible_analyses"]          # idempotent


@pytest.fixture
def iso_admin(tmp_path):
    """Admin client on an isolated database, so campaigns created here never touch other tests' data."""
    from app.core.db import get_db
    eng = create_engine(f"sqlite:///{tmp_path / 'del.sqlite'}", connect_args={"check_same_thread": False})
    upgrade(eng)
    S = sessionmaker(bind=eng, autoflush=False)

    def _db():
        db = S()
        try:
            yield db
        finally:
            db.close()

    app = create_app()
    app.dependency_overrides[get_db] = _db
    yield authed_client(app, "admin"), S, eng
    eng.dispose()


def test_delete_mode_leaves_no_orphans_and_recomputes_campaigns(iso_admin, monkeypatch):
    admin, S, eng = iso_admin
    camp_dir = os.path.join(FIX, "campaign")
    ids = [_upload(admin, os.path.join(camp_dir, f"campaign_member_{i}.eml")) for i in (1, 2, 3)]
    victim = ids[0]
    with S() as db:
        assert db.query(CampaignMember).filter_by(analysis_id=victim).count() == 1
        members_before = db.query(CampaignMember).count()
    admin.post(f"/api/v1/investigations/from-analysis/{victim}")
    with S() as db:
        db.get(Analysis, victim).created_at = utcnow() - timedelta(days=400)
        db.commit()
    _policy(monkeypatch, days=30, mode="delete")
    res = admin.post("/api/v1/admin/retention/run", json={"dry_run": False}).json()
    assert victim in res["deleted"]
    with S() as db:
        assert db.get(Analysis, victim) is None
        for model in retention.dependent_models():
            assert db.query(model).filter(model.analysis_id == victim).count() == 0, model.__tablename__
        live = {o.entity_id for o in db.query(Observation).all()}
        assert all(e.id in live for e in db.query(Entity).all())                  # no orphan entities
        assert db.query(CaseAnalysisLink).filter_by(analysis_id=victim).count() == 0
        assert db.query(CampaignMember).count() == members_before - 1            # campaign recomputed
        assert db.query(AuditEvent).filter_by(event_type="retention_purge", analysis_id=victim).count() == 1
        assert db.query(AuditEvent).filter_by(analysis_id=victim).count() >= 2   # audit kept
        assert verify(db)["ok"] is True
    names = set(inspect(eng).get_table_names())
    covered = {m.__tablename__ for m in retention.dependent_models()}
    for t in names:
        cols = {c["name"] for c in inspect(eng).get_columns(t)}
        if "analysis_id" in cols and t != "audit_event":
            assert t in covered, f"{t} references analyses but is not purged on delete"


def test_legal_hold_blocks_retention_and_erasure(admin, monkeypatch):
    aid = _upload(admin, _unique_bec())
    _age(aid, 400)
    assert admin.post("/api/v1/admin/holds", json={"target_type": "analysis", "target_id": aid, "reason": ""}).status_code == 400
    h = admin.post("/api/v1/admin/holds", json={"target_type": "analysis", "target_id": aid,
                                                "reason": "litigation request 42"})
    assert h.status_code == 201
    hid = h.json()["id"]
    _policy(monkeypatch, days=30, mode="delete")
    res = admin.post("/api/v1/admin/retention/run", json={"dry_run": False}).json()
    assert aid in res["held_skipped"] and aid not in res["deleted"]
    e = admin.request("DELETE", f"/api/v1/admin/analyses/{aid}", json={"reason": "erasure request"})
    assert e.status_code == 409 and e.json()["error"]["code"] == "LEGAL_HOLD"
    assert admin.get("/api/v1/analyses").json()[0]["legal_hold"] in (True, False)
    assert admin.post(f"/api/v1/admin/holds/{hid}/clear", json={"reason": "settled"}).status_code == 200
    ok = admin.request("DELETE", f"/api/v1/admin/analyses/{aid}", json={"reason": "erasure request"})
    assert ok.status_code == 200 and ok.json()["deleted"] is True
    with dbmod.SessionLocal() as db:
        for t in ("legal_hold_set", "legal_hold_cleared", "analysis_erasure_refused", "analysis_erased"):
            assert _count(db, t, analysis_id=aid) == 1, t
        assert db.get(LegalHold, hid).cleared_at is not None


def test_case_hold_protects_member_analyses(admin, monkeypatch):
    aid = _upload(admin, _unique_bec())
    cid = admin.post(f"/api/v1/investigations/from-analysis/{aid}").json()["id"]
    admin.post("/api/v1/admin/holds", json={"target_type": "case", "target_id": cid, "reason": "case under review"})
    _age(aid, 400)
    _policy(monkeypatch, days=30, mode="delete")
    res = admin.post("/api/v1/admin/retention/run", json={"dry_run": False}).json()
    assert aid in res["held_skipped"]
    st = admin.get("/api/v1/admin/retention/status").json()
    assert any(h["target_id"] == cid for h in st["holds"]) and st["policy"]["audit_events_purged"] is False
    assert admin.get(f"/api/v1/investigations/{cid}").json()["legal_hold"] is True


def test_retention_cli_dry_run_default(monkeypatch, capsys):
    from app import cli
    _policy(monkeypatch, days=30)
    assert cli.main(["retention-run"]) == 0
    assert "DRY RUN" in capsys.readouterr().out


def test_cli_audit_verify_and_checkpoint(capsys):
    from app import cli
    assert cli.main(["audit-verify"]) == 0
    out = capsys.readouterr().out
    assert "chain: OK" in out and "not tamper-proof" in out
    assert cli.main(["audit-checkpoint"]) == 0
    assert "checkpoint: seq=" in capsys.readouterr().out


# ── masking ──────────────────────────────────────────────────────────────────
def test_viewer_sees_masked_analysis_list_case_and_search(analyst, viewer):
    aid = _upload(analyst, _unique_bec())
    cid = analyst.post(f"/api/v1/investigations/from-analysis/{aid}").json()["id"]
    full = analyst.get(f"/api/v1/analyses/{aid}").json()
    assert full["body_text"] and DISPLAY in json.dumps(full) and "pii_masked" not in full
    v = viewer.get(f"/api/v1/analyses/{aid}").json()
    text_ = json.dumps(v)
    assert v["pii_masked"] is True and v["body_text"] is None and v["body_restricted"] is True
    assert v["from"]["display_name"] == "restricted" and v["from"]["email"] == "d***@internal-corp.example"
    assert v["from"]["domain"] == "internal-corp.example" and v["sha256"] == full["sha256"]
    assert v["detection"]["score"] == full["detection"]["score"]
    for bad in (*EMAILS, DISPLAY, BODY_PHRASE):
        assert bad not in text_, bad
    for path in ("/api/v1/analyses", f"/api/v1/investigations/{cid}", f"/api/v1/investigations/{cid}/analyses",
                 "/api/v1/search?q=internal-corp", f"/api/v1/analyses/{aid}/correlation"):
        t = viewer.get(path).text
        for bad in (*EMAILS, DISPLAY, BODY_PHRASE):
            assert bad not in t, (path, bad)
    with dbmod.SessionLocal() as db:
        assert _events(db, event_type="analysis_viewed", analysis_id=aid)[-1].detail == {"masked": True}


def test_masked_pdf_for_viewer(analyst, viewer, monkeypatch):
    import app.api.case_router as cr
    seen = {}
    real = cr.build_report_pdf

    def spy(**kw):
        seen.update(kw)
        return real(**kw)

    monkeypatch.setattr(cr, "build_report_pdf", spy)
    aid = _upload(analyst, _unique_bec())
    cid = analyst.post(f"/api/v1/investigations/from-analysis/{aid}").json()["id"]
    assert viewer.get(f"/api/v1/investigations/{cid}/report/{aid}").status_code == 200
    assert any("MASKED VIEW" in n for n in seen["view_notes"])
    blob = json.dumps({k: v for k, v in seen.items() if k != "view_notes"}, default=str)
    for bad in (*EMAILS, DISPLAY):
        assert bad not in blob, bad
    assert seen["analysis_row"]["sha256"] and seen["detection"]["score"] == 100
    analyst.get(f"/api/v1/investigations/{cid}/report/{aid}")
    assert not seen["view_notes"]                                                   # analyst: unmasked
    with dbmod.SessionLocal() as db:
        flags = [e.detail["masked"] for e in _events(db, event_type="report_generated", analysis_id=aid)]
        assert flags == [True, False]


def test_masking_covers_every_get_endpoint_for_viewers(analyst, viewer):
    """Serializer coverage: any GET route that leaks raw PII to a viewer fails this test."""
    aid = _upload(analyst, _unique_bec())
    cid = analyst.post(f"/api/v1/investigations/from-analysis/{aid}").json()["id"]
    with dbmod.SessionLocal() as db:
        camp = db.query(Campaign).first()
    params = {"analysis_id": aid, "case_id": cid, "campaign_id": camp.id if camp else "none",
              "entity_type": "display_name_alias", "value": "dana finance director", "assessment_id": "none",
              "hold_id": "none"}
    from app.security.permissions import ROUTE_PERMISSIONS, role_allows
    checked = 0
    for (method, path), perm in ROUTE_PERMISSIONS.items():
        if method != "GET" or not role_allows("viewer", perm) or perm == "public":
            continue
        url = path.format(**params) if "{" in path else path
        r = viewer.get(url)
        if r.headers.get("content-type", "").startswith("application/json"):
            for bad in (*EMAILS, DISPLAY, BODY_PHRASE):
                assert bad not in r.text, (path, bad)
            checked += 1
    assert checked >= 15


def test_mask_payload_unit():
    from app.privacy.masking import mask_payload
    out = mask_payload({"from": {"display_name": "Jane Roe", "email": "jane@ex.test", "domain": "ex.test"},
                        "body_text": "hi", "items": [{"type": "display_name_alias", "value": "jane roe"}],
                        "note": "(display name: Jane Roe). Reply to bob@x.test", "ip": "203.0.113.9"})
    assert out["from"] == {"display_name": "restricted", "email": "j***@ex.test", "domain": "ex.test", "pii_masked": True}
    assert out["body_text"] is None and out["body_restricted"] is True and out["pii_masked"] is True
    assert out["items"][0]["value"] == "restricted"
    assert out["note"] == "(display name: restricted). Reply to b***@x.test" and out["ip"] == "203.0.113.9"


def test_guarantee_wording_is_honest():
    for word in ("immutable", "worm", "tamper-proof chain"):
        assert word not in GUARANTEE.lower()
    assert "tamper-evident" in GUARANTEE.lower() and "not tamper-proof" in GUARANTEE.lower()


def test_ensure_triggers_is_idempotent():
    ensure_triggers(dbmod.engine)
    ensure_triggers(dbmod.engine)
    with dbmod.SessionLocal() as db:
        assert verify(db)["ok"] is True


def test_hash_depends_on_key_and_prev():
    ev = AuditEvent(id="x", event_type="t", seq=1, detail={}, created_at=utcnow())
    assert compute_hash(ev, GENESIS_PREV, b"a" * 40) != compute_hash(ev, GENESIS_PREV, b"b" * 40)
    assert compute_hash(ev, GENESIS_PREV, b"a" * 40) != compute_hash(ev, "1" * 64, b"a" * 40)
