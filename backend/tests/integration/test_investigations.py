"""Investigation-case tests: persistence, integrity, audit, restart survivability."""
from __future__ import annotations

import hashlib
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import app.cases.service as svc
from app.core.db import SessionLocal
from app.main import create_app

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "eml"


@pytest.fixture
def client() -> TestClient:
    return TestClient(create_app())


def _upload(client: TestClient, name: str = "phishing_multipart.eml") -> dict:
    p = FIXTURES / name
    r = client.post("/api/v1/analyses",
                    files={"file": (name, p.read_bytes(), "message/rfc822")})
    assert r.status_code == 201
    return r.json()


# ── case creation from analysis ──────────────────────────────────────────

def test_create_investigation_from_analysis(client: TestClient) -> None:
    up = _upload(client)
    r = client.post(f"/api/v1/investigations/from-analysis/{up['id']}")
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["case_number"].startswith("CASE-")
    assert body["analyses"][0]["analysis_id"] == up["id"]
    assert body["analyses"][0]["sha256"] == up["sha256"]
    assert body["evidence_policy"]["store_mode"] == "hash_only"


def test_list_and_get_investigation(client: TestClient) -> None:
    up = _upload(client)
    c = client.post(f"/api/v1/investigations/from-analysis/{up['id']}").json()
    lst = client.get("/api/v1/investigations").json()
    assert any(x["id"] == c["id"] for x in lst)
    got = client.get(f"/api/v1/investigations/{c['id']}")
    assert got.status_code == 200
    assert got.json()["case_number"] == c["case_number"]
    assert got.json()["analyses"][0]["threat_score"] == up["detection"]["score"]


def test_case_metadata_is_sanitized(client: TestClient) -> None:
    """Subject with control chars / long padding is capped+cleaned in case title."""
    raw = (FIXTURES / "benign.eml").read_bytes()
    up = client.post("/api/v1/analyses", files={"file": ("b.eml", raw, "message/rfc822")}).json()
    case = client.post(f"/api/v1/investigations/from-analysis/{up['id']}").json()
    title = case["title"] or ""
    assert len(title) <= 120
    assert "\x00" not in title and "\n" not in title


# ── evidence integrity ────────────────────────────────────────────────────

def test_integrity_hash_only_reports_unavailable_honestly(client: TestClient) -> None:
    """Default policy stores no bytes → integrity check must NOT fake a result."""
    up = _upload(client)
    case = client.post(f"/api/v1/investigations/from-analysis/{up['id']}").json()
    r = client.post(f"/api/v1/investigations/{case['id']}/evidence-integrity/{up['id']}")
    assert r.status_code == 200
    body = r.json()
    assert body["result"] == "unavailable"
    assert "hash-only" in body["detail"]


def test_integrity_match_with_retained_bytes(client: TestClient, monkeypatch) -> None:
    """With raw retained, recomputed SHA-256 matches → 'match'."""
    # Inject raw bytes directly (simulating the opt-in raw retention path).
    up = _upload(client)
    with SessionLocal() as db:
        from app.core.models import Analysis
        rec = db.get(Analysis, up["id"])
        raw = (FIXTURES / "phishing_multipart.eml").read_bytes()
        rec.evidence_blob = raw
        assert hashlib.sha256(raw).hexdigest() == rec.raw_sha256
        db.commit()
    case = client.post(f"/api/v1/investigations/from-analysis/{up['id']}").json()
    r = client.post(f"/api/v1/investigations/{case['id']}/evidence-integrity/{up['id']}").json()
    assert r["result"] == "match"
    assert r["detail"] == ""


def test_integrity_mismatch_on_corrupted_evidence(client: TestClient) -> None:
    """Corrupted stored bytes must surface as mismatch, never crash or 'match'."""
    up = _upload(client)
    with SessionLocal() as db:
        from app.core.models import Analysis
        rec = db.get(Analysis, up["id"])
        rec.evidence_blob = b"tampered bytes!" + b"x" * 32      # corrupt evidence
        # keep recorded hash genuine
        rec.raw_sha256 = hashlib.sha256((FIXTURES / "phishing_multipart.eml").read_bytes()).hexdigest()
        db.commit()
    case = client.post(f"/api/v1/investigations/from-analysis/{up['id']}").json()
    r = client.post(f"/api/v1/investigations/{case['id']}/evidence-integrity/{up['id']}").json()
    assert r["result"] == "mismatch"
    assert "recomputed" in r["detail"]


# ── persistence across restarts ──────────────────────────────────────────

def test_persistence_across_server_restart(client: TestClient) -> None:
    """Write with one app instance; verify with a *fresh* instance later."""
    up = _upload(client)
    case = client.post(f"/api/v1/investigations/from-analysis/{up['id']}").json()

    fresh = TestClient(create_app())     # simulates a restarted server (same DB file)
    got = fresh.get(f"/api/v1/investigations/{case['id']}")
    assert got.status_code == 200
    assert got.json()["analyses"][0]["analysis_id"] == up["id"]
    again = fresh.post("/api/v1/analyses",
                       files={"file": ("b.eml", (FIXTURES / "benign.eml").read_bytes(), "message/rfc822")})
    assert again.status_code == 201
    lst = fresh.get("/api/v1/investigations").json()
    assert any(x["id"] == case["id"] for x in lst)


# ── audit events ──────────────────────────────────────────────────────────

def test_audit_events_recorded(client: TestClient) -> None:
    up = _upload(client)
    case = client.post(f"/api/v1/investigations/from-analysis/{up['id']}").json()
    with SessionLocal() as db:
        from app.core.models import AuditEvent
        types = {e.event_type for e in db.query(AuditEvent).filter(AuditEvent.analysis_id == up["id"]).all()}
        assert "analysis_created" in types
    client.post(f"/api/v1/investigations/{case['id']}/evidence-integrity/{up['id']}")
    with SessionLocal() as db:
        from app.core.models import AuditEvent
        ints = [e for e in db.query(AuditEvent).filter(AuditEvent.analysis_id == up["id"]).all()
                if e.event_type == "integrity_verified"]
        assert ints, "integrity check must be audited"


def test_audit_events_are_append_only_via_api(client: TestClient) -> None:
    """No API route mutates audit rows — no mutation endpoints exist for them."""
    app = create_app()
    paths = {getattr(r, "path", "") for r in app.routes}
    assert not any(p.startswith("/api/v1/investigations/audit") for p in paths)


# ── PDF report (Part B) ──────────────────────────────────────────────────

def test_report_pdf_generated(client: TestClient) -> None:
    up = _upload(client)
    case = client.post(f"/api/v1/investigations/from-analysis/{up['id']}").json()
    r = client.get(f"/api/v1/investigations/{case['id']}/report/{up['id']}")
    assert r.status_code == 200
    assert r.headers["content-type"] == "application/pdf"
    assert r.content[:5] == b"%PDF-"
    assert len(r.content) > 1000
    assert "attachment" in r.headers.get("content-disposition", "")
    with SessionLocal() as db:
        from app.core.models import AuditEvent
        reps = [e for e in db.query(AuditEvent).filter(AuditEvent.analysis_id == up["id"]).all()
                if e.event_type == "report_generated"]
        assert reps and reps[-1].detail["size_bytes"] == len(r.content)


def test_report_pdf_malformed_input_still_succeeds(client: TestClient) -> None:
    """Malformed message → report still generates; unavailable fields shown honestly."""
    up = client.post("/api/v1/analyses", files={
        "file": ("malformed.eml", (FIXTURES / "malformed.eml").read_bytes(), "message/rfc822")
    })
    assert up.status_code == 201
    body = up.json()
    case = client.post(f"/api/v1/investigations/from-analysis/{body['id']}").json()
    r = client.get(f"/api/v1/investigations/{case['id']}/report/{body['id']}")
    assert r.status_code == 200
    assert r.content[:5] == b"%PDF-"


def test_report_pdf_unknown_ids_404(client: TestClient) -> None:
    assert client.get("/api/v1/investigations/nope/report/nope").status_code == 404


def test_report_works_with_enrichment_unavailable(client: TestClient) -> None:
    """Zero enrichment results → report renders 'no enrichment results available'."""
    up = client.post("/api/v1/analyses", files={
        "file": ("b.eml", (FIXTURES / "benign.eml").read_bytes(), "message/rfc822")
    }).json()
    case = client.post(f"/api/v1/investigations/from-analysis/{up['id']}").json()
    r = client.get(f"/api/v1/investigations/{case['id']}/report/{up['id']}")
    assert r.status_code == 200 and r.content[:5] == b"%PDF-"
