"""P4: stored ML/SHAP/LLM assessment shared by the dashboard and the PDF report."""
from __future__ import annotations

import copy
import json
import re
from pathlib import Path

import httpx
import pytest
import respx
from fastapi.testclient import TestClient

from app.main import create_app
from tests.authutil import authed_client  # noqa: E402
from app.reports import pdf as P

DOCS = Path(__file__).resolve().parents[3] / "docs" / "llm"
SAMPLE = (DOCS / "sample_bec_injection.eml").read_bytes()
REAL = json.loads((DOCS / "sample_bec_injection.response.json").read_text())  # actual backend output
BASE = "http://127.0.0.1:11434"


def _full() -> dict:
    a = copy.deepcopy(REAL)
    a.update(source="upload", generated_at="2026-11-19T18:00:00+00:00", analysis_id="x")
    return a


def _pdf_text(monkeypatch, **kw) -> tuple[bytes, str]:
    """Build an uncompressed PDF and return (bytes, the text drawn on its pages)."""
    from reportlab import rl_config
    monkeypatch.setattr(rl_config, "pageCompression", 0)
    data = P.build_report_pdf(
        case_dict={"case_number": "CASE-1", "id": "c"}, analysis_row={"id": "a1", "sha256": "f" * 64,
                                                                      "size_bytes": 10, "sender": {}},
        detection={"score": 80, "verdict": "phishing_fraud_likely", "findings": [], "unknowns": []},
        forensics={}, auth={}, enrichment={}, integrity={"result": "unavailable", "detail": "hash only"},
        report_id="RPT-TEST", generated_at="2026-11-19", **kw)
    lines = []
    for block in re.findall(rb"\bBT\b(.*?)\bET\b", data, re.S):          # one text block per wrapped line
        for line in re.split(rb"T\*", block):
            parts = re.findall(rb"\(((?:\\.|[^\\)])*)\)\s*Tj", line)
            lines.append(b"".join(parts).decode("latin-1"))
    drawn = " ".join(lines)
    return data, drawn.replace("\\(", "(").replace("\\)", ")").replace("\\\\", "\\")


def _pages(data: bytes) -> int:
    return len(re.findall(rb"/Type\s*/Page[^s]", data))


# ── persistence + read endpoint ───────────────────────────────────────────

def _mock_ollama(r, content: str):
    r.get(f"{BASE}/api/tags").mock(return_value=httpx.Response(
        200, json={"models": [{"name": "mistral:latest", "digest": "d1"}]}))
    r.post(f"{BASE}/api/chat").mock(return_value=httpx.Response(
        200, json={"message": {"content": content}, "done_reason": "stop"}))


ANSWER = json.dumps({"summary": "Reply-To diverges from the sender domain.", "assessment": "Moderate.",
                     "findings": [{"statement": "Reply-To uses freemail.example.", "evidence_ids": ["E2"],
                                   "basis": "verified"}],
                     "recommended_actions": ["Confirm by phone."], "limitations": ["SPF was not verified."]})


def test_assessment_is_stored_and_served_unchanged():
    c = authed_client()
    with respx.mock(assert_all_called=False) as r:
        _mock_ollama(r, ANSWER)
        made = c.post("/api/v1/llm/forensic-summary", files={"file": ("m.eml", SAMPLE, "message/rfc822")}).json()
    got = c.get(f"/api/v1/analyses/{made['analysis_id']}/assessment").json()
    assert got == made
    assert set(got) == {"analysis_id", "assessment_id", "version", "source", "generated_at", "ml", "explanation",
                        "forensic_summary"}
    assert got["version"] == 1
    assert got["source"] == "upload" and got["forensic_summary"]["status"] == "ok"


def test_assessment_404_codes():
    c = authed_client()
    assert c.get("/api/v1/analyses/nope/assessment").json()["error"]["code"] == "NOT_FOUND"
    up = c.post("/api/v1/analyses", files={"file": ("m.eml", SAMPLE, "message/rfc822")}).json()
    r = c.get(f"/api/v1/analyses/{up['id']}/assessment")
    assert r.status_code == 404 and r.json()["error"]["code"] == "ASSESSMENT_NOT_GENERATED"


def test_stored_regeneration_reuses_upload_time_ml_instead_of_degrading():
    from app.core.db import SessionLocal
    from app.core.models import AssessmentVersion
    c = authed_client()
    up = c.post("/api/v1/analyses", files={"file": ("m.eml", SAMPLE, "message/rfc822")}).json()
    with SessionLocal() as db:
        db.add(AssessmentVersion(analysis_id=up["id"], version=1, source="upload", ml_json=REAL["ml"],
                                 explanation_json=REAL["explanation"], summary_json=None))
        db.commit()
    with respx.mock(assert_all_called=False) as r:
        _mock_ollama(r, ANSWER)
        out = c.post(f"/api/v1/analyses/{up['id']}/forensic-summary").json()
    assert out["source"] == "stored_analysis" and out["ml"]["status"] == "ok"
    assert out["ml"]["label"] == REAL["ml"]["label"] and out["ml"]["reused_from_assessment"]
    assert out["version"] == 2


def test_stored_analysis_hash_only_explains_ml_unavailability():
    c = authed_client()
    up = c.post("/api/v1/analyses", files={"file": ("m.eml", SAMPLE, "message/rfc822")}).json()
    with respx.mock(assert_all_called=False) as r:
        r.get(f"{BASE}/api/tags").mock(side_effect=httpx.ConnectError("down"))
        out = c.post(f"/api/v1/analyses/{up['id']}/forensic-summary").json()
    assert out["ml"]["status"] == "unavailable" and "hash_only" in out["ml"]["reason"]
    assert out["explanation"]["status"] == "unavailable"
    assert out["forensic_summary"]["status"] == "unavailable"


# ── PDF ──────────────────────────────────────────────────────────────────

def test_pdf_with_all_components(monkeypatch):
    data, text = _pdf_text(monkeypatch, assessment=_full())
    assert data.startswith(b"%PDF-")
    for needle in ("ML Classification, SHAP and AI-Assisted Interpretation", REAL["ml"]["label"],
                   "uncalibrated", "SHAP feature contributions", "does not explain the DistilRoBERTa",
                   "AI-GENERATED INTERPRETATION", "VERIFIED", "INFERRED", "E7", "Recommended actions",
                   "Model-stated limitations", "Evidence items cited above", "mistral:latest"):
        assert needle in text, needle
    assert "9. Confidence & Limitations" in text and "1. Evidence & Integrity" in text   # structure kept


def test_pdf_without_assessment_claims_nothing(monkeypatch):
    _, text = _pdf_text(monkeypatch, assessment=None)
    assert "No ML / SHAP / AI assessment has been generated" in text
    assert "Predicted class" not in text and "AI-GENERATED" not in text


@pytest.mark.parametrize("status", ["unavailable", "timeout", "invalid_output"])
def test_pdf_with_unavailable_components(monkeypatch, status):
    a = _full()
    a["ml"] = {"status": "unavailable", "reason": "raw message not retained (CASE_EVIDENCE_STORE=hash_only)"}
    a["explanation"] = {"status": "unavailable", "reason": "SHAP not installed", "components": {}}
    a["forensic_summary"] = {**a["forensic_summary"], "status": status, "summary": None, "assessment": None,
                             "findings": [], "reason": f"llm {status}"}
    _, text = _pdf_text(monkeypatch, assessment=a)
    assert "UNAVAILABLE" in text and "hash_only" in text and "SHAP not installed" in text
    assert f"llm {status}" in text
    assert "Predicted class" not in text and "No findings passed" not in text   # nothing claimed to run


def test_pdf_escapes_markup_and_handles_long_text(monkeypatch):
    a = _full()
    evil = '<font size="40">X</font> <b>unclosed & <para> ]]> \\ ( ) <img src="x"/>'
    a["forensic_summary"]["summary"] = (evil + " ") * 5 + ("lorem ipsum dolor " * 400)
    a["forensic_summary"]["findings"] = [{"statement": f"{evil} finding {i} " + "word " * 120,
                                          "evidence_ids": ["E1", "E2"], "basis": "inferred"} for i in range(25)]
    a["forensic_summary"]["rejected_findings"] = [{"statement": evil, "reason": evil}]
    a["ml"]["label"] = evil
    data, text = _pdf_text(monkeypatch, assessment=a)
    assert data.startswith(b"%PDF-") and _pages(data) >= 4
    assert "<font" in text and "&lt;" not in text        # shown literally, never interpreted as markup
    assert "finding 24" in text                           # long tables continue across pages


def test_pdf_missing_fields_are_not_fabricated(monkeypatch):
    a = {"analysis_id": "x", "source": "upload", "generated_at": None,
         "ml": {"status": "ok"}, "explanation": {"status": "ok"}, "forensic_summary": {"status": "ok"}}
    _, text = _pdf_text(monkeypatch, assessment=a)
    assert "n/a" in text and "No findings passed validation" in text
    assert "VERIFIED" not in text


def test_report_endpoint_includes_stored_assessment(monkeypatch):
    from reportlab import rl_config
    monkeypatch.setattr(rl_config, "pageCompression", 0)
    c = authed_client()
    with respx.mock(assert_all_called=False) as r:
        _mock_ollama(r, ANSWER)
        made = c.post("/api/v1/llm/forensic-summary", files={"file": ("m.eml", SAMPLE, "message/rfc822")}).json()
    case = c.post(f"/api/v1/investigations/from-analysis/{made['analysis_id']}").json()
    pdf = c.get(f"/api/v1/investigations/{case['id']}/report/{made['analysis_id']}").content
    assert pdf.startswith(b"%PDF-")
    assert b"Reply-To uses freemail.example." in pdf and b"AI-GENERATED INTERPRETATION" in pdf
