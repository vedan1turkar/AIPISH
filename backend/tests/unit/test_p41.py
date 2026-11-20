"""P4.1: SHAP interpretation, recommendation grounding, Received-header wording,
name redaction, assessment history/migration, duplicate-run guard, PDF layout.
Synthetic data only; offline (Ollama mocked)."""
from __future__ import annotations

import copy
import json
import logging
import re
from email.message import EmailMessage
from pathlib import Path

import httpx
import respx
from fastapi.testclient import TestClient

from app.api import llm_router
from app.core.db import SessionLocal
from app.core.models import AnalysisAssessment, AssessmentVersion, migrate_assessments
from app.llm import service
from app.llm.evidence import build_pack
from app.llm.recommend import SYSTEM_GENERAL, classify
from app.llm.redact import name_tokens, redact_names
from app.llm.validate import validate
from app.main import create_app
from tests.authutil import authed_client  # noqa: E402
from app.ml.shap_view import component_view
from app.reports import pdf as P

DOCS = Path(__file__).resolve().parents[3] / "docs" / "llm"
SAMPLE = (DOCS / "sample_bec_injection.eml").read_bytes()
REAL = json.loads((DOCS / "sample_bec_injection.response.json").read_text())
BASE = "http://127.0.0.1:11434"
XGB = REAL["explanation"]["components"]["xgb"]


def _analysis(**over):
    a = {"subject": "Urgent wire before 3pm - confidential", "from_domain": "halvorsen-1ogistics.test",
         "from_display_name": "Elena Hartley (CEO)", "from_email": "elena.hartley@halvorsen-1ogistics.test",
         "to_emails": ["priya.varma@halvorsen-logistics.test"], "reply_to_emails": ["x@freemail.example"],
         "urls": [{"host": "halvorsen-1ogistics.test"}], "attachments": [], "received_count": 0,
         "body_text": "Priya, are you at your desk? Please wire the funds today.\n\nRegards,\nElena Hartley",
         "detection_json": {"score": 100, "verdict": "phishing_fraud_likely", "unknowns": [], "findings": [
             {"rule_id": "credential_request", "knowledge": "heuristic", "severity": "high", "contribution": 25,
              "title": "Credential request", "evidence": "matched 1 phrase(s), e.g. “password”"}]},
         "auth_json": {}, "forensics_json": {}, "enrichment_json": {}}
    a.update(over)
    return a


# ── SHAP interpretation ───────────────────────────────────────────────────

def test_shap_view_reports_net_movement_and_divergence():
    v = component_view("xgb", XGB, "fraud", "fraud", REAL["ml"])
    assert v["net_direction"] == "away" and abs(v["net"] - (XGB["output_value"] - XGB["base_value"])) < 1e-9
    assert "moved from -0.0098 to -0.9326" in v["net_sentence"] and "away from 'fraud'" in v["net_sentence"]
    note = v["divergence_note"]
    assert "still predicts 'fraud'" in note and "DistilRoBERTa" in note and "do not explain the ensemble" in note
    assert "XGBoost gave 'fraud' 0.4211" in note and "DistilRoBERTa gave 'fraud' 0.9997" in note
    assert "rejecting" in note                         # margin below baseline != rejecting the class


def test_shap_rows_include_aggregate_and_add_up():
    v = component_view("xgb", XGB, "fraud", "fraud", REAL["ml"])
    agg = [r for r in v["rows"] if r["aggregated"]]
    assert [r["feature"] for r in agg] == ["text_semantic_components"] and abs(agg[0]["shap_value"] - 0.97869) < 1e-6
    assert v["displayed_additivity_ok"] and not v["has_remainder"]
    assert abs(XGB["base_value"] + v["shown_sum"] - XGB["output_value"]) < 1e-3


def test_shap_remainder_when_rows_are_truncated():
    comp = copy.deepcopy(XGB)
    comp["top_contributions"] = comp["top_contributions"][:1]
    v = component_view("xgb", comp, "fraud", "fraud")
    assert v["has_remainder"] and not v["displayed_additivity_ok"]
    assert abs(v["shown_sum"] + v["remainder"] - v["net"]) < 1e-9


def test_no_divergence_note_when_component_agrees():
    comp = {**XGB, "output_value": 1.5}
    comp["top_contributions"] = []
    comp["aggregated"] = [{"feature": "text_semantic_components", "group": "text", "detail": "x",
                           "shap_value": 1.5 - XGB["base_value"]}]
    v = component_view("xgb", comp, "fraud", "fraud")
    assert v["net_direction"] == "toward" and v["divergence_note"] is None


def test_evidence_item_matches_shap_response():
    pack = build_pack(_analysis(), REAL["ml"], REAL["explanation"])
    item = next(i for i in pack.items if i["source"] == "shap:xgb")
    s = item["statement"]
    assert "text_semantic_components +0.979" in s and "aggregate of 100 TF-IDF SVD components" in s
    assert "not an individually interpretable word or phrase" in s
    assert "raw margin (not a probability)" in s and "XGBoost component only" in s
    for r in XGB["top_contributions"]:
        assert f"{r['shap_value']:+.3f}" in s
    assert "still predicts 'fraud'" in s and len(s) <= 1400


# ── recommendation grounding ──────────────────────────────────────────────

def test_unsupported_detail_recommendations_are_rejected():
    pack = build_pack(_analysis(), REAL["ml"], REAL["explanation"])
    for text in ("Investigate the phone number provided in the email.",
                 "Investigate the new supplier mentioned in the email.",
                 "Investigate the approval code provided in the email.",
                 "Call back the mobile number in this message to confirm."):
        c = classify(text, pack)
        assert c["kind"] == "rejected", text
        # P4.2: calling a number from the email is now rejected as unsafe (stronger than "unsupported")
        assert ("no deterministic evidence item establishes" in c["reason"]) or c["reason"].startswith("unsafe:")


def test_neutral_and_evidence_linked_recommendations():
    pack = build_pack(_analysis(), REAL["ml"], REAL["explanation"])
    ids = pack.ids
    linked = classify("Investigate the URL provided in the email.", pack)
    assert linked["kind"] == "evidence_linked" and linked["evidence_ids"]
    assert all(e in ids and ids[e]["category"] != "model" for e in linked["evidence_ids"])   # no invented ids
    assert classify("Independently verify supplier and payment details.", pack)["kind"] == "general"
    assert classify("Alert the recipient of the potential phishing attempt.", pack)["kind"] == "general"
    sender = classify("Examine the sender domain's history.", pack)
    assert sender["kind"] == "evidence_linked" and sender["evidence_ids"] == ["E1"]


def test_recommendation_text_is_redacted():
    pack = build_pack(_analysis(), REAL["ml"], REAL["explanation"])
    c = classify("Reset password: hunter2 and email ops.lead@corp.test about card 4111 1111 1111 1111", pack)
    assert "hunter2" not in c["text"] and "ops.lead" not in c["text"] and "4111" not in c["text"]


def test_validate_separates_recommendations_from_findings():
    pack = build_pack(_analysis(), REAL["ml"], REAL["explanation"])
    data = {"summary": "Reply-To diverges.", "assessment": "Moderate.", "limitations": [],
            "findings": [{"statement": "Credential request phrasing.", "evidence_ids": ["E7"], "basis": "inferred"}],
            "recommended_actions": ["Investigate the phone number provided in the email.",
                                    "Investigate the URL provided in the email.",
                                    "Review the organisation's email security policies."]}
    out = validate(data, pack)
    kinds = [(r["origin"], r["kind"]) for r in out["recommendations"]]
    # P4.2: shown advice is always system-template text; model wording is never passed through
    assert ("system_template", "evidence_linked") in kinds and ("system", "general") in kinds
    assert all(r["text"] in SYSTEM_GENERAL for r in out["recommendations"] if r["kind"] == "general")
    rejected = {r["text"]: r["reason"] for r in out["rejected_recommendations"]}
    assert "Investigate the phone number provided in the email." in rejected
    assert "not a recognised investigative action" in rejected["Review the organisation's email security policies."]
    linked = next(r for r in out["recommendations"] if r["kind"] == "evidence_linked")
    assert linked["category"] == "url_analysis" and "Do not open" in linked["text"]
    assert linked["model_suggestions"] == ["Investigate the URL provided in the email."]
    assert out["recommended_actions"] == [linked["text"]]
    assert len(out["findings"]) == 1                     # recommendations never become findings


# ── Received-header wording ───────────────────────────────────────────────

def test_no_received_wording_does_not_overreach():
    from app.forensics.headers import run_header_forensics
    from app.ingestion.parser import parse_eml
    f = run_header_forensics(parse_eml(SAMPLE)).to_dict()
    rat = next(i["rationale"] for i in f["inconsistencies"] if i["rule_id"] == "no_received")
    assert "cannot be reconstructed from the available evidence" in rat
    assert "public SMTP as far as" not in rat and "did not travel" not in rat


# ── name redaction ────────────────────────────────────────────────────────

def test_header_derived_names_are_redacted_in_body():
    pack = build_pack(_analysis(), None, None)
    assert "Priya" not in pack.body_excerpt and "Hartley" not in pack.body_excerpt
    assert "[RECIPIENT_NAME]" in pack.body_excerpt and "[SENDER_NAME]" in pack.body_excerpt
    assert "desk" in pack.body_excerpt and "Please wire the funds" in pack.body_excerpt
    assert pack.redactions["personal_name"] >= 3
    assert "Elena Hartley (CEO)" in pack.items[0]["statement"]   # sender display name kept as forensic evidence


def test_ordinary_capitalised_words_are_not_redacted():
    text = ("The invoice is due Monday. Please review it. Dear Customer, thanks.\n"
            "Hello Team, the Board met in London.\n\nRegards,\nAccounts Team")
    out = redact_names(text, name_tokens(["Support Desk"], ["accounts@corp.test"]), set())
    assert out == text


def test_greeting_and_signoff_names_are_redacted():
    out = redact_names("Hi Marcus,\nplease call.\n\nKind regards,\nSofia Lindqvist", set(), set())
    assert out == "Hi [NAME],\nplease call.\n\nKind regards,\n[NAME]"


def test_names_do_not_reach_ollama_or_logs(caplog):
    caplog.set_level(logging.DEBUG)
    with respx.mock as r:
        r.get(f"{BASE}/api/tags").mock(return_value=httpx.Response(200, json={"models": [{"name": "mistral:latest"}]}))
        route = r.post(f"{BASE}/api/chat").mock(return_value=httpx.Response(200, json={"message": {"content": json.dumps(
            {"summary": "s", "assessment": "a", "findings": [], "recommended_actions": [], "limitations": []})},
            "done_reason": "stop"}))
        service.forensic_summary(_analysis(), None, None)
    user = json.loads(route.calls[0].request.content)["messages"][1]["content"]
    excerpt = user[user.rindex("<<UNTRUSTED_EMAIL_"):user.rindex("<<END_UNTRUSTED_EMAIL_")]
    assert "Priya" not in excerpt and "Hartley" not in excerpt
    logged = " ".join(x.getMessage() for x in caplog.records)
    assert "Priya" not in logged and "wire the funds" not in logged


# ── assessment history, migration, duplicate guard ───────────────────────

def _mock(r):
    r.get(f"{BASE}/api/tags").mock(return_value=httpx.Response(200, json={"models": [{"name": "mistral:latest",
                                                                                         "digest": "d"}]}))
    r.post(f"{BASE}/api/chat").mock(return_value=httpx.Response(200, json={"message": {"content": json.dumps(
        {"summary": "Reply-To diverges.", "assessment": "Moderate.", "findings": [], "recommended_actions": [],
         "limitations": []})}, "done_reason": "stop"}))


def test_regeneration_appends_versions_and_keeps_history():
    c = authed_client()
    up = c.post("/api/v1/analyses", files={"file": ("m.eml", SAMPLE, "message/rfc822")}).json()
    aid = up["id"]
    with respx.mock(assert_all_called=False) as r:
        _mock(r)
        v1 = c.post(f"/api/v1/analyses/{aid}/forensic-summary").json()
        v2 = c.post(f"/api/v1/analyses/{aid}/forensic-summary").json()
    assert (v1["version"], v2["version"]) == (1, 2) and v1["assessment_id"] != v2["assessment_id"]
    assert c.get(f"/api/v1/analyses/{aid}/assessment").json()["assessment_id"] == v2["assessment_id"]
    hist = c.get(f"/api/v1/analyses/{aid}/assessments").json()
    assert [h["version"] for h in hist] == [2, 1] and hist[1]["assessment_id"] == v1["assessment_id"]
    old = c.get(f"/api/v1/analyses/{aid}/assessments/{v1['assessment_id']}").json()
    assert old == v1                                                   # earlier version unchanged
    other = c.post("/api/v1/analyses", files={"file": ("m.eml", SAMPLE, "message/rfc822")}).json()["id"]
    r404 = c.get(f"/api/v1/analyses/{other}/assessments/{v1['assessment_id']}")
    assert r404.status_code == 404 and r404.json()["error"]["code"] == "ASSESSMENT_NOT_FOUND"


def test_pdf_is_pinned_to_the_requested_assessment_version(monkeypatch):
    from reportlab import rl_config
    monkeypatch.setattr(rl_config, "pageCompression", 0)
    c = authed_client()
    aid = c.post("/api/v1/analyses", files={"file": ("m.eml", SAMPLE, "message/rfc822")}).json()["id"]
    with respx.mock(assert_all_called=False) as r:
        _mock(r)
        v1 = c.post(f"/api/v1/analyses/{aid}/forensic-summary").json()
        case = c.post(f"/api/v1/investigations/from-analysis/{aid}").json()
        pinned = c.get(f"/api/v1/investigations/{case['id']}/report/{aid}",
                       params={"assessment_id": v1["assessment_id"]}).content
        v2 = c.post(f"/api/v1/analyses/{aid}/forensic-summary").json()
        pinned_again = c.get(f"/api/v1/investigations/{case['id']}/report/{aid}",
                             params={"assessment_id": v1["assessment_id"]}).content
        latest = c.get(f"/api/v1/investigations/{case['id']}/report/{aid}").content
    def has_id(pdf, ident):
        return ident[:8].encode() in pdf
    assert has_id(pinned, v1["assessment_id"]) and has_id(pinned_again, v1["assessment_id"])
    assert not has_id(pinned_again, v2["assessment_id"])
    assert has_id(latest, v2["assessment_id"]) and b"v2" in latest and b"v1" in pinned_again
    bad = c.get(f"/api/v1/investigations/{case['id']}/report/{aid}", params={"assessment_id": "nope"})
    assert bad.status_code == 404


def test_migration_copies_legacy_rows_once_without_destroying_them():
    import uuid
    aid = uuid.uuid4().hex
    with SessionLocal() as db:
        db.add(AnalysisAssessment(analysis_id=aid, source="upload", ml_json={"status": "ok", "label": "fraud"},
                                  explanation_json=None, summary_json={"status": "ok"}))
        db.commit()
        assert migrate_assessments(db) >= 1
        rows = db.query(AssessmentVersion).filter_by(analysis_id=aid).all()
        assert len(rows) == 1 and rows[0].id == f"p4-{aid}"[:32] and rows[0].version == 1
        assert rows[0].ml_json["label"] == "fraud"
        assert migrate_assessments(db) == 0                                  # idempotent
        assert db.get(AnalysisAssessment, aid) is not None                    # legacy row untouched


def test_duplicate_generation_is_refused_while_running():
    c = authed_client()
    aid = c.post("/api/v1/analyses", files={"file": ("m.eml", SAMPLE, "message/rfc822")}).json()["id"]
    llm_router._running.add(aid)
    try:
        r = c.post(f"/api/v1/analyses/{aid}/forensic-summary")
    finally:
        llm_router._running.discard(aid)
    assert r.status_code == 409 and r.json()["error"]["code"] == "ASSESSMENT_IN_PROGRESS"
    assert c.get(f"/api/v1/analyses/{aid}/assessments").json() == []          # nothing stored


# ── PDF layout ────────────────────────────────────────────────────────────

def _lines(monkeypatch, **kw) -> list[str]:
    from reportlab import rl_config
    monkeypatch.setattr(rl_config, "pageCompression", 0)
    data = P.build_report_pdf(
        case_dict={"case_number": "CASE-1"}, analysis_row={"sha256": "f" * 64, "size_bytes": 1, "sender": {},
                                                           "return_path": None},
        detection={"score": 100, "verdict": "phishing_fraud_likely", "unknowns": [], "findings": [
            {"rule_id": "sender_reply_to_mismatch", "severity": "medium", "contribution": 35, "knowledge": "fact",
             "evidence": "From: a.test -> Reply-To: b.example", "rationale": "Replies diverted."},
            {"rule_id": "header_inconsistency_forensics", "severity": "high", "contribution": 20,
             "knowledge": "heuristic", "evidence": "x", "rationale": "y"}]},
        forensics={}, auth={}, enrichment={}, integrity={"result": "unavailable"},
        report_id="RPT-5bbe8595-20261119163532", generated_at="2026-11-19T16:35:32.724935+00:00", **kw)
    out = []
    for block in re.findall(rb"\bBT\b(.*?)\bET\b", data, re.S):
        for line in re.split(rb"T\*", block):
            parts = re.findall(rb"\(((?:\\.|[^\\)])*)\)\s*Tj", line)
            if parts:
                text = b"".join(parts).decode("latin-1").replace("\\(", "(").replace("\\)", ")").strip()
                out.append(re.sub(r"([_.-]) ", r"\1", text))   # drop the invisible 1pt break spaces
    return out


def test_findings_headers_and_short_values_stay_on_one_line(monkeypatch):
    lines = _lines(monkeypatch)
    for whole in ("Severity", "Points", "OBSERVED FACT", "HEURISTIC", "medium", "+35", "+20", "100/100",
                  "2026-11-19 16:35:32 UTC", "Return-Path"):
        assert whole in lines, whole
    assert any(ln.replace(" ", "") == "RPT-5bbe8595-20261119163532" for ln in lines)   # report id on one line
    assert "not present" in lines                        # empty Return-Path no longer renders blank


def test_pdf_section8_shap_and_recommendations(monkeypatch):
    a = copy.deepcopy(REAL)
    a.update(analysis_id="x", assessment_id="abcdef0123456789", version=3, source="upload",
             generated_at="2026-11-19T18:00:00+00:00")
    pack = build_pack(_analysis(), a["ml"], a["explanation"])
    a["forensic_summary"].update(validate({"summary": "s", "assessment": "a", "findings": [], "limitations": [],
                                           "recommended_actions": ["Investigate the URL provided in the email.",
                                                                   "Investigate the phone number provided."]},
                                          pack))
    text = re.sub(r"_ ", "_", " ".join(_lines(monkeypatch, assessment=a)))   # identifiers wrapped at '_'
    for needle in ("v3", "raw-margin", "not probabilities", "away from 'fraud' overall",
                   "Why the ensemble still predicts this class", "text_semantic_components",
                   "not an individually interpretable", "Additivity: base", "check passed",
                   "Evidence-linked recommendations", "General recommendations (system templates",
                   "Rejected unsafe or unsupported", "INDEPENDENT VERIFICATION REQUIRED", "not reliably detected"):
        assert needle in text, needle


def test_pdf_older_assessment_without_grounding_is_labelled(monkeypatch):
    a = copy.deepcopy(REAL)
    a.update(analysis_id="x", source="upload", generated_at=None)
    text = " ".join(_lines(monkeypatch, assessment=a))
    assert "generated before recommendation grounding" in text and "not versioned" in text


def test_email_message_without_received_in_pdf_uses_neutral_wording(monkeypatch):
    m = EmailMessage()
    m["From"], m["To"], m["Subject"] = "a@b.test", "c@d.test", "s"
    m.set_content("hello there this is a body")
    text = " ".join(_lines(monkeypatch))
    assert "transport path cannot be" in text and "public SMTP" not in text
