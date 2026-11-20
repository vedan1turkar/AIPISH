"""P4.2: safe, constrained investigative recommendations (adversarial). Synthetic data, offline."""
from __future__ import annotations

import copy
import json
import re
from pathlib import Path

import httpx
import pytest
import respx

from app.llm import service
from app.llm.evidence import build_pack
from app.llm.recommend import (EVIDENCE_TEMPLATES, GENERAL_TEMPLATES, classify, financial_context,
                               general_recommendations, ground)
from app.llm.validate import validate

DOCS = Path(__file__).resolve().parents[3] / "docs" / "llm"
REAL = json.loads((DOCS / "sample_bec_injection.response.json").read_text())
BASE = "http://127.0.0.1:11434"
TEMPLATES = set(GENERAL_TEMPLATES.values()) | set(EVIDENCE_TEMPLATES.values())


def _analysis(**over):
    a = {"subject": "Urgent wire before 3pm - confidential", "from_domain": "halvorsen-1ogistics.test",
         "from_display_name": "Elena Hartley (CEO)", "from_email": "elena.hartley@halvorsen-1ogistics.test",
         "to_emails": ["priya.varma@halvorsen-logistics.test"], "reply_to_emails": ["boss@freemail.example"],
         "urls": [{"host": "halvorsen-1ogistics.test"}], "attachments": [], "received_count": 0,
         "body_text": "Please wire USD 48,200 today. Call me on +00 555 0100 2233.",
         "detection_json": {"score": 100, "verdict": "phishing_fraud_likely", "unknowns": [], "findings": [
             {"rule_id": "sender_reply_to_mismatch", "knowledge": "fact", "severity": "high", "contribution": 35,
              "title": "Reply-To differs from sender domain",
              "evidence": "From: halvorsen-1ogistics.test -> Reply-To: freemail.example"}]},
         "auth_json": {}, "forensics_json": {}, "enrichment_json": {}}
    a.update(over)
    return a


@pytest.fixture(scope="module")
def pack():
    return build_pack(_analysis(), REAL["ml"], REAL["explanation"])


# ── the ten required cases ───────────────────────────────────────────────
UNSAFE_REQUIRED = [
    "Reply to the sender to confirm the wire transfer.",
    "Call the phone number in the email.",
    "Use the link in the email to check the supplier.",
    "Contact the sender using the Reply-To address.",
    "Verify the payment using a contact number from the email signature.",
]


@pytest.mark.parametrize("text", UNSAFE_REQUIRED)
def test_required_unsafe_cases_are_rejected(pack, text):
    r = classify(text, pack)
    assert r["kind"] == "rejected" and r["reason"].startswith("unsafe:"), (text, r)


def test_case6_independent_channel_is_general_template(pack):
    r = classify("Verify the request using a previously established independent contact channel.", pack)
    assert (r["kind"], r["category"]) == ("general", "independent_verification")
    assert r["text"] == GENERAL_TEMPLATES["independent_verification"] and r["evidence_ids"] == []


def test_case7_escalation_is_general_template(pack):
    r = classify("Escalate the suspicious email to the security team.", pack)
    assert (r["kind"], r["category"], r["text"]) == ("general", "escalate", GENERAL_TEMPLATES["escalate"])


def test_case8_preservation_is_general_template(pack):
    r = classify("Preserve the original email for investigation.", pack)
    assert (r["kind"], r["category"]) == ("general", "preserve_evidence")


def test_case9_unsupported_supplier_is_rejected(pack):
    r = classify("Investigate the supplier mentioned in the email.", pack)
    assert r["kind"] == "rejected" and "no deterministic evidence item establishes" in r["reason"]


def test_case9_supplier_is_accepted_only_when_evidence_exists():
    a = _analysis(detection_json={"score": 60, "verdict": "suspicious", "unknowns": [], "findings": [
        {"rule_id": "payment_diversion", "knowledge": "heuristic", "severity": "high", "contribution": 25,
         "title": "Payment diversion", "evidence": "matched 'new supplier bank details'"}]})
    p = build_pack(a, None, None)
    r = classify("Review the payment request to the new supplier.", p)
    assert r["kind"] == "evidence_linked" and r["category"] == "payment_request"
    assert r["evidence_ids"] and all(p.ids[e]["source"] == "rule:payment_diversion" for e in r["evidence_ids"])


def test_case10_evidence_linked_uses_deterministic_ids_and_template(pack):
    r = classify("Investigate the Reply-To domain mismatch.", pack)
    assert (r["kind"], r["category"]) == ("evidence_linked", "reply_to_mismatch")
    assert r["text"] == EVIDENCE_TEMPLATES["reply_to_mismatch"] and "Do not send anything" in r["text"]
    sources = {pack.ids[e]["source"] for e in r["evidence_ids"]}
    assert sources and sources <= {"rule:sender_reply_to_mismatch", "forensics:replyto_mismatch"}


# ── paraphrases and disguises: never accepted ────────────────────────────
DISGUISED = [
    "Verify the wire transfer request with the sender.",                 # the known P4.1 failure
    "R.e.p.l.y to the s-e-n-d-e-r to confirm.",
    "Reply​ to the sen​der to confirm.",                         # zero-width spaces
    "ＲＥＰＬＹ to the sender now",                                         # full-width letters
    "Just respond—quickly—to confirm!",
    "Get in touch with the person who sent it to double-check the transfer.",
    "Reach out to the requester to confirm the payment.",
    "Email the sender back asking whether the request is genuine.",
    "Confirm the bank details with the supplier by replying to this thread.",
    "Verify with the sender via the reply-to address that the wire is legitimate.",
    "Ring the mobile listed at the bottom of the message.",
    "Phone the number in the signature.",
    "Dial the number provided to verify.",
    "Hit the button in the message to confirm the invoice.",
    "Click the link to verify the account.",
    "Open the attachment to see the invoice.",
    "Download the attached PDF and review it.",
    "Go ahead and send the money once the CEO confirms.",
    "Process the invoice payment as requested.",
    "Update the supplier bank details as instructed.",
    "Approve the invoice.",
    "Wire the funds to the new account.",
    "Ask her to confirm over email.",
    "Speak with the CEO using the number she provided.",
    "Use the contact details in the e-mail to verify the request.",
]


@pytest.mark.parametrize("text", DISGUISED)
def test_disguised_unsafe_advice_is_never_accepted(pack, text):
    r = classify(text, pack)
    assert r["kind"] == "rejected", (text, r)


@pytest.mark.parametrize("text", [
    "Do not reply to the email or call any number in it.",
    "Never click links or open attachments from this message.",
    "Do not transfer any funds until the request is independently verified.",
    "Hold the payment; do not change bank details before independent verification.",
])
def test_negated_safety_advice_maps_to_general_templates(pack, text):
    r = classify(text, pack)
    assert r["kind"] == "general" and r["text"] in TEMPLATES, (text, r)


@pytest.mark.parametrize("text", ["Review the organisation's email security policies.",
                                  "Think about it carefully.", "Confirm with Elena directly.", ""])
def test_unrecognised_or_ambiguous_actions_are_rejected(pack, text):
    assert classify(text, pack)["kind"] == "rejected"


def test_shown_text_is_never_model_wording(pack):
    actions = ["Investigate the URL provided in the email.", "Escalate this to the SOC!!",
               "Examine the SPF and DKIM results."]
    recs, _ = ground(actions, pack)
    for r in recs:
        assert r["text"] in TEMPLATES and r["text"] not in actions


def test_url_analysis_never_says_to_open(pack):
    r = classify("Analyse the link in a sandbox without opening it.", pack)
    assert r["category"] == "url_analysis" and "Do not open" in r["text"]


def test_evidence_category_without_evidence_is_rejected():
    p = build_pack(_analysis(attachments=[]), None, None)
    r = classify("Analyse the attachment in a sandbox.", p)
    assert r["kind"] == "rejected"


# ── financial context & general set ──────────────────────────────────────

def test_financial_context_detected_from_evidence_and_text(pack):
    fin = financial_context(pack)
    assert fin["detected"] and "independently verified" in fin["warning"]
    assert any(s["term"] == "wire" for s in fin["evidence_signals"])
    keys = [g["category"] for g in general_recommendations(fin)]
    assert keys[:2] == ["independent_verification", "hold_payments"]


def test_no_financial_warning_for_benign_context():
    a = _analysis(subject="Lunch on Friday?", body_text="Are we still on for lunch?",
                  detection_json={"score": 0, "verdict": "minimal", "unknowns": [], "findings": []})
    fin = financial_context(build_pack(a, None, None))
    assert not fin["detected"] and fin["warning"] is None
    keys = [g["category"] for g in general_recommendations(fin)]
    assert "hold_payments" not in keys and "do_not_use_email_contacts" in keys


def test_ground_dedupes_and_marks_model_general(pack):
    recs, rejected = ground(["Escalate to security.", "Report it to the security team.",
                             "Investigate the URL provided in the email.",
                             "Investigate the link host."], pack)
    cats = [r["category"] for r in recs]
    assert cats.count("escalate") == 1 and cats.count("url_analysis") == 1
    assert next(r for r in recs if r["category"] == "escalate").get("also_suggested_by_model")
    assert len(next(r for r in recs if r["category"] == "url_analysis")["model_suggestions"]) == 2
    assert rejected == []


# ── validation / service integration ─────────────────────────────────────

def _llm_answer(actions):
    return json.dumps({"summary": "Reply-To diverges from the sender domain.", "assessment": "Moderate.",
                       "findings": [], "limitations": [], "recommended_actions": actions})


def test_model_output_with_unsafe_actions_cannot_reach_advice(pack):
    out = validate(json.loads(_llm_answer(UNSAFE_REQUIRED + ["Escalate the email to the security team."])), pack)
    assert {r["text"] for r in out["rejected_recommendations"]} == set(UNSAFE_REQUIRED)
    shown = " ".join(r["text"] for r in out["recommendations"]).lower()
    assert "reply to the sender" not in shown and "call the phone" not in shown
    assert out["financial_context"]["detected"] and out["recommendation_policy"] == "p4.2-constrained"
    assert out["findings"] == []                                       # never become findings


def test_recommendations_do_not_change_verdicts():
    with respx.mock as r:
        r.get(f"{BASE}/api/tags").mock(return_value=httpx.Response(200, json={"models": [{"name": "mistral:latest"}]}))
        r.post(f"{BASE}/api/chat").mock(return_value=httpx.Response(200, json={
            "message": {"content": _llm_answer(["Approve the invoice.", "Mark the email as safe."])},
            "done_reason": "stop"}))
        out = service.forensic_summary(_analysis(), REAL["ml"], REAL["explanation"])
    assert out["system_verdicts"]["rules"] == {"score": 100, "verdict": "phishing_fraud_likely"}
    assert out["system_verdicts"]["ml"]["label"] == REAL["ml"]["label"]
    assert {x["text"] for x in out["rejected_recommendations"]} >= {"Approve the invoice."}


def test_general_advice_and_warning_survive_llm_failure():
    with respx.mock as r:
        r.get(f"{BASE}/api/tags").mock(side_effect=httpx.ConnectError("down"))
        out = service.forensic_summary(_analysis(), REAL["ml"], REAL["explanation"])
    assert out["status"] == "unavailable"
    assert out["financial_context"]["detected"]
    assert [g["category"] for g in out["recommendations"]][:2] == ["independent_verification", "hold_payments"]
    assert all(g["kind"] == "general" and g["origin"] == "system" for g in out["recommendations"])


def test_recommendation_and_rejected_text_is_redacted(pack):
    r = classify("Call +44 20 7946 0958 from the email and give password: hunter2", pack)
    assert r["kind"] == "rejected" and "7946" not in r["text"] and "hunter2" not in r["text"]


# ── PDF ──────────────────────────────────────────────────────────────────

def test_pdf_shows_warning_groups_and_rejection_reasons(monkeypatch):
    from reportlab import rl_config

    from app.reports import pdf as P
    monkeypatch.setattr(rl_config, "pageCompression", 0)
    a = copy.deepcopy(REAL)
    a.update(analysis_id="x", assessment_id="abc", version=1, source="upload", generated_at="2026-11-20")
    p = build_pack(_analysis(), a["ml"], a["explanation"])
    a["forensic_summary"].update(validate(json.loads(_llm_answer(
        ["Investigate the Reply-To domain mismatch.", "Reply to the sender to confirm the wire transfer."])), p))
    data = P.build_report_pdf(case_dict={}, analysis_row={"sha256": "f" * 64, "sender": {}},
                              detection={"score": 100, "verdict": "phishing_fraud_likely", "findings": [],
                                         "unknowns": []}, forensics={}, auth={}, enrichment={}, integrity={},
                              report_id="R", assessment=a)
    lines = []
    for block in re.findall(rb"\bBT\b(.*?)\bET\b", data, re.S):
        for line in re.split(rb"T\*", block):
            parts = re.findall(rb"\(((?:\\.|[^\\)])*)\)\s*Tj", line)
            lines.append(b"".join(parts).decode("latin-1"))
    text = re.sub(r"([_.:-]) ", r"\1", " ".join(lines)).replace("\\(", "(").replace("\\)", ")")
    for needle in ("INDEPENDENT VERIFICATION REQUIRED", "Evidence-linked recommendations",
                   "General recommendations (system templates", "Rejected unsafe or unsupported",
                   "Reply to the sender to confirm the wire transfer.", "replies to the suspicious email",
                   "not findings"):
        assert needle in text, needle


def test_live_false_positive_sender_and_reply_to_domains(pack):
    """Seen in the live Mistral run: investigating the domains is not contacting anyone."""
    r = classify("Investigate the sender and reply-to domains", pack)
    assert (r["kind"], r["category"]) == ("evidence_linked", "reply_to_mismatch")
