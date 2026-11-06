"""Detection-engine tests: positive, negative, borderline, malformed, determinism.

Key invariants under test:
- known-phishing fixture scores in the phishing band with multiple findings
- benign fixture scores 0 / minimal with NO findings
- a single keyword or a single failed auth result can NEVER reach the
  phishing band alone (guardrail)
- malformed messages produce unknowns, never a "safe" claim
- identical inputs → identical output (determinism)
"""
from __future__ import annotations

from pathlib import Path

import pytest

from app.detection import build_features, get_config, run_detection
from app.detection.engine import VERDICT_MINIMAL, VERDICT_PHISHING, VERDICT_SUSPICIOUS
from app.ingestion.parser import parse_eml

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "eml"
CFG = get_config()


def detect(raw: bytes):
    return run_detection(parse_eml(raw))


# ── positive ───────────────────────────────────────────────────────────────

def test_phishing_fixture_scores_in_phishing_band() -> None:
    r = detect((FIXTURES / "phishing_multipart.eml").read_bytes())
    assert r.score >= CFG.band_phishing_min
    assert r.verdict == VERDICT_PHISHING
    ids = [f.rule_id for f in r.findings]
    assert "sender_reply_to_mismatch" in ids
    assert "urgency_language" in ids
    assert "credential_request" in ids
    # score = min(sum of contributions, 100) — bounded
    assert r.score == min(sum(f.contribution for f in r.findings), 100)


def test_lookalike_domain_fires_with_brand_display_name() -> None:
    raw = b'From: "PayPal Security" <alerts@paypa1-secure.com>\r\nTo: v@e.net\r\nSubject: hi\r\n\r\nplease check\r\n'
    r = detect(raw)
    f = next(f for f in r.findings if f.rule_id == "lookalike_domain")
    assert f.knowledge == "heuristic"
    assert f.evidence.startswith("display name claims brand")
    assert f.contribution == CFG.weights["lookalike_domain"]


def test_ip_literal_url_fires() -> None:
    raw = b"From: d@shop.example\r\nTo: v@e.net\r\nSubject: offer\r\n\r\nClick http://203.0.113.9/act\r\n"
    r = detect(raw)
    f = next(f for f in r.findings if f.rule_id == "ip_literal_url")
    assert f.knowledge == "fact"
    assert "203.0.113.9" in f.evidence


def test_bec_payment_diversion_fires() -> None:
    raw = (
        b"From: ceo@internal-corp.com\r\nTo: fin@internal-corp.com\r\n"
        b"Subject: quick task\r\n\r\n"
        b"Please urgently update the bank details for our vendor and remit to the new account number.\r\n"
    )
    r = detect(raw)
    ids = [f.rule_id for f in r.findings]
    assert "payment_diversion" in ids
    assert r.verdict == VERDICT_SUSPICIOUS        # 25+20=45 < 60: suspicious, not phishing


def test_risky_attachment_fires() -> None:
    raw = (
        b"From: s@corp.example\r\nTo: v@e.net\r\nSubject: doc\r\n"
        b'Content-Type: multipart/mixed; boundary="B"\r\n\r\n'
        b"--B\r\nContent-Type: text/plain\r\n\r\nsee attached\r\n"
        b"--B\r\nContent-Type: application/octet-stream; name=\"invoice.docm\"\r\n"
        b"Content-Disposition: attachment; filename=\"invoice.docm\"\r\n\r\n"
        b"AA\r\n--B--\r\n"
    )
    r = detect(raw)
    ids = [f.rule_id for f in r.findings]
    assert "risky_attachment_type" in ids
    att_f = next(f for f in r.findings if f.rule_id == "risky_attachment_type")
    assert att_f.knowledge == "fact"


def test_url_obfuscation_fires() -> None:
    raw = (
        "From: p@corp.example\r\nTo: v@e.net\r\nSubject: hi\r\n\r\n"
        "Check https://exa\u200b\u200bmple.com/login now\r\n"
    ).encode()
    r = detect(raw)
    ids = [f.rule_id for f in r.findings]
    assert "url_obfuscation" in ids


# ── negative (must NOT fire) ───────────────────────────────────────────────

def test_benign_fixture_scores_zero() -> None:
    r = detect((FIXTURES / "benign.eml").read_bytes())
    assert r.score == 0
    assert r.verdict == VERDICT_MINIMAL
    assert r.findings == []


def test_legit_brand_domain_never_fires_lookalike() -> None:
    raw = b'From: "PayPal Service" <service@paypal.com>\r\nTo: v@e.net\r\nSubject: hi\r\n\r\ncheck\r\n'
    r = detect(raw)
    assert all(f.rule_id != "lookalike_domain" for f in r.findings)


def test_lookalike_requires_reliable_reference() -> None:
    # lookalike domain but NO brand in display name → must NOT fire
    raw = b'From: "Some Vendor" <alerts@paypa1-secure.com>\r\nTo: v@e.net\r\nSubject: hi\r\n\r\ncheck\r\n'
    r = detect(raw)
    assert all(f.rule_id != "lookalike_domain" for f in r.findings)


def test_single_keyword_cannot_reach_phishing_band() -> None:
    """One urgency word alone is 20 points — verdict stays minimal."""
    raw = b"From: m@corp.example\r\nTo: v@e.net\r\nSubject: hi\r\n\r\nThis is urgent.\r\n"
    r = detect(raw)
    assert r.score <= CFG.weights["urgency_language"]
    assert r.verdict == VERDICT_MINIMAL


def test_single_auth_failure_cannot_reach_phishing_band() -> None:
    """A lone spf=fail line adds only its small weight; never phishing by itself."""
    raw = (
        b"From: m@corp.example\r\nTo: v@e.net\r\nSubject: hi\r\n"
        b"Authentication-Results: mx.test; spf=fail smtp.mailfrom=corp.example\r\n"
        b"\r\nHello, the report is on the drive.\r\n"
    )
    r = detect(raw)
    assert [f.rule_id for f in r.findings] == ["auth_failure_support"]
    assert r.score <= CFG.weights["auth_failure_support"]
    assert r.verdict == VERDICT_MINIMAL


def test_normal_attachment_types_not_flagged() -> None:
    raw = (
        b"From: s@corp.example\r\nTo: v@e.net\r\nSubject: doc\r\n"
        b'Content-Type: multipart/mixed; boundary="B"\r\n\r\n'
        b"--B\r\nContent-Type: text/plain\r\n\r\nsee attached\r\n"
        b"--B\r\nContent-Type: application/pdf; name=\"notes.pdf\"\r\n"
        b"Content-Disposition: attachment; filename=\"notes.pdf\"\r\n\r\n"
        b"AA\r\n--B--\r\n"
    )
    r = detect(raw)
    assert all(f.rule_id != "risky_attachment_type" for f in r.findings)


# ── borderline ─────────────────────────────────────────────────────────────

def test_borderline_mail_is_suspicious_not_phishing() -> None:
    """Urgency + caps in subject (20+15=35) — suspicious, below phishing."""
    raw = (
        b"From: n@corp.example\r\nTo: v@e.net\r\nSubject: ACTION REQUIRED NOW\r\n\r\n"
        b"Please respond asap about the vendor forms.\r\n"
    )
    r = detect(raw)
    assert CFG.band_suspicious_min <= r.score < CFG.band_phishing_min
    assert r.verdict == VERDICT_SUSPICIOUS


# ── malformed → unknown, never safe ───────────────────────────────────────

def test_malformed_message_yields_unknowns_not_safe() -> None:
    r = detect(b"\x00\xff garbage not an email")
    assert r.score == 0
    assert r.verdict == VERDICT_MINIMAL
    fields = {u.field for u in r.unknowns}
    assert "from_domain" in fields
    assert "urls" in fields
    assert "headers" in fields
    # observed facts never claim safety
    assert all("safe" not in txt.lower() for txt in r.observed_facts)


# ── determinism ─────────────────────────────────────────────────────────────

@pytest.mark.parametrize("fixture", ["benign.eml", "phishing_multipart.eml", "malformed.eml"])
def test_identical_input_identical_output(fixture: str) -> None:
    raw = (FIXTURES / fixture).read_bytes()
    a = detect(raw)
    b = detect(raw)
    assert a.score == b.score
    assert a.verdict == b.verdict
    assert [f.to_dict() for f in a.findings] == [f.to_dict() for f in b.findings]
    assert a.to_dict() == b.to_dict()


def test_findings_sorted_deterministically() -> None:
    r = detect((FIXTURES / "phishing_multipart.eml").read_bytes())
    keys = [(-f.contribution, f.rule_id) for f in r.findings]
    assert keys == sorted(keys)


# ── schema of findings ─────────────────────────────────────────────────────

def test_finding_has_severity_evidence_rationale_knowledge() -> None:
    r = detect((FIXTURES / "phishing_multipart.eml").read_bytes())
    for f in r.findings:
        assert f.severity in {"info", "low", "medium", "high", "critical"}
        assert f.evidence.strip()
        assert f.rationale.strip()
        assert f.knowledge in {"fact", "heuristic"}
        assert 0 < f.contribution <= f.weight


def test_score_bounded_0_100() -> None:
    r = detect((FIXTURES / "phishing_multipart.eml").read_bytes())
    assert 0 <= r.score <= 100


def test_config_is_single_source_of_truth() -> None:
    cfg = get_config()
    assert cfg.band_suspicious_min < cfg.band_phishing_min
    assert all(0 < w <= 50 for w in cfg.weights.values())   # no single rule can dominate
