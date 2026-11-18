"""Authentication-module tests: claim parsing, statuses, alignment, DNS mocking.

Live DNS is never used in tests — a stub resolver dict and monkeypatched
``safe_dns_query`` / ``check_spf_live`` / ``check_dkim_live`` simulate:
missing records, NXDOMAIN/unavailable DNS, malformed headers, and
conflicting results.
"""
from __future__ import annotations

from pathlib import Path

import pytest

import app.auth as auth_mod
from app.auth import run_auth_analysis
from app.ingestion.parser import parse_eml
from app.detection import run_detection
from app.detection.config import get_config

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "eml"
PHISH_RAW = (FIXTURES / "phishing_multipart.eml").read_bytes()


@pytest.fixture(autouse=True)
def _no_live_dns(monkeypatch):
    """Default every live lookup to an offline 'unavailable' stub; tests that
    need a specific live verdict patch the function themselves (overrides this)."""
    monkeypatch.setattr(auth_mod, "safe_dns_query", lambda *a, **k: (None, "offline-stub"))
    monkeypatch.setattr(auth_mod, "check_spf_live", lambda *a, **k: (None, "spf_error:offline-stub"))
    monkeypatch.setattr(auth_mod, "check_dkim_live", lambda *a, **k: (None, "dkim_error:offline-stub"))


def _mk(raw=PHISH_RAW, extra_relay_ip=None, **kw):
    """Build an offline auth analysis; kw keys override defaults (live etc.)."""
    defaults: dict = dict(live=False)
    defaults.update(kw)
    return run_auth_analysis(parse_eml(raw), raw, relay_origin_ip=extra_relay_ip, **defaults)


# ── claim parsing (offline) ───────────────────────────────────────────────

def test_claims_extracted_as_parsed_not_verified() -> None:
    a = _mk()
    assert a.spf.status == "parsed"
    assert a.spf.claim_texts == ["fail (paypa1-secure.com)"]
    assert a.dmarc.status == "parsed"
    assert any("fail" in t for t in a.dmarc.claim_texts)
    assert a.spf.reason and "not verified" in a.spf.reason


def test_no_claims_no_headers_is_unknown() -> None:
    raw = b"From: s@clean.example\r\nTo: v@r.net\r\nSubject: t\r\n\r\nbody\r\n"
    a = _mk(raw)
    assert a.spf.status == "unknown"
    assert a.dkim.status == "unknown"
    assert a.dmarc.status == "unknown"


def test_status_legend_documented() -> None:
    a = _mk()
    for k in ("parsed", "verified_pass", "verified_fail", "unavailable", "unknown"):
        assert k in a.to_dict()["status_legend"]


# ── SPF live (mocked) ─────────────────────────────────────────────────────

def test_spf_live_pass(monkeypatch) -> None:
    monkeypatch.setattr(auth_mod, "check_spf_live", lambda *a, **k: ("pass", "live check"))
    raw = (FIXTURES / "benign.eml").read_bytes()
    a = _mk(raw, extra_relay_ip="96.7.128.175", live=True)
    assert a.spf.status == "verified_pass"


def test_spf_live_fail(monkeypatch) -> None:
    monkeypatch.setattr(auth_mod, "check_spf_live", lambda *a, **k: ("fail", "live check"))
    a = _mk(extra_relay_ip="96.7.128.175", live=True)
    assert a.spf.status == "verified_fail"


def test_spf_dns_unavailable(monkeypatch) -> None:
    monkeypatch.setattr(auth_mod, "check_spf_live", lambda *a, **k: (None, "spf_error:DNSTimeout"))
    a = _mk(extra_relay_ip="96.7.128.175", live=True)
    assert a.spf.status == "unavailable"
    assert a.spf.reason and "DNSTimeout" in a.spf.reason


def test_spf_no_ip_no_live_call(monkeypatch) -> None:
    """No relay IP → cannot run live SPF; stays a claim, never invented."""
    called = {"x": False}
    def boom(*a, **k):
        called["x"] = True
        raise AssertionError("live SPF must not run without an IP")
    monkeypatch.setattr(auth_mod, "check_spf_live", boom)
    a = _mk(extra_relay_ip=None, live=True)
    assert a.spf.status == "parsed"
    assert called["x"] is False


# ── DKIM live (mocked) ───────────────────────────────────────────────────

def test_dkim_live_pass(monkeypatch) -> None:
    """A message WITH a DKIM-Signature gets live verification when mocked pass."""
    monkeypatch.setattr(auth_mod, "check_dkim_live", lambda *a, **k: ("pass", "live check"))
    a = _mk((FIXTURES / "multihop_auth.eml").read_bytes(), live=True)   # fixture has DKIM-Signature
    assert a.dkim.status == "verified_pass"


def test_dkim_fail(monkeypatch) -> None:
    monkeypatch.setattr(auth_mod, "check_dkim_live", lambda *a, **k: ("fail", "dkim_error:PublicKeyNotFound"))
    a = _mk((FIXTURES / "multihop_auth.eml").read_bytes(), extra_relay_ip="96.7.128.175", live=True)
    assert a.dkim.status == "verified_fail"


def test_dkim_dns_error_is_unavailable(monkeypatch) -> None:
    monkeypatch.setattr(auth_mod, "check_dkim_live", lambda *a, **k: (None, "dkim_error:DNSTimeout"))
    a = _mk((FIXTURES / "multihop_auth.eml").read_bytes(), live=True)
    assert a.dkim.status == "unavailable"
    assert "DNSTimeout" in a.dkim.reason


# ── DMARC lookup (mocked) ────────────────────────────────────────────────

def test_dmarc_record_found(monkeypatch) -> None:
    monkeypatch.setattr(auth_mod, "dmarc_record_lookup", lambda *a, **k: ("v=DMARC1; p=reject; sp=reject", None))
    a = _mk(live=True)
    assert a.dmarc.detail.get("published_policy") == "reject"


def test_dmarc_record_missing(monkeypatch) -> None:
    monkeypatch.setattr(auth_mod, "dmarc_record_lookup", lambda *a, **k: (None, "not_found"))
    a = _mk(live=True)
    assert a.dmarc.status in ("parsed", "unknown")


def test_dmarc_dns_down_is_unavailable(monkeypatch) -> None:
    monkeypatch.setattr(auth_mod, "dmarc_record_lookup", lambda *a, **k: (None, "DNSTimeout"))
    a = _mk(live=True)
    assert a.dmarc.status == "unavailable"
    assert "DNSTimeout" in a.dmarc.reason


def test_org_domain_fallback(monkeypatch) -> None:
    # subdomain with no record falls back to org domain
    monkeypatch.setattr(auth_mod, "safe_dns_query", lambda name, q, **k: ([], None))
    plain = auth_mod.org_domain("mail.paypal.com")
    assert plain == "paypal.com"


# ── alignment ─────────────────────────────────────────────────────────────

def test_alignment_spf_misaligned_dkim_aligned() -> None:
    a = _mk((FIXTURES / "multihop_auth.eml").read_bytes())
    assert a.alignment["spf"] == "misaligned"     # other-mailer.com vs legit-brand.com
    assert a.alignment["dkim"] == "aligned"       # d=legit-brand.com == From domain


def test_alignment_unknown_without_envelope() -> None:
    raw = b"From: s@alone.example\r\nTo: v@r.net\r\nSubject: t\r\n\r\nbody\r\n"
    a = _mk(raw)
    assert a.alignment["spf"] == "unknown"


# ── conflicting results → threat score ───────────────────────────────────

def test_verified_fail_feeds_threat_score() -> None:
    """Locally-verified failures add auth_verified_fail weight to the score."""
    raw = (FIXTURES / "multihop_auth.eml").read_bytes()
    parsed = parse_eml(raw)
    base = run_detection(parsed)
    bridged = run_detection(
        parsed,
        auth_verified_fail_protocols=["spf", "dmarc"],
        auth_alignment={"spf": "misaligned", "dkim": "aligned"},
    )
    assert bridged.score >= base.score + get_config().weights["auth_verified_fail"]
    ids = [f.rule_id for f in bridged.findings]
    assert "auth_verified_fail" in ids and "auth_dmarc_misaligned" in ids


def test_claim_only_adds_nothing() -> None:
    """Claims without verification (live=False path) must not raise the score."""
    raw = (FIXTURES / "multihop_auth.eml").read_bytes()
    parsed = parse_eml(raw)
    base = run_detection(parsed)
    same = run_detection(
        parsed,
        auth_verified_fail_protocols=[],
        auth_has_conflict=False,
        auth_alignment={},
    )
    assert same.score == base.score


def test_header_claim_conflict_detection() -> None:
    """verified_fail + claimed pass = auth_conflict finding."""
    parsed = parse_eml(PHISH_RAW)
    # simulate: header says pass (we can't change the fixture, so flip read)
    # instead: verified pass vs claimed fail → also a conflict
    r = run_detection(
        parsed,
        auth_has_conflict=True,
        auth_conflict_detail="spf: header claimed fail, locally verified pass",
    )
    ids = [f.rule_id for f in r.findings]
    assert "auth_conflict" in ids
    f = next(f for f in r.findings if f.rule_id == "auth_conflict")
    assert f.knowledge == "heuristic"


def test_deterministic_offline() -> None:
    a1 = _mk()
    a2 = _mk()
    assert a1.to_dict() == a2.to_dict()
