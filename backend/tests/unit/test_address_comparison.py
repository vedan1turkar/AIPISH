"""P5d.1: Return-Path / sender / Reply-To domain comparison fix, plus ML feature parity."""
from __future__ import annotations

import json
import math
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.auth import run_auth_analysis
from app.detection import run_detection
from app.forensics.headers import run_header_forensics
from app.ingestion.addresses import (
    HEADER_COMPARISON_VERSION,
    address_domain,
    address_domains,
    message_id_domain,
    normalize_mail_domain,
)
from app.ingestion.parser import parse_eml

FIX = Path(__file__).resolve().parents[1] / "fixtures"


def eml(frm="Alice <alice@example-corp.test>", return_path=None, reply_to=None, sender=None,
        message_id="<m1@example-corp.test>") -> bytes:
    h = ["Received: from mail.example-corp.test (mail.example-corp.test [96.7.128.175])\r\n"
         "\tby mx.receiver.test with ESMTP id x; Sat, 10 Oct 2026 09:00:00 +0000\r\n",
         f"From: {frm}\r\n", "To: bob@receiver.test\r\n", "Subject: hello\r\n",
         "Date: Sat, 10 Oct 2026 09:00:00 +0000\r\n", f"Message-ID: {message_id}\r\n"]
    if return_path is not None:
        h.append(f"Return-Path: {return_path}\r\n")
    if reply_to is not None:
        h.append(f"Reply-To: {reply_to}\r\n")
    if sender is not None:
        h.append(f"Sender: {sender}\r\n")
    return ("".join(h) + "MIME-Version: 1.0\r\nContent-Type: text/plain\r\n\r\nhello\r\n").encode("utf-8")


def inc(raw: bytes, legacy: bool = False) -> list[str]:
    return [i.rule_id for i in run_header_forensics(parse_eml(raw), legacy_domain_compare=legacy).inconsistencies]


# ── helper ───────────────────────────────────────────────────────────────
@pytest.mark.parametrize("value,expected", [
    ("<bounce@example-corp.test>", "example-corp.test"),
    ("bounce@Example-Corp.TEST", "example-corp.test"),
    ("<bounce@example-corp.test.>", "example-corp.test"),
    ("Bounce Service <bounce@example-corp.test>", "example-corp.test"),
    ('"Doe, Jane" <jane@example-corp.test>', "example-corp.test"),
    ("bounce@example-corp.test (bounce handler)", "example-corp.test"),
    ("  <bounce@example-corp.test>  ", "example-corp.test"),
    ("<x@bücher.test>", "xn--bcher-kva.test"),
    ("<x@xn--bcher-kva.test>", "xn--bcher-kva.test"),
    ("<>", None),
    ("", None),
    (None, None),
    ("not an address", None),
])
def test_address_domain(value, expected):
    assert address_domain(value) == expected


def test_multiple_addresses_and_message_id():
    assert address_domains("a@one.test, \"B, b\" <b@Two.TEST.>, c@three.test") == ["one.test", "two.test", "three.test"]
    assert message_id_domain("<abc@Example-Corp.TEST>") == "example-corp.test"
    assert normalize_mail_domain("Ex​ample.COM.") == "example.com" and HEADER_COMPARISON_VERSION == 2


# ── forensics ────────────────────────────────────────────────────────────
def test_angle_bracket_return_path_equal_to_from_is_not_a_mismatch():
    raw = eml(return_path="<bounce@example-corp.test>")
    assert "returnpath_mismatch" not in inc(raw)
    assert "returnpath_mismatch" in inc(raw, legacy=True)            # the old bug, kept for ML parity


def test_real_return_path_mismatch_still_detected():
    r = run_header_forensics(parse_eml(eml(return_path="<bounce@other-mailer.test>")))
    rp = next(i for i in r.inconsistencies if i.rule_id == "returnpath_mismatch")
    assert rp.evidence == "From domain example-corp.test ≠ Return-Path domain other-mailer.test"   # no stray '>'


@pytest.mark.parametrize("rp", [
    "Bounce Service <bounce@example-corp.test>", '"Ops, Bounce" <bounce@example-corp.test>',
    "bounce@example-corp.test (handler)", "<BOUNCE@EXAMPLE-CORP.TEST>", "<bounce@example-corp.test.>",
])
def test_equivalent_return_path_forms_do_not_mismatch(rp):
    assert "returnpath_mismatch" not in inc(eml(return_path=rp))


def test_punycode_and_unicode_from_compare_equal():
    raw = eml(frm="Shop <info@bücher.test>", return_path="<b@xn--bcher-kva.test>",
              reply_to="r@XN--BCHER-KVA.test", message_id="<m@bücher.test>")
    assert set(inc(raw)) & {"returnpath_mismatch", "replyto_mismatch", "messageid_domain_mismatch"} == set()


def test_null_reverse_path_bounce_never_mismatches_or_crashes():
    for legacy in (False, True):
        assert "returnpath_mismatch" not in inc(eml(return_path="<>"), legacy=legacy)


def test_reply_to_variants():
    assert "replyto_mismatch" not in inc(eml(reply_to="Alice <alice@Example-Corp.TEST>"))
    assert "replyto_mismatch" not in inc(eml(frm="S <s@xn--bcher-kva.test>", reply_to="s@bücher.test"))
    assert "replyto_mismatch" in inc(eml(frm="S <s@xn--bcher-kva.test>", reply_to="s@bücher.test"), legacy=True)
    assert "replyto_mismatch" in inc(eml(reply_to="Pay <pay@drop-box-mail.test>"))
    multi = inc(eml(reply_to="alice@example-corp.test, pay@drop-box-mail.test"))
    assert multi.count("replyto_mismatch") == 1                      # only the diverging address


def test_sender_header_is_not_a_comparison_input():
    # No consumer compares Sender today; a divergent Sender must not create a mismatch by accident.
    assert set(inc(eml(sender="Relay <relay@other-mailer.test>"))) & {"returnpath_mismatch", "replyto_mismatch"} == set()
    assert address_domain("Relay <relay@Other-Mailer.TEST.>") == "other-mailer.test"


# ── detection (Reply-To rule) ────────────────────────────────────────────
def test_detection_reply_to_rule_normalises_but_legacy_path_does_not():
    # Unicode Reply-To vs punycode From: same domain. (The parser drops trailing-dot addresses
    # entirely, so the IDN form is the reachable variant of this bug class here.)
    raw = eml(frm="Shop <info@xn--bcher-kva.test>", reply_to="info@Bücher.test")
    parsed = parse_eml(raw)
    fired = lambda **kw: [f.rule_id for f in run_detection(parsed, **kw).findings]  # noqa: E731
    assert "sender_reply_to_mismatch" not in fired()
    assert "sender_reply_to_mismatch" in fired(legacy_domain_compare=True)
    real = parse_eml(eml(reply_to="pay@drop-box-mail.test"))
    assert "sender_reply_to_mismatch" in [f.rule_id for f in run_detection(real).findings]


# ── auth alignment, enrichment and correlation parsing ──────────────────
def test_auth_alignment_uses_parsed_return_path():
    parsed = parse_eml(eml(return_path="Bounce <bounce@mail.example-corp.test.>"))
    assert run_auth_analysis(parsed, b"", live=False).alignment["spf"] == "aligned"
    parsed = parse_eml(eml(return_path="<>"))
    assert run_auth_analysis(parsed, b"", live=False).alignment["spf"] == "unknown"
    parsed = parse_eml(eml(return_path="<b@other-mailer.test>"))
    assert run_auth_analysis(parsed, b"", live=False).alignment["spf"] == "misaligned"


def test_enrichment_and_correlation_return_path_parsing():
    from app.correlation.config import get_correlation_config
    from app.correlation.extract import extract
    from app.enrichment.iocs import collect_iocs
    parsed = parse_eml(eml(return_path="Bounce <bounce@Other-Mailer.test.>"))
    assert any(i.value == "other-mailer.test" and i.origin == "Return-Path" for i in collect_iocs(parsed, []))
    rec = SimpleNamespace(forensics_json={}, from_domain="example-corp.test", reply_to_emails=[],
                          return_path="Bounce <bounce@Other-Mailer.test.>", message_id=None, urls=[], attachments=[],
                          from_display_name=None)
    rp = [x for x in extract(rec, get_correlation_config()) if x.type == "return_path_domain"]
    assert [x.value for x in rp] == ["other-mailer.test"]


def test_new_analyses_record_comparison_version():
    r = run_header_forensics(parse_eml(eml())).to_dict()
    assert r["header_comparison_version"] == 2


# ── ML parity ────────────────────────────────────────────────────────────
def test_ml_rule_features_identical_to_pre_fix_baseline():
    """The ML feature path must produce exactly the rule features the model was trained on.

    Snapshot generated from commit 699a9fd (before the fix) for every committed fixture."""
    from app.ml import features as F
    snap = json.loads((FIX / "ml" / "legacy_rule_features_699a9fd.json").read_text())
    assert snap["feature_names"] == list(F.RULE_FEATURE_NAMES)
    assert set(snap["fixtures"]) == {str(p.relative_to(FIX)) for p in FIX.rglob("*.eml")}
    for rel, expected in snap["fixtures"].items():
        got = [None if math.isnan(v) else v for v in F.rule_features(F.run_rules_offline((FIX / rel).read_bytes()))]
        assert got == expected, rel
    # and at least one fixture really differs between the paths, so the test is meaningful
    raw = (FIX / "demo/attack/synthetic_macro_attachment.eml").read_bytes()
    assert F.run_rules_offline(raw)["score"] != F.run_rules_offline_current(raw)["score"]


def test_ml_endpoints_feed_legacy_features_but_show_fixed_rules():
    from tests.authutil import authed_client
    c = authed_client(role="analyst")
    p = FIX / "demo/attack/synthetic_macro_attachment.eml"
    body = c.post("/api/v1/ml/classify", files={"file": (p.name, p.read_bytes(), "message/rfc822")}).json()
    assert body["rules"]["score"] == 45 and "header_inconsistency_forensics" not in body["rules"]["fired"]
