"""Header-forensics tests: chain order, IP classes, trust boundary, confidence.

Covers: multiple Received headers, missing fields, forged-looking values,
IPv4/IPv6, documentation/private/public addresses, trusted vs untrusted
boundary, and Return-Path/Reply-To/Message-ID inconsistencies.
"""
from __future__ import annotations

from pathlib import Path

from app.forensics import run_header_forensics
from app.forensics.ipclass import classify_ip
from app.ingestion.parser import parse_eml


def _build(received_lines: list[bytes], extra: bytes = b"") -> bytes:
    head = b"".join(received_lines)
    return (
        head
        + b"From: sender@legit.example\r\n"
        + b"To: victim@receiver.net\r\n"
        + b"Subject: t\r\n"
        + extra
        + b"\r\nbody\r\n"
    )


# ── IP classification ──────────────────────────────────────────────────────

def test_ip_classes() -> None:
    assert classify_ip("8.8.8.8").category == "public"
    assert classify_ip("10.0.0.42").category == "private"
    assert classify_ip("172.16.9.9").category == "private"
    assert classify_ip("192.168.1.1").category == "private"
    assert classify_ip("127.0.0.1").category == "loopback"
    assert classify_ip("169.254.3.3").category == "link_local"
    assert classify_ip("192.0.2.55").category == "documentation"
    assert classify_ip("198.51.100.10").category == "documentation"
    assert classify_ip("203.0.113.77").category == "documentation"
    assert classify_ip("100.64.1.1").category == "shared"
    assert classify_ip("224.0.0.5").category == "multicast"
    assert classify_ip("240.1.2.3").category == "reserved"
    # IPv6
    assert classify_ip("2001:4860:4860::8888").category == "public"
    assert classify_ip("::1").category == "loopback"
    assert classify_ip("fe80::1").category == "link_local"
    assert classify_ip("2001:db8::1").category == "documentation"
    assert classify_ip("fd00::5").category == "private"
    assert classify_ip("ff02::1").category == "multicast"
    # invalid/missing
    assert classify_ip("not-an-ip").category == "invalid"
    assert classify_ip(None).category == "invalid"


# ── chain construction ─────────────────────────────────────────────────────

def test_multi_hop_chain_order_and_metadata() -> None:
    raw = _build([
        # top = LAST hop (receiver's own trace)
        b"Received: from mx.boundary-mail.net (mx.boundary-mail.net [96.7.128.175])\r\n"
        b"\tby mx.receiver.net (Postfix) with ESMTPS id 999 for <v@receiver.net>;\r\n"
        b"\tSat, 10 Oct 2026 09:15:05 +0000 (UTC)\r\n",
        b"Received: from relay.first.example.org (relay.first.example.org [172.217.14.99])\r\n"
        b"\tby mx.boundary-mail.net with ESMTP id abc123;\r\n"
        b"\tSat, 10 Oct 2026 09:15:03 +0000 (UTC)\r\n",
        # bottom = FIRST hop (may be forged)
        b"Received: from original.bad.example (originator [203.0.113.9])\r\n"
        b"\tby relay.first.example.org with ESMTP;\r\n"
        b"\tSat, 10 Oct 2026 09:15:01 +0000\r\n",
    ])
    r = run_header_forensics(parse_eml(raw))
    # display order = chronological: first hop first, receiver trace last
    assert [h.index for h in r.chain] == [0, 1, 2]
    assert r.chain[0].from_ip == "203.0.113.9"          # documentation → excluded from claims
    assert r.chain[1].from_ip == "172.217.14.99"        # public
    assert r.chain[2].from_ip == "96.7.128.175"         # public, trusted hop
    # timestamps and protocols carried through
    assert r.chain[2].protocol == "esmtps"
    assert r.chain[2].tls is True
    assert r.chain[2].timestamp and "10 Oct 2026" in r.chain[2].timestamp


def test_public_candidates_and_earliest_vs_verified() -> None:
    raw = _build([
        b"Received: from mx.boundary-mail.net (mx.boundary-mail.net [96.7.128.175])\r\n"
        b"\tby mx.receiver.net with ESMTPS;\r\n\tSat, 10 Oct 2026 09:15:05 +0000\r\n",
        b"Received: from relay.example.org (unknown [172.217.14.99])\r\n"
        b"\tby mx.boundary-mail.net with ESMTP;\r\n\tSat, 10 Oct 2026 09:15:03 +0000\r\n",
    ])
    r = run_header_forensics(parse_eml(raw))
    # BOTH hops carry trusted-boundary by-hosts (mx.boundary-mail.net matches the
    # mx. prefix pattern; mx.receiver.net matches the receiver domain), so both
    # pass the threshold — the "verified" pick is the earliest such hop.
    assert r.candidate_ips == ["172.217.14.99", "96.7.128.175"]
    assert r.earliest_candidate_ip == "172.217.14.99"   # earliest public
    # trusted-zone requirement: verified origin must come from a trusted hop —
    # pick is earliest trusted public IP with sufficient confidence
    assert r.verified_originating_ip == "172.217.14.99"
    assert len(r.chain[0].confidence_reasons) >= 2       # documented rules present


def test_documentation_and_private_ips_excluded_from_origin_claims() -> None:
    raw = _build([
        b"Received: from doc.example (test [192.0.2.55])\r\n"
        b"\tby mx.receiver.net with SMTP;\r\n\tSat, 10 Oct 2026 09:10:00 +0000\r\n",
        b"Received: from gw.corp.local (unknown [10.0.0.42])\r\n"
        b"\tby internal.local with SMTP;\r\n\tSat, 10 Oct 2026 09:00:00 +0000\r\n",
    ])
    r = run_header_forensics(parse_eml(raw))
    assert r.candidate_ips == []                        # 10.x private, 192.0.2.x documentation
    assert r.earliest_candidate_ip is None
    # chronological: bottom (10.x private) first, doc IP second
    assert r.chain[0].from_ip_category == "private"
    assert r.chain[1].from_ip_category == "documentation"


def test_ipv6_handled() -> None:
    raw = _build([
        b"Received: from v6relay.example (v6relay.example [IPv6:2001:4860:4860::8888])\r\n"
        b"\tby mx.receiver.net with ESMTPS;\r\n\tSat, 10 Oct 2026 09:00:00 +0000\r\n",
    ])
    r = run_header_forensics(parse_eml(raw))
    assert r.chain[0].from_ip == "2001:4860:4860::8888"
    assert r.chain[0].from_ip_category == "public"
    assert r.earliest_candidate_ip == "2001:4860:4860::8888"


def test_trusted_boundary_by_receiver_domain() -> None:
    raw = _build([
        # TOP hop: receiver's own trace → trusted (display index 1)
        b"Received: from outside.example (outside [8.8.4.4])\r\n"
        b"\tby mx.receiver.net with ESMTPS;\r\n\tSat, 10 Oct 2026 09:00:00 +0000\r\n",
        # BOTTOM hop: unrelated by-host → untrusted forged-looking zone (display index 0)
        b"Received: from somewhere.example (unknown [8.8.8.8])\r\n"
        b"\tby forge.totalcontrol.example with SMTP;\r\n\tSat, 10 Oct 2026 08:59:00 +0000\r\n",
    ])
    r = run_header_forensics(parse_eml(raw))
    # chronological order: bottom first
    assert r.chain[0].trusted is False                  # by forge.totalcontrol.example
    assert r.chain[1].trusted is True                   # by mx.receiver.net
    assert r.trusted_boundary_index == 1
    # forged-looking hop below the boundary is capped lower
    assert r.chain[0].confidence < r.chain[1].confidence * 0.95


def test_missing_fields_never_crash() -> None:
    raw = _build([b"Received: by mx.receiver.net;\r\n\tSat, 10 Oct 2026 09:00:00 +0000\r\n"])
    r = run_header_forensics(parse_eml(raw))
    assert r.chain[0].from_host is None
    assert r.chain[0].from_ip is None
    assert r.chain[0].from_ip_category == "missing"
    assert r.candidate_ips == []


def test_no_received_headers() -> None:
    raw = (
        b"From: s@legit.example\r\nTo: v@receiver.net\r\nSubject: t\r\n\r\nbody\r\n"
    )
    r = run_header_forensics(parse_eml(raw))
    assert r.chain == []
    assert r.trusted_boundary_index is None
    assert any(i.rule_id == "no_received" for i in r.inconsistencies)


def test_excess_hops_flagged() -> None:
    hops = [
        b"Received: from h%d.example (%d.example [%d])\r\n"
        b"\tby mx.receiver.net with SMTP;\r\n\tSat, 10 Oct 2026 09:00:00 +0000\r\n"
        % (i, i, 8 + i)
        for i in range(1, 13)
    ]
    r = run_header_forensics(parse_eml(_build(hops)))
    assert any(i.rule_id == "excess_hops" for i in r.inconsistencies)


# ── inconsistencies ────────────────────────────────────────────────────────

def test_returnpath_replyto_messageid_mismatches() -> None:
    extra = (
        b"Return-Path: <bounce@other-mailer.com>\r\n"
        b"Reply-To: divergent@elsewhere.net\r\n"
        b"Message-ID: <abc@elsewhere.net>\r\n"
    )
    raw = _build([], extra=extra)
    r = run_header_forensics(parse_eml(raw))
    ids = [i.rule_id for i in r.inconsistencies]
    assert "returnpath_mismatch" in ids
    assert "replyto_mismatch" in ids
    assert "messageid_domain_mismatch" in ids
    for inc in r.inconsistencies:
        assert inc.evidence and inc.rationale


def test_inconsistency_evidence_quotes_real_values() -> None:
    extra = b"Reply-To: catch@evil.example\r\n"
    raw = _build([], extra=extra)
    r = run_header_forensics(parse_eml(raw))
    inc = next(i for i in r.inconsistencies if i.rule_id == "replyto_mismatch")
    assert "evil.example" in inc.evidence


# ── documentation always present ───────────────────────────────────────────

def test_forgery_note_and_disclaimer_and_rules_documented() -> None:
    raw = _build([
        b"Received: by mx.receiver.net;\r\n\tSat, 10 Oct 2026 09:00:00 +0000\r\n",
    ])
    r = run_header_forensics(parse_eml(raw))
    assert "forge" in r.forgery_note.lower()
    assert "not people" in r.disclaimer.lower() or "no person" in r.disclaimer.lower() or "person" in r.disclaimer.lower()
    assert r.confidence_rules and any("+20" in rule for rule in r.confidence_rules)


def test_phishing_fixture_still_works() -> None:
    parsed = parse_eml((Path(__file__).resolve().parents[1] / "fixtures" / "eml" / "phishing_multipart.eml").read_bytes())
    r = run_header_forensics(parsed)
    assert r.chain, "existing fixture must not break"
    ids = [i.rule_id for i in r.inconsistencies]
    assert "returnpath_mismatch" in ids
