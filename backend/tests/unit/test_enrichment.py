"""Enrichment tests — fully offline via stubbed providers.

Covers: normalization/validation (ipaddress), provider statuses incl.
skipped-without-credentials, DNS outage handling, cache behavior, private-IP
geo refusal, and score bridging that only fires on provider-backed evidence.
"""
from __future__ import annotations

from pathlib import Path

import pytest

import app.enrichment.engine as E
from app.enrichment import get_enrichment_config
from app.enrichment.engine import run_enrichment
from app.enrichment.iocs import (
    collect_iocs,
    is_global_ip,
    is_private_ip,
    normalize_domain,
    normalize_ip,
)
from app.detection import run_detection
from app.detection.config import get_config
from app.ingestion.parser import parse_eml

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "eml"
MULTIHOP = (FIXTURES / "multihop_auth.eml").read_bytes()


@pytest.fixture(autouse=True)
def offline_env(monkeypatch):
    """Force offline: stub providers to avoid any real network + clear cache."""
    monkeypatch.setenv("ENRICH_ENABLE_ALL", "0")
    offline = lambda value, cfg, *a, **k: {"status": "unavailable", "reason": "offline-stub"}  # noqa: E731
    for name in ("dns", "rdap", "ipgeo_http"):
        monkeypatch.setitem(E._ENABLED_PROVIDERS, name, offline)
    E._cache.clear()      # never let one test's cached answers leak into another
    yield
    E._cache.clear()


# ── normalization / validation ────────────────────────────────────────────

def test_normalize_ip_valid_and_invalid() -> None:
    assert normalize_ip("8.8.8.8") == "8.8.8.8"
    assert normalize_ip("[2001:4860:4860::8888]") == "2001:4860:4860::8888"
    assert normalize_ip("1.2.3.4:8080") == "1.2.3.4"
    assert normalize_ip("999.1.1.1") is None
    assert normalize_ip("nope") is None
    assert normalize_ip(None) is None


def test_normalize_domain() -> None:
    assert normalize_domain("WWW.Example.COM.") == "example.com"
    assert normalize_domain("mail völ.example") is None
    assert normalize_domain("") is None


def test_ip_classification_global_vs_not() -> None:
    assert is_global_ip("8.8.8.8") is True
    assert is_global_ip("10.0.0.42") is False
    assert is_global_ip("203.0.113.9") is False      # documentation
    assert is_global_ip("::1") is False
    assert is_global_ip("2001:4860:4860::8888") is True
    assert is_global_ip(None) is False


def test_collect_iocs_sources_and_dedupe() -> None:
    parsed = parse_eml(MULTIHOP)
    iocs = collect_iocs(parsed, forensic_ips=["2001:4860:4860::8888"])
    kinds = {(i.kind, i.value) for i in iocs}
    assert ("domain", "legit-brand.com") in kinds        # From
    assert ("domain", "other-mailer.com") in kinds       # Return-Path
    assert ("domain", "elsewhere.net") in kinds          # Reply-To
    assert any(k == "ip" for k, _ in kinds)              # forensic candidate present
    # deduped: no duplicate entries
    assert len(kinds) == len(iocs)


# ── statuses: skipped / not_found / ok ────────────────────────────────────

def test_missing_credentials_produce_skipped(monkeypatch) -> None:
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    monkeypatch.delenv("MAXMIND_GEOIP2_DB", raising=False)
    parsed = parse_eml(MULTIHOP)
    result, iocs = run_enrichment(
        parsed, forensic_ips=["8.8.8.8"],
        cfg=type(get_enrichment_config())(abuseipdb_api_key=None, maxmind_geoip2_db=None),
    )
    statuses = {(r.provider, r.status) for r in result.results}
    assert ("abuseipdb", "skipped") in statuses
    assert ("geoip2_file", "skipped") in statuses
    reasons = [r.evidence.get("reason", "") for r in result.results if r.provider == "abuseipdb"]
    assert any("ABUSEIPDB_API_KEY" in x for x in reasons)


def test_dns_ok_and_cache(monkeypatch) -> None:
    calls = {"n": 0}
    def fake_dns(value, cfg, resolver=None):
        calls["n"] += 1
        return {"status": "ok", "records": {"A": ["93.184.216.34"], "AAAA": None, "MX": [f"10 mail.{value}"], "TXT": ["v=spf1 -all"]}}
    monkeypatch.setitem(E._ENABLED_PROVIDERS, "dns", fake_dns)
    monkeypatch.setitem(E._ENABLED_PROVIDERS, "rdap", lambda v, cfg: {"status": "skipped", "reason": "test"})
    monkeypatch.setitem(E._ENABLED_PROVIDERS, "ipgeo_http", lambda v, cfg: {"status": "skipped", "reason": "test"})
    parsed = parse_eml(MULTIHOP)
    r1, _ = run_enrichment(parsed, forensic_ips=["8.8.8.8"])
    n1 = calls["n"]
    r2, _ = run_enrichment(parsed, forensic_ips=["8.8.8.8"])   # second run → cached
    assert calls["n"] == n1
    ok = [r for r in r1.results if r.provider == "dns" and r.status == "ok"]
    assert ok and any("93.184.216.34" in str(r.evidence) for r in ok)
    assert all(r.provenance for r in r1.results)               # provenance always present
    assert all(r.latency_ms >= 0 for r in r1.results)


def test_dns_not_found(monkeypatch) -> None:
    def fake_dns(value, cfg, resolver=None):
        return {"status": "not_found", "reason": "NXDOMAIN"}
    monkeypatch.setitem(E._ENABLED_PROVIDERS, "dns", fake_dns)
    monkeypatch.setitem(E._ENABLED_PROVIDERS, "rdap", lambda v, cfg: {"status": "skipped", "reason": "test"})
    monkeypatch.setitem(E._ENABLED_PROVIDERS, "ipgeo_http", lambda v, cfg: {"status": "skipped", "reason": "test"})
    parsed = parse_eml(MULTIHOP)
    result, _ = run_enrichment(parsed, forensic_ips=["8.8.8.8"])
    assert any(r.status == "not_found" for r in result.results)


def test_dns_unavailable_is_degraded_not_crash(monkeypatch) -> None:
    def fake_dns(value, cfg, resolver=None):
        return {"status": "unavailable", "reason": "dns-errors:4"}
    monkeypatch.setitem(E._ENABLED_PROVIDERS, "dns", fake_dns)
    monkeypatch.setitem(E._ENABLED_PROVIDERS, "rdap", lambda v, cfg: {"status": "skipped", "reason": "test"})
    monkeypatch.setitem(E._ENABLED_PROVIDERS, "ipgeo_http", lambda v, cfg: {"status": "skipped", "reason": "test"})
    parsed = parse_eml(MULTIHOP)
    result, _ = run_enrichment(parsed, forensic_ips=["8.8.8.8"])
    assert result.degraded and any("dns" in d for d in result.degraded)
    assert result.results  # analysis continues regardless


# ── privacy: no public geo for non-global IPs ────────────────────────────

def test_private_ip_never_gets_geo(monkeypatch) -> None:
    called = {"geo": 0}
    def fake_geo(ip, cfg):
        called["geo"] += 1
        return {"status": "ok"}
    monkeypatch.setitem(E._ENABLED_PROVIDERS, "ipgeo_http", fake_geo)
    monkeypatch.setitem(E._ENABLED_PROVIDERS, "dns", lambda v, cfg: {"status": "not_found", "reason": "x"})
    monkeypatch.setitem(E._ENABLED_PROVIDERS, "rdap", lambda v, cfg: {"status": "skipped", "reason": "test"})
    parsed = parse_eml(MULTIHOP)
    # forensic candidates: only PRIVATE IPs
    result, iocs = run_enrichment(parsed, forensic_ips=["10.0.0.42"])
    assert "10.0.0.42" in [i.value for i in iocs]
    geo_calls = [r for r in result.results if r.provider == "ipgeo_http"]
    assert all(r.ioc_value != "10.0.0.42" for r in geo_calls)   # never geoqueried
    assert called["geo"] == 0


# ── score bridging only on evidence ─────────────────────────────────────

def test_bridge_needs_provider_evidence() -> None:
    cfg = get_config()
    parsed = parse_eml(MULTIHOP)
    base = run_detection(parsed)
    assert base.score == run_detection(      # no enrichment evidence → unchanged
        parsed, enrichment_url_ip_not_global=[], enrichment_domain_no_mx_and_new=[]).score
    bridged = run_detection(
        parsed,
        enrichment_url_ip_not_global=["exa\u200bmple.invalid"],
        enrichment_domain_no_mx_and_new=["legit-brand.com"],
    )
    ids = [f.rule_id for f in bridged.findings]
    assert "ip_url_risky_lookup" in ids and "domain_no_mx_shortlived" in ids
    assert bridged.score >= base.score
    f = next(f for f in bridged.findings if f.rule_id == "domain_no_mx_shortlived")
    assert "legit-brand.com" in f.evidence
    assert all(0 < f_.contribution <= f_.weight for f_ in bridged.findings)


def test_rate_limit_and_timeout_shapes() -> None:
    assert E.ipgeo_lookup("8.8.8.8", type(get_enrichment_config())(
        ipgeo_base_url="http://127.0.0.1:1/json/{ip}",      # closed port → error path
    ))["status"] == "unavailable"
