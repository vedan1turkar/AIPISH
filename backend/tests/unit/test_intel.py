"""P5a — threat-intelligence provider integrations. Fully mocked (respx); no live network.

Fake credentials only. Every outbound request is captured and checked to carry
nothing but the bare indicator (plus the provider's own auth header/param).
"""
from __future__ import annotations

import io
import json
import logging
from datetime import timedelta
from pathlib import Path

import httpx
import pytest
import respx
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import app.intel.config as intel_config
from app.core.db import Base, get_db
from app.core.models import Analysis, AuditEvent, IntelCacheEntry, ThreatIntelRun, utcnow
from app.intel import base as B
from app.intel.config import IntelConfig, endpoint_allowed
from app.intel.providers import AbuseIPDB, IPinfo, Shodan, TorExitList, VirusTotal, parse_tor_list
from app.intel.service import extract_indicators, run_threat_intel
from app.intel.validate import validate, validate_domain, validate_hash, validate_ip
from app.main import create_app

FAKE = {"virustotal": "test-key-not-real-vt", "abuseipdb": "test-key-not-real-abuse",
        "shodan": "test-key-not-real-shodan", "ipinfo": "test-key-not-real-ipinfo"}
FAKE_VALUES = list(FAKE.values())
VT = "https://www.virustotal.com/api/v3"
ABUSE = "https://api.abuseipdb.com/api/v2/check"
SHODAN = "https://api.shodan.io/shodan/host"
IPINFO = "https://ipinfo.io"
TOR = "https://check.torproject.org/torbulkexitlist"
PUB = "8.8.8.8"
SHA = "a" * 64
BEC = Path(__file__).parents[1] / "fixtures" / "demo" / "bec_wire_change.eml"


def make_cfg(**kw) -> IntelConfig:
    base = dict(
        offline=False, simulated=False, retry_backoff_seconds=0.0, max_iocs_per_analysis=20,
        virustotal_api_key=FAKE["virustotal"], abuseipdb_api_key=FAKE["abuseipdb"],
        shodan_api_key=FAKE["shodan"], ipinfo_token=FAKE["ipinfo"],
        vt_base=VT, abuseipdb_base="https://api.abuseipdb.com/api/v2", shodan_base="https://api.shodan.io",
        ipinfo_base=IPINFO, tor_list_url=TOR,
        enable_virustotal=True, enable_abuseipdb=True, enable_shodan=True, enable_ipinfo=True,
        enable_tor_exit_list=True,
        vt_per_minute=100, vt_per_day=1000, abuseipdb_per_minute=100, abuseipdb_per_day=1000,
        shodan_per_minute=100, shodan_per_day=1000, ipinfo_per_minute=100, ipinfo_per_day=1000,
        tor_per_minute=100, tor_per_day=1000,
    )
    base.update(kw)
    return IntelConfig(**base)


@pytest.fixture(autouse=True)
def _reset():
    B.reset_limiters()
    yield
    B.reset_limiters()
    intel_config.reset_intel_config()


@pytest.fixture
def db():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    yield session
    session.close()


def vt_body(mal=0, sus=0, harmless=60, undetected=10, **attrs):
    return {"data": {"attributes": {"last_analysis_stats": {"malicious": mal, "suspicious": sus,
                                                            "harmless": harmless, "undetected": undetected},
                                    "reputation": 0, "last_analysis_date": 1763600000, **attrs}}}


def abuse_body(score=0, reports=0, **extra):
    return {"data": {"ipAddress": PUB, "abuseConfidenceScore": score, "totalReports": reports,
                     "countryCode": "US", "isp": "Example ISP", "usageType": "Data Center",
                     "lastReportedAt": None, "isTor": False, **extra}}


# ── validation ───────────────────────────────────────────────────────────
@pytest.mark.parametrize("ip", ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111", "[8.8.4.4]"])
def test_valid_public_ips(ip):
    norm, reason = validate_ip(ip)
    assert norm and reason is None


@pytest.mark.parametrize("ip,reason", [
    ("10.1.2.3", "private"), ("192.168.0.1", "private"), ("172.16.5.5", "private"),
    ("127.0.0.1", "loopback"), ("::1", "loopback"), ("169.254.1.1", "link_local"), ("fe80::1", "link_local"),
    ("224.0.0.1", "multicast"), ("ff02::1", "multicast"), ("0.0.0.0", "unspecified"), ("::", "unspecified"),
    ("100.64.1.1", "shared_cgnat"), ("192.0.2.10", "documentation"), ("198.51.100.1", "documentation"),
    ("203.0.113.9", "documentation"), ("2001:db8::1", "documentation"), ("240.0.0.1", "reserved"),
    ("198.18.0.1", "reserved"), ("fc00::1", "private"),
    ("::ffff:10.0.0.1", "ipv4_mapped_private"), ("::ffff:127.0.0.1", "ipv4_mapped_loopback"),
    ("999.1.1.1", "invalid_ip"), ("8.8.8.8/32", "invalid_ip"), ("fe80::1%eth0", "invalid_ip"), ("", "invalid_ip"),
])
def test_rejected_ips(ip, reason):
    norm, got = validate_ip(ip)
    assert norm is None and got == reason


def test_ipv4_mapped_public_normalises_to_ipv4():
    assert validate_ip("::ffff:8.8.8.8") == ("8.8.8.8", None)


@pytest.mark.parametrize("d,norm", [("Example-Phish.COM.", "example-phish.com"), ("fastmail-temp.net", "fastmail-temp.net"),
                                    ("bücher.de", "xn--bcher-kva.de")])
def test_valid_domains(d, norm):
    assert validate_domain(d) == (norm, None)


@pytest.mark.parametrize("d,reason", [
    ("8.8.8.8", "ip_as_domain"), ("localhost", "localhost"), ("intranet", "single_label"),
    ("printer.local", "internal_or_reserved_suffix"), ("db.internal", "internal_or_reserved_suffix"),
    ("nas.lan", "internal_or_reserved_suffix"), ("internal-corp.example", "internal_or_reserved_suffix"),
    ("example.com", "documentation_domain"), ("a" * 64 + ".com", "label_too_long"),
    ("bad_label.com", "invalid_label"), ("-x.com", "invalid_label"), ("evil.com/path", "invalid_domain"),
    ("user@evil.com", "invalid_domain"), ("x.123", "invalid_tld"), ("app.localhost", "localhost"),
])
def test_rejected_domains(d, reason):
    assert validate_domain(d) == (None, reason)


def test_hash_validation():
    assert validate_hash("D41D8CD98F00B204E9800998ECF8427E")[0] == "d41d8cd98f00b204e9800998ecf8427e"
    assert validate_hash("a" * 40)[0] and validate_hash("b" * 64)[0]
    for bad in ("a" * 31, "g" * 32, "a" * 63, "zz", None):
        assert validate_hash(bad)[0] is None


def test_type_inference():
    assert validate("8.8.8.8")[:2] == ("ip", "8.8.8.8")
    assert validate(SHA)[:2] == ("hash", SHA)
    assert validate("evil-example.net")[:2] == ("domain", "evil-example.net")
    assert validate("10.0.0.1") == ("ip", None, "private")


def test_endpoint_policy():
    assert endpoint_allowed("https://api.example.org")
    assert endpoint_allowed("http://127.0.0.1:8765")
    assert not endpoint_allowed("http://api.example.org")
    assert not endpoint_allowed("https://user:pw@api.example.org")


# ── interface basics ─────────────────────────────────────────────────────
def test_consent_default_off_never_calls_network():
    with respx.mock(assert_all_called=False) as m:
        route = m.route().mock(return_value=httpx.Response(200, json=vt_body()))
        r = VirusTotal(make_cfg()).lookup(PUB)          # no consent argument → refused
    assert r.status == B.NOT_ATTEMPTED_CONSENT_DISABLED and not route.called


def test_rejected_indicator_never_calls_network():
    with respx.mock(assert_all_called=False) as m:
        route = m.route().mock(return_value=httpx.Response(200, json=vt_body()))
        for p in (VirusTotal, AbuseIPDB, Shodan, IPinfo, TorExitList):
            r = p(make_cfg()).lookup("10.0.0.5", "ip", consent=True)
            assert r.status == B.NOT_APPLICABLE_INDICATOR
            assert "private" in r.message
    assert not route.called


def test_not_applicable_type():
    r = AbuseIPDB(make_cfg()).lookup("evil-example.net", consent=True)
    assert r.status == B.NOT_APPLICABLE_INDICATOR and r.error_code == "indicator_type_not_supported"


@pytest.mark.parametrize("cls,key", [(VirusTotal, "virustotal_api_key"), (AbuseIPDB, "abuseipdb_api_key"),
                                     (Shodan, "shodan_api_key"), (IPinfo, "ipinfo_token")])
def test_missing_credentials(cls, key):
    with respx.mock(assert_all_called=False) as m:
        route = m.route().mock(return_value=httpx.Response(200, json={}))
        r = cls(make_cfg(**{key: None})).lookup(PUB, consent=True)
    assert r.status == B.MISSING_CREDENTIALS and not route.called


def test_offline_without_cache(db):
    with respx.mock(assert_all_called=False) as m:
        route = m.route().mock(return_value=httpx.Response(200, json=vt_body()))
        r = VirusTotal(make_cfg(offline=True)).lookup(PUB, consent=True, db=db)
    assert r.status == B.NOT_ATTEMPTED_OFFLINE and not route.called


def test_unsafe_endpoint_refused():
    with respx.mock(assert_all_called=False) as m:
        route = m.route().mock(return_value=httpx.Response(200, json=vt_body()))
        r = VirusTotal(make_cfg(vt_base="http://vt.example.org/api")).lookup(PUB, consent=True)
    assert r.status == B.NOT_PERMITTED and r.error_code == "endpoint_not_allowed" and not route.called


# ── VirusTotal ───────────────────────────────────────────────────────────
def test_vt_ip_flagged_get_only():
    with respx.mock() as m:
        route = m.get(f"{VT}/ip_addresses/{PUB}").mock(return_value=httpx.Response(
            200, json=vt_body(mal=3, sus=1, country="US", as_owner="Example AS", asn=15169)))
        r = VirusTotal(make_cfg()).lookup(PUB, consent=True)
    req = route.calls.last.request
    assert req.method == "GET" and req.headers["x-apikey"] == FAKE["virustotal"]
    assert r.status == B.MALICIOUS_OR_FLAGGED and r.data["malicious"] == 3 and r.data["asn"] == 15169
    assert r.source.startswith("VirusTotal API v3 GET /ip_addresses")


def test_vt_domain_clean_wording_is_not_safe():
    with respx.mock() as m:
        m.get(f"{VT}/domains/evil-example.net").mock(return_value=httpx.Response(200, json=vt_body()))
        r = VirusTotal(make_cfg()).lookup("evil-example.net", consent=True)
    assert r.status == B.REPORTED_CLEAN_NO_FLAGS
    assert "not proof of safety" in r.message.lower()
    assert "safe" not in r.message.lower().replace("not proof of safety", "")


def test_vt_hash_and_no_record():
    with respx.mock() as m:
        m.get(f"{VT}/files/{SHA}").mock(return_value=httpx.Response(404, json={"error": {"code": "NotFoundError"}}))
        r = VirusTotal(make_cfg()).lookup(SHA, consent=True)
    assert r.status == B.NO_RECORD and "not proof of safety" in r.message.lower()


def test_vt_never_posts_or_uploads():
    """Only GET requests exist in the adapter; a POST route is never hit."""
    with respx.mock(assert_all_called=False) as m:
        post = m.post(url__regex=r".*").mock(return_value=httpx.Response(200, json={}))
        m.get(url__regex=r".*").mock(return_value=httpx.Response(200, json=vt_body()))
        for ind in (PUB, "evil-example.net", SHA):
            VirusTotal(make_cfg()).lookup(ind, consent=True)
    assert not post.called
    src = (Path(__file__).parents[2] / "app" / "intel" / "providers.py").read_text()
    assert "/urls" not in src and ".post(" not in src and "files=" not in src


@pytest.mark.parametrize("code,status", [(401, B.AUTH_FAILED), (403, B.NOT_PERMITTED), (400, B.PROVIDER_ERROR)])
def test_vt_http_errors(code, status):
    with respx.mock() as m:
        m.get(f"{VT}/ip_addresses/{PUB}").mock(return_value=httpx.Response(code, json={"error": {}}))
        r = VirusTotal(make_cfg()).lookup(PUB, consent=True)
    assert r.status == status


def test_vt_malformed_json():
    with respx.mock() as m:
        m.get(f"{VT}/ip_addresses/{PUB}").mock(return_value=httpx.Response(200, text="<html>nope"))
        r = VirusTotal(make_cfg()).lookup(PUB, consent=True)
    assert r.status == B.MALFORMED_RESPONSE


def test_vt_429_retry_after_sets_cooldown():
    with respx.mock() as m:
        route = m.get(f"{VT}/ip_addresses/{PUB}").mock(return_value=httpx.Response(
            429, headers={"Retry-After": "42"}, json={"error": {"code": "QuotaExceededError"}}))
        p = VirusTotal(make_cfg())
        r1 = p.lookup(PUB, consent=True)
        r2 = p.lookup(PUB, consent=True)
    assert r1.status == B.RATE_LIMITED and r1.retry_after_seconds == 42
    assert r2.status == B.RATE_LIMITED and r2.error_code == "local_rate_limited"
    assert route.call_count == 1            # honoured Retry-After: no second request


def test_vt_daily_quota_429():
    with respx.mock() as m:
        m.get(f"{VT}/ip_addresses/{PUB}").mock(return_value=httpx.Response(
            429, json={"error": {"code": "QuotaExceededError", "message": "daily quota exceeded"}}))
        r = VirusTotal(make_cfg()).lookup(PUB, consent=True)
    assert r.status == B.QUOTA_EXHAUSTED


def test_local_rate_limiter_vt_4_per_minute():
    with respx.mock() as m:
        route = m.get(url__regex=r".*/ip_addresses/.*").mock(return_value=httpx.Response(200, json=vt_body()))
        p = VirusTotal(make_cfg(vt_per_minute=4))
        statuses = [p.lookup(ip, consent=True).status for ip in ("8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9")]
    assert statuses[:4] == [B.REPORTED_CLEAN_NO_FLAGS] * 4 and statuses[4] == B.RATE_LIMITED
    assert route.call_count == 4


def test_daily_quota_counter():
    with respx.mock() as m:
        m.get(url__regex=r".*").mock(return_value=httpx.Response(200, json=abuse_body()))
        p = AbuseIPDB(make_cfg(abuseipdb_per_day=2))
        statuses = [p.lookup(ip, consent=True).status for ip in ("8.8.8.8", "8.8.4.4", "1.1.1.1")]
    assert statuses[2] == B.QUOTA_EXHAUSTED


def test_5xx_retried_once_then_succeeds():
    with respx.mock() as m:
        route = m.get(f"{VT}/ip_addresses/{PUB}").mock(side_effect=[httpx.Response(503), httpx.Response(200, json=vt_body())])
        r = VirusTotal(make_cfg()).lookup(PUB, consent=True)
    assert r.status == B.REPORTED_CLEAN_NO_FLAGS and route.call_count == 2


def test_5xx_twice_is_provider_error_only_one_retry():
    with respx.mock() as m:
        route = m.get(f"{VT}/ip_addresses/{PUB}").mock(return_value=httpx.Response(502))
        r = VirusTotal(make_cfg()).lookup(PUB, consent=True)
    assert r.status == B.PROVIDER_ERROR and route.call_count == 2


def test_timeout_retried_once_then_timeout():
    with respx.mock() as m:
        route = m.get(f"{VT}/ip_addresses/{PUB}").mock(side_effect=httpx.ReadTimeout("slow"))
        r = VirusTotal(make_cfg()).lookup(PUB, consent=True)
    assert r.status == B.TIMEOUT and route.call_count == 2


# ── AbuseIPDB ────────────────────────────────────────────────────────────
def test_abuseipdb_flagged_and_fields():
    with respx.mock() as m:
        route = m.get(ABUSE).mock(return_value=httpx.Response(200, json=abuse_body(score=87, reports=12,
                                                                                   lastReportedAt="2026-11-01T00:00:00+00:00")))
        r = AbuseIPDB(make_cfg()).lookup(PUB, consent=True)
    req = route.calls.last.request
    assert dict(req.url.params) == {"ipAddress": PUB, "maxAgeInDays": "90"}
    assert req.headers["Key"] == FAKE["abuseipdb"]
    assert r.status == B.MALICIOUS_OR_FLAGGED
    assert r.data["abuse_confidence_score"] == 87 and r.data["total_reports"] == 12
    assert r.data["usage_type"] == "Data Center" and r.data["last_reported_at"].startswith("2026-11-01")


def test_abuseipdb_no_reports_is_no_record_not_clean():
    with respx.mock() as m:
        m.get(ABUSE).mock(return_value=httpx.Response(200, json=abuse_body()))
        r = AbuseIPDB(make_cfg()).lookup(PUB, consent=True)
    assert r.status == B.NO_RECORD and "no reports found" in r.message.lower()
    assert "not proof of safety" in r.message.lower()


def test_abuseipdb_low_score_is_record_found():
    with respx.mock() as m:
        m.get(ABUSE).mock(return_value=httpx.Response(200, json=abuse_body(score=5, reports=2)))
        r = AbuseIPDB(make_cfg()).lookup(PUB, consent=True)
    assert r.status == B.RECORD_FOUND


@pytest.mark.parametrize("resp,status", [
    (httpx.Response(401, json={}), B.AUTH_FAILED), (httpx.Response(403, json={}), B.NOT_PERMITTED),
    (httpx.Response(200, json={"data": {"abuseConfidenceScore": "x"}}), B.MALFORMED_RESPONSE),
    (httpx.Response(200, json=[1, 2]), B.MALFORMED_RESPONSE),
    (httpx.Response(429, headers={"X-RateLimit-Remaining": "0", "Retry-After": "3600"}, json={}), B.QUOTA_EXHAUSTED),
    (httpx.Response(429, headers={"Retry-After": "5"}, json={}), B.RATE_LIMITED),
])
def test_abuseipdb_errors(resp, status):
    with respx.mock() as m:
        m.get(ABUSE).mock(return_value=resp)
        r = AbuseIPDB(make_cfg()).lookup(PUB, consent=True)
    assert r.status == status


# ── Shodan ───────────────────────────────────────────────────────────────
def test_shodan_success_record_found():
    with respx.mock() as m:
        route = m.get(f"{SHODAN}/{PUB}").mock(return_value=httpx.Response(200, json={
            "ports": [443, 53, 53], "org": "Example Org", "isp": "Example ISP", "asn": "AS15169",
            "hostnames": ["dns.example-host.net"], "tags": ["cloud"], "country_name": "United States",
            "vulns": ["CVE-1", "CVE-2"]}))
        r = Shodan(make_cfg()).lookup(PUB, consent=True)
    params = dict(route.calls.last.request.url.params)
    assert params == {"key": FAKE["shodan"], "minify": "true"}
    assert r.status == B.RECORD_FOUND and r.data["open_ports"] == [53, 443]
    assert r.data["known_vulnerability_count"] == 2 and r.data["asn"] == "AS15169"


def test_shodan_risk_tag_flags():
    with respx.mock() as m:
        m.get(f"{SHODAN}/{PUB}").mock(return_value=httpx.Response(200, json={"ports": [], "tags": ["compromised"]}))
        r = Shodan(make_cfg()).lookup(PUB, consent=True)
    assert r.status == B.MALICIOUS_OR_FLAGGED


def test_shodan_404_is_no_record():
    with respx.mock() as m:
        m.get(f"{SHODAN}/{PUB}").mock(return_value=httpx.Response(404, json={"error": "No information available"}))
        r = Shodan(make_cfg()).lookup(PUB, consent=True)
    assert r.status == B.NO_RECORD and "not proof of safety" in r.message.lower()


@pytest.mark.parametrize("resp,status", [(httpx.Response(401, json={}), B.AUTH_FAILED),
                                         (httpx.Response(200, json={"ports": "80"}), B.MALFORMED_RESPONSE)])
def test_shodan_errors(resp, status):
    with respx.mock() as m:
        m.get(f"{SHODAN}/{PUB}").mock(return_value=resp)
        assert Shodan(make_cfg()).lookup(PUB, consent=True).status == status


def test_shodan_timeout():
    with respx.mock() as m:
        m.get(f"{SHODAN}/{PUB}").mock(side_effect=httpx.ConnectTimeout("x"))
        assert Shodan(make_cfg()).lookup(PUB, consent=True).status == B.TIMEOUT


# ── IPinfo ───────────────────────────────────────────────────────────────
def test_ipinfo_without_privacy_marks_unavailable_not_false():
    with respx.mock() as m:
        route = m.get(f"{IPINFO}/{PUB}/json").mock(return_value=httpx.Response(200, json={
            "ip": PUB, "city": "Mountain View", "region": "California", "country": "US",
            "org": "AS15169 Google LLC", "loc": "37.4,-122.1"}))
        r = IPinfo(make_cfg()).lookup(PUB, consent=True)
    assert route.calls.last.request.headers["Authorization"] == f"Bearer {FAKE['ipinfo']}"
    assert r.status == B.RECORD_FOUND and r.data["asn"] == "AS15169"
    for f in ("is_vpn", "is_proxy", "is_tor", "is_relay", "is_hosting"):
        assert r.data[f] == "unavailable"
    assert r.data["privacy_flags_returned"] is False
    assert "does not identify a person" in r.data["caveat"]


def test_ipinfo_privacy_flags():
    body = {"ip": PUB, "privacy": {"vpn": True, "proxy": False, "tor": False, "relay": False, "hosting": True}}
    with respx.mock() as m:
        m.get(f"{IPINFO}/{PUB}/json").mock(return_value=httpx.Response(200, json=body))
        r = IPinfo(make_cfg()).lookup(PUB, consent=True)
    assert r.status == B.MALICIOUS_OR_FLAGGED and r.data["is_vpn"] is True and r.data["is_proxy"] is False
    body["privacy"] = {k: False for k in body["privacy"]}
    B.reset_limiters()
    with respx.mock() as m:
        m.get(f"{IPINFO}/{PUB}/json").mock(return_value=httpx.Response(200, json=body))
        r = IPinfo(make_cfg()).lookup(PUB, consent=True)
    assert r.status == B.REPORTED_CLEAN_NO_FLAGS


@pytest.mark.parametrize("resp,status", [(httpx.Response(403, json={}), B.NOT_PERMITTED),
                                         (httpx.Response(404, json={}), B.NO_RECORD),
                                         (httpx.Response(200, json={"city": "x"}), B.MALFORMED_RESPONSE),
                                         (httpx.Response(429, json={}), B.RATE_LIMITED)])
def test_ipinfo_errors(resp, status):
    with respx.mock() as m:
        m.get(f"{IPINFO}/{PUB}/json").mock(return_value=resp)
        assert IPinfo(make_cfg()).lookup(PUB, consent=True).status == status


# ── cache ────────────────────────────────────────────────────────────────
def test_fresh_cache_hit_makes_no_network_call(db):
    with respx.mock() as m:
        route = m.get(ABUSE).mock(return_value=httpx.Response(200, json=abuse_body(score=90, reports=3)))
        p = AbuseIPDB(make_cfg())
        first = p.lookup(PUB, consent=True, db=db)
        second = p.lookup(PUB, consent=True, db=db)
    assert route.call_count == 1
    assert first.cache_state == "none" and second.cache_state == "fresh"
    assert second.status == B.MALICIOUS_OR_FLAGGED and second.fetched_at == first.fetched_at


def _expire(db):
    for row in db.query(IntelCacheEntry).all():
        row.expires_at = utcnow() - timedelta(hours=1)
        row.fetched_at = utcnow() - timedelta(hours=30)
    db.commit()


def test_expired_cache_refetches(db):
    with respx.mock() as m:
        route = m.get(ABUSE).mock(return_value=httpx.Response(200, json=abuse_body(score=90, reports=3)))
        p = AbuseIPDB(make_cfg())
        p.lookup(PUB, consent=True, db=db)
        _expire(db)
        r = p.lookup(PUB, consent=True, db=db)
    assert route.call_count == 2 and r.cache_state == "none"


def test_stale_fallback_on_provider_failure_is_labelled(db):
    p = AbuseIPDB(make_cfg())
    with respx.mock() as m:
        m.get(ABUSE).mock(return_value=httpx.Response(200, json=abuse_body(score=90, reports=3)))
        p.lookup(PUB, consent=True, db=db)
    _expire(db)
    with respx.mock() as m:
        m.get(ABUSE).mock(return_value=httpx.Response(500))
        r = p.lookup(PUB, consent=True, db=db)
    assert r.cache_state == "stale" and r.error_code == B.PROVIDER_ERROR
    assert r.status == B.MALICIOUS_OR_FLAGGED and r.message.startswith("STALE")
    assert r.cache_age_seconds >= 29 * 3600


def test_offline_uses_stale_cache_labelled(db):
    with respx.mock() as m:
        m.get(f"{SHODAN}/{PUB}").mock(return_value=httpx.Response(200, json={"ports": [22]}))
        Shodan(make_cfg()).lookup(PUB, consent=True, db=db)
    _expire(db)
    with respx.mock(assert_all_called=False) as m:
        route = m.route().mock(return_value=httpx.Response(200, json={}))
        r = Shodan(make_cfg(offline=True)).lookup(PUB, consent=True, db=db)
    assert not route.called and r.cache_state == "stale" and r.error_code == B.NOT_ATTEMPTED_OFFLINE


def test_errors_are_not_cached(db):
    with respx.mock() as m:
        m.get(ABUSE).mock(return_value=httpx.Response(500))
        AbuseIPDB(make_cfg()).lookup(PUB, consent=True, db=db)
    assert db.query(IntelCacheEntry).count() == 0


def test_cache_row_holds_no_secret(db):
    with respx.mock() as m:
        m.get(f"{SHODAN}/{PUB}").mock(return_value=httpx.Response(200, json={"ports": [22]}))
        Shodan(make_cfg()).lookup(PUB, consent=True, db=db)
    row = db.query(IntelCacheEntry).one()
    blob = json.dumps({"d": row.data_json, "m": row.message, "k": row.key})
    assert not any(v in blob for v in FAKE_VALUES) and "api.shodan.io" not in blob


# ── Tor ──────────────────────────────────────────────────────────────────
TOR_TEXT = "# comment\n185.220.101.1\n185.220.101.2\nnot-an-ip\n\n2001:67c:e60:c0c:192:42:116:16\n"


def test_tor_list_parse():
    assert parse_tor_list(TOR_TEXT) == sorted(["185.220.101.1", "185.220.101.2", "2001:67c:e60:c0c:192:42:116:16"])


def test_tor_membership_and_list_cached(db):
    with respx.mock() as m:
        route = m.get(TOR).mock(return_value=httpx.Response(200, text=TOR_TEXT, headers={"content-type": "text/plain"}))
        p = TorExitList(make_cfg())
        hit = p.lookup("185.220.101.1", consent=True, db=db)
        miss = p.lookup(PUB, consent=True, db=db)
    assert route.call_count == 1                       # list fetched once, then checked locally
    assert route.calls.last.request.url.params == httpx.QueryParams()   # no indicator sent at all
    assert hit.status == B.MALICIOUS_OR_FLAGGED and hit.data["listed"] is True
    assert miss.status == B.NO_RECORD and "not proof of safety" in miss.message.lower()
    assert miss.cache_state == "fresh"


def test_tor_refresh_after_expiry(db):
    with respx.mock() as m:
        route = m.get(TOR).mock(return_value=httpx.Response(200, text=TOR_TEXT))
        p = TorExitList(make_cfg())
        p.lookup(PUB, consent=True, db=db)
        _expire(db)
        r = p.lookup(PUB, consent=True, db=db)
    assert route.call_count == 2 and r.cache_state == "fresh"


def test_tor_offline_stale_and_no_list(db):
    r = TorExitList(make_cfg(offline=True)).lookup(PUB, consent=True, db=db)
    assert r.status == B.NOT_ATTEMPTED_OFFLINE
    with respx.mock() as m:
        m.get(TOR).mock(return_value=httpx.Response(200, text=TOR_TEXT))
        TorExitList(make_cfg()).lookup(PUB, consent=True, db=db)
    _expire(db)
    with respx.mock(assert_all_called=False) as m:
        route = m.route().mock(return_value=httpx.Response(200, text=""))
        r = TorExitList(make_cfg(offline=True)).lookup("185.220.101.2", consent=True, db=db)
    assert not route.called and r.cache_state == "stale" and r.status == B.MALICIOUS_OR_FLAGGED
    assert r.message.startswith("STALE")


def test_tor_fetch_failure_without_cache(db):
    with respx.mock() as m:
        m.get(TOR).mock(return_value=httpx.Response(200, text="<html>blocked</html>", headers={"content-type": "text/html"}))
        r = TorExitList(make_cfg()).lookup(PUB, consent=True, db=db)
    assert r.status == B.MALFORMED_RESPONSE and r.indicator == PUB


# ── sanitising provider strings ──────────────────────────────────────────
def test_provider_strings_sanitised_and_truncated():
    evil = "Evil‮Org\x00<script>alert(1)</script>" + "x" * 500
    with respx.mock() as m:
        m.get(f"{SHODAN}/{PUB}").mock(return_value=httpx.Response(200, json={"ports": [], "org": evil,
                                                                             "hostnames": [evil] * 50}))
        r = Shodan(make_cfg()).lookup(PUB, consent=True)
    assert "‮" not in r.data["org"] and "\x00" not in r.data["org"]
    assert len(r.data["org"]) <= 120 and len(r.data["hostnames"]) <= 10


# ── full run over a stored analysis ──────────────────────────────────────
MARKERS = ["SECRET-SUBJECT-MARKER", "BODY-MARKER-XYZ", "alice.victim", "bob.attacker", "QUERYSECRET",
           "/path/to/secret", "Dana Finance", "case-id-marker"]


def _analysis(db, **kw) -> Analysis:
    rec = Analysis(
        raw_sha256="f" * 64, raw_size_bytes=100, subject="SECRET-SUBJECT-MARKER",
        from_display_name="Dana Finance", from_email="alice.victim@sender-corp.net", from_domain="sender-corp.net",
        to_emails=["victim@target.net"], reply_to_emails=["bob.attacker@reply-evil.net"],
        return_path="<bounce@bounce-host.net>", body_text="BODY-MARKER-XYZ please pay",
        urls=[{"url": "https://evil-host.net/path/to/secret?token=QUERYSECRET", "host": "evil-host.net",
               "scheme": "https", "in_html": False, "in_text": True},
              {"url": "http://10.0.0.9/x", "host": "10.0.0.9", "scheme": "http", "in_html": False, "in_text": True}],
        attachments=[{"filename": "invoice.pdf", "sha256": SHA, "size_bytes": 10, "content_type": "application/pdf",
                      "is_inline": False, "content_id": None}],
        forensics_json={"candidate_ips": [PUB], "earliest_candidate_ip": PUB, "verified_originating_ip": None,
                        "relay_chain": [{"index": 0, "from_ip": PUB}, {"index": 1, "from_ip": "192.168.1.5"}]},
        detection_score=100, detection_verdict="phishing_fraud_likely", detection_json={"score": 100},
    )
    for k, v in kw.items():
        setattr(rec, k, v)
    db.add(rec)
    db.commit()
    return rec


def _mock_all(m, fail=False):
    if fail:
        m.get(url__regex=r".*").mock(side_effect=httpx.ConnectError("down"))
        return
    m.get(url__regex=rf"{VT}/.*").mock(return_value=httpx.Response(200, json=vt_body(mal=1)))
    m.get(ABUSE).mock(return_value=httpx.Response(200, json=abuse_body(score=50, reports=4)))
    m.get(url__regex=rf"{SHODAN}/.*").mock(return_value=httpx.Response(200, json={"ports": [25], "org": "Org"}))
    m.get(url__regex=rf"{IPINFO}/.*").mock(return_value=httpx.Response(200, json={"ip": PUB, "org": "AS1 X"}))
    m.get(TOR).mock(return_value=httpx.Response(200, text=TOR_TEXT))


def test_extract_indicators_from_stored_analysis(db):
    rec = _analysis(db)
    inds = {(i.indicator_type, i.value): i for i in extract_indicators(rec)}
    assert ("ip", PUB) in inds and ("hash", SHA) in inds and ("domain", "evil-host.net") in inds
    assert ("domain", "sender-corp.net") in inds and ("domain", "reply-evil.net") in inds
    assert ("domain", "bounce-host.net") in inds
    rejected = [i for i in inds.values() if not i.eligible]
    assert {i.value for i in rejected} == {"10.0.0.9", "192.168.1.5"}
    assert all("path" not in i.value and "@" not in i.value for i in inds.values())


def test_outbound_requests_contain_only_the_indicator(db):
    rec = _analysis(db)
    with respx.mock(assert_all_called=False) as m:
        _mock_all(m)
        run = run_threat_intel(db, rec, consent=True, cfg=make_cfg())
        requests = [c.request for c in m.calls]
    assert requests, "expected provider calls"
    indicators = {PUB, SHA, "evil-host.net", "sender-corp.net", "reply-evil.net", "bounce-host.net"}
    for req in requests:
        blob = str(req.url) + json.dumps(dict(req.headers)) + req.content.decode("latin-1")
        for marker in MARKERS + [rec.id, "victim@target.net", "invoice.pdf", "10.0.0.9", "192.168.1.5"]:
            assert marker not in blob, (marker, str(req.url))
        assert req.method == "GET" and req.content == b""
        sent = set(req.url.path.split("/")) | set(req.url.params.values())
        allowed = indicators | set(FAKE_VALUES) | {"", "api", "v3", "v2", "ip_addresses", "domains", "files",
                                                    "check", "shodan", "host", "json", "90", "true",
                                                    "torbulkexitlist"}
        assert sent <= allowed, sent - allowed
        assert set(k.lower() for k in req.url.params.keys()) <= {"ipaddress", "maxageindays", "key", "minify"}
    assert run["counts"]["rejected"] == 2


def test_run_records_consent_and_audit(db):
    rec = _analysis(db)
    with respx.mock(assert_all_called=False) as m:
        _mock_all(m)
        run = run_threat_intel(db, rec, consent=True, source="upload", cfg=make_cfg(),
                               providers=["abuseipdb", "tor_exit_list"])
    assert run["consent"]["granted"] is True and run["consent"]["source"] == "upload"
    assert run["consent"]["providers"] == ["abuseipdb", "tor_exit_list"]
    assert run["informational_only"] is True and run["version"] == 1
    ev = db.query(AuditEvent).filter_by(event_type="threat_intel_lookup").one()
    assert ev.detail["consent_granted"] is True and ev.detail["providers"] == ["abuseipdb", "tor_exit_list"]
    assert PUB not in json.dumps(ev.detail)       # audit holds decisions + counts, not indicators


def test_consent_refused_records_decision_and_sends_nothing(db):
    rec = _analysis(db)
    with respx.mock(assert_all_called=False) as m:
        route = m.route().mock(return_value=httpx.Response(200, json={}))
        run = run_threat_intel(db, rec, consent=False, cfg=make_cfg())
    assert not route.called
    statuses = {r["status"] for i in run["indicators"] for r in i["results"]}
    assert statuses == {B.NOT_ATTEMPTED_CONSENT_DISABLED}
    assert db.get(ThreatIntelRun, run["run_id"]).consent_granted is False


def test_offline_run_sends_nothing(db):
    rec = _analysis(db)
    with respx.mock(assert_all_called=False) as m:
        route = m.route().mock(return_value=httpx.Response(200, json={}))
        run = run_threat_intel(db, rec, consent=True, cfg=make_cfg(offline=True))
    assert not route.called and run["offline"] is True
    assert {r["status"] for i in run["indicators"] for r in i["results"]} == {B.NOT_ATTEMPTED_OFFLINE}


def test_ioc_cap_marks_rest_visible(db):
    rec = _analysis(db)
    with respx.mock(assert_all_called=False) as m:
        _mock_all(m)
        run = run_threat_intel(db, rec, consent=True, cfg=make_cfg(max_iocs_per_analysis=2))
    capped = [i for i in run["indicators"] if i["state"] == B.NOT_ATTEMPTED_CAP_REACHED]
    assert run["counts"]["looked_up"] == 2 and len(capped) == run["counts"]["eligible"] - 2
    assert all(i["results"] == [] and "cap" in i["message"] for i in capped)


def test_duplicate_iocs_deduplicated_within_run(db):
    rec = _analysis(db, from_domain="dup-domain.net", reply_to_emails=["x@dup-domain.net", "y@DUP-domain.net"],
                    return_path="<z@dup-domain.net>")
    with respx.mock(assert_all_called=False) as m:
        _mock_all(m)
        run_threat_intel(db, rec, consent=True, cfg=make_cfg(), providers=["virustotal"])
        dom_calls = [c for c in m.calls if "/domains/dup-domain.net" in str(c.request.url)]
    assert len(dom_calls) == 1


def test_versioned_runs_append(db):
    rec = _analysis(db)
    with respx.mock(assert_all_called=False) as m:
        _mock_all(m)
        a = run_threat_intel(db, rec, consent=True, cfg=make_cfg())
        b = run_threat_intel(db, rec, consent=True, cfg=make_cfg())
    assert (a["version"], b["version"]) == (1, 2)
    assert db.query(ThreatIntelRun).count() == 2


def test_every_provider_failing_never_breaks_run(db):
    rec = _analysis(db)
    with respx.mock(assert_all_called=False) as m:
        _mock_all(m, fail=True)
        run = run_threat_intel(db, rec, consent=True, cfg=make_cfg())
    statuses = {r["status"] for i in run["indicators"] for r in i["results"]}
    assert statuses <= {B.PROVIDER_ERROR, B.TIMEOUT}
    db.refresh(rec)
    assert rec.detection_score == 100 and rec.detection_verdict == "phishing_fraud_likely"


def test_intel_never_reaches_llm_evidence(db):
    from app.api.llm_router import _analysis_dict
    from app.llm.evidence import build_pack
    rec = _analysis(db)
    with respx.mock(assert_all_called=False) as m:
        _mock_all(m)
        m.get(url__regex=rf"{SHODAN}/.*").mock(return_value=httpx.Response(200, json={"ports": [], "org": "PROVIDER-ORG-MARKER"}))
        run_threat_intel(db, rec, consent=True, cfg=make_cfg())
    pack = build_pack(_analysis_dict(rec), None, None)
    text = json.dumps(pack.ids, default=str) + pack.known_text()
    assert "PROVIDER-ORG-MARKER" not in text and "abuse_confidence" not in text


# ── secrets ──────────────────────────────────────────────────────────────
def test_config_repr_and_status_never_leak_keys():
    cfg = make_cfg()
    assert not any(v in repr(cfg) for v in FAKE_VALUES)
    status = json.dumps(cfg.status())
    assert not any(v in status for v in FAKE_VALUES)
    p = cfg.status()["providers"]
    assert p["virustotal"] == {"label": "VirusTotal", "configured": True, "enabled": True, "requires_credentials": True}
    assert p["maxmind_geoip2"]["configured"] is False and p["misp"]["enabled"] is False
    assert make_cfg(shodan_api_key=None).status()["providers"]["shodan"]["configured"] is False


def test_no_secret_in_logs_results_or_errors(db, caplog):
    caplog.set_level(logging.DEBUG)
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setLevel(logging.DEBUG)
    logging.getLogger().addHandler(handler)
    try:
        rec = _analysis(db)
        results = []
        for mode in ("ok", "fail", "malformed"):
            B.reset_limiters()
            db.query(IntelCacheEntry).delete()
            db.commit()
            with respx.mock() as m:
                if mode == "ok":
                    _mock_all(m)
                elif mode == "fail":
                    m.get(url__regex=r".*").mock(side_effect=httpx.ConnectError("boom " + FAKE["shodan"]))
                else:
                    m.get(url__regex=r".*").mock(return_value=httpx.Response(200, text="{bad"))
                results.append(run_threat_intel(db, rec, consent=True, cfg=make_cfg()))
    finally:
        logging.getLogger().removeHandler(handler)
    blob = json.dumps(results) + caplog.text + stream.getvalue()
    for v in FAKE_VALUES:
        assert v not in blob
    assert "api.shodan.io" not in json.dumps(results)


# ── endpoints ────────────────────────────────────────────────────────────
@pytest.fixture
def api(db, monkeypatch):
    app = create_app()
    app.dependency_overrides[get_db] = lambda: db
    intel_config._CONFIG = make_cfg()
    return TestClient(app)


def test_status_endpoint_booleans_only(api):
    r = api.get("/api/v1/intel/status")
    assert r.status_code == 200
    body = r.json()
    assert body["consent_default"] is False and body["informational_only"] is True
    assert all(isinstance(v["configured"], bool) and isinstance(v["enabled"], bool) for v in body["providers"].values())
    assert not any(v in r.text for v in FAKE_VALUES)


def test_endpoints_run_and_fetch(api, db):
    rec = _analysis(db)
    assert api.get(f"/api/v1/analyses/{rec.id}/threat-intel").json()["error"]["code"] == "INTEL_NOT_RUN"
    with respx.mock(assert_all_called=False) as m:
        m.route(host="testserver").pass_through()
        _mock_all(m)
        r = api.post(f"/api/v1/analyses/{rec.id}/threat-intel", json={"consent": True, "source": "on_demand"})
    assert r.status_code == 201, r.text
    run = r.json()
    got = api.get(f"/api/v1/analyses/{rec.id}/threat-intel")
    assert got.status_code == 200 and got.json()["run_id"] == run["run_id"]
    pinned = api.get(f"/api/v1/analyses/{rec.id}/threat-intel", params={"run_id": run["run_id"]})
    assert pinned.json()["version"] == 1
    assert api.get(f"/api/v1/analyses/{rec.id}/threat-intel", params={"run_id": "nope"}).status_code == 404
    assert not any(v in r.text for v in FAKE_VALUES)


def test_endpoint_validation(api, db):
    rec = _analysis(db)
    assert api.post(f"/api/v1/analyses/{rec.id}/threat-intel", json={}).status_code == 400          # consent required
    bad = api.post(f"/api/v1/analyses/{rec.id}/threat-intel", json={"consent": True, "providers": ["misp"]})
    assert bad.status_code == 400 and bad.json()["error"]["code"] == "UNKNOWN_PROVIDER"
    assert api.post("/api/v1/analyses/nope/threat-intel", json={"consent": True}).status_code == 404


def test_endpoint_in_progress_409(api, db):
    from app.intel import service
    rec = _analysis(db)
    service._running.add(rec.id)
    try:
        r = api.post(f"/api/v1/analyses/{rec.id}/threat-intel", json={"consent": False})
    finally:
        service._running.discard(rec.id)
    assert r.status_code == 409 and r.json()["error"]["code"] == "INTEL_IN_PROGRESS"


def test_upload_then_failing_intel_leaves_verdict_unchanged(api, db):
    up = api.post("/api/v1/analyses", files={"file": ("bec.eml", BEC.read_bytes(), "message/rfc822")})
    assert up.status_code == 201
    before = up.json()
    with respx.mock(assert_all_called=False) as m:
        m.route(host="testserver").pass_through()
        _mock_all(m, fail=True)
        r = api.post(f"/api/v1/analyses/{before['id']}/threat-intel", json={"consent": True})
    assert r.status_code == 201
    after = api.get(f"/api/v1/analyses/{before['id']}").json()
    assert after["detection"] == before["detection"]
    assert (after["detection"]["score"], after["detection"]["verdict"]) == (100, "phishing_fraud_likely")
    inds = {i["indicator"]: i for i in r.json()["indicators"]}
    assert inds["internal-corp.example"]["state"] == B.NOT_APPLICABLE_INDICATOR
    assert inds["fastmail-temp.net"]["state"] == "looked_up"


# ── PDF ──────────────────────────────────────────────────────────────────
def _pdf_text(pdf: bytes) -> str:
    """Text of an uncompressed PDF (see the `nocompress` fixture), lines joined by spaces."""
    import re
    out = []
    for block in re.findall(rb"\bBT\b(.*?)\bET\b", pdf, re.S):
        for line in re.split(rb"T\*", block):
            parts = re.findall(rb"\(((?:\\.|[^\\)])*)\)\s*Tj", line)
            if parts:
                text = b"".join(parts).decode("latin-1").replace("\\(", "(").replace("\\)", ")").strip()
                out.append(re.sub(r"([_.-]) ", r"\1", text))
    return " ".join(out)


@pytest.fixture(autouse=True)
def nocompress(monkeypatch):
    from reportlab import rl_config
    monkeypatch.setattr(rl_config, "pageCompression", 0)


def _build(intel):
    from app.reports.pdf import build_report_pdf
    return build_report_pdf(case_dict={"case_number": "CASE-T"}, analysis_row={"id": "a", "sha256": "f" * 64},
                            detection={}, forensics={}, auth={}, enrichment={}, integrity={"result": "unavailable"},
                            report_id="RPT-T", intel=intel)


def test_pdf_section_not_run():
    text = _pdf_text(_build(None))
    assert "Threat Intelligence Lookups" in text and "NOT RUN" in text


def test_pdf_section_content_statuses_and_escaping(db):
    rec = _analysis(db)
    with respx.mock(assert_all_called=False) as m:
        _mock_all(m)
        m.get(url__regex=rf"{SHODAN}/.*").mock(return_value=httpx.Response(
            200, json={"ports": [25], "org": "<b>Evil</b><font size=40>&inject;", "tags": ["compromised"]}))
        run = run_threat_intel(db, rec, consent=True, cfg=make_cfg())
    pdf = _build(run)
    text = _pdf_text(pdf)
    assert "GRANTED" in text and "FLAGGED by provider" in text
    assert "NOT APPLICABLE" in text and "not proof of safety" in text.lower()
    assert "<b>Evil</b>" in text          # printed literally, not interpreted
    assert not any(v.encode() in pdf for v in FAKE_VALUES) and not any(v in text for v in FAKE_VALUES)


def test_pdf_consent_disabled_and_stale_labels(db):
    rec = _analysis(db)
    refused = run_threat_intel(db, rec, consent=False, cfg=make_cfg())
    text = _pdf_text(_build(refused))
    assert "NOT GIVEN" in text and "NOT ATTEMPTED" in text
    p = AbuseIPDB(make_cfg())
    with respx.mock() as m:
        m.get(ABUSE).mock(return_value=httpx.Response(200, json=abuse_body(score=90, reports=3)))
        p.lookup(PUB, consent=True, db=db)
    _expire(db)
    with respx.mock(assert_all_called=False) as m:
        _mock_all(m, fail=True)
        stale_run = run_threat_intel(db, rec, consent=True, cfg=make_cfg(), providers=["abuseipdb"])
    assert "STALE" in _pdf_text(_build(stale_run))


def test_pdf_report_endpoint_pins_intel_run(api, db):
    rec = _analysis(db)
    first = run_threat_intel(db, rec, consent=False, cfg=make_cfg())
    with respx.mock(assert_all_called=False) as m:
        _mock_all(m)
        run_threat_intel(db, rec, consent=True, cfg=make_cfg())
    case = api.post(f"/api/v1/investigations/from-analysis/{rec.id}").json()
    r = api.get(f"/api/v1/investigations/{case['id']}/report/{rec.id}", params={"intel_run_id": first["run_id"]})
    assert r.status_code == 200
    assert "NOT GIVEN" in _pdf_text(r.content)
    ev = db.query(AuditEvent).filter_by(event_type="report_generated").one()
    assert ev.detail["intel_run_id"] == first["run_id"]
    bad = api.get(f"/api/v1/investigations/{case['id']}/report/{rec.id}", params={"intel_run_id": "x"})
    assert bad.status_code == 404


# ── optional live tests (skipped by default; never run in this task) ─────
@pytest.mark.live
@pytest.mark.parametrize("provider", ["virustotal", "abuseipdb", "shodan", "ipinfo", "tor_exit_list"])
def test_live_provider_smoke(provider):
    """Requires AIPISH_RUN_LIVE=1 and real (rotated) keys. Looks up 8.8.8.8 only."""
    from app.intel.providers import PROVIDER_CLASSES
    cfg = IntelConfig(offline=False)
    if not cfg.configured(provider):
        pytest.skip(f"{provider} not configured")
    r = PROVIDER_CLASSES[provider](cfg).lookup("8.8.8.8", consent=True)
    assert r.status in B.STATUSES
    assert r.status not in (B.MALFORMED_RESPONSE, B.AUTH_FAILED), r.status
