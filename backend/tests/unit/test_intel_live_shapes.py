"""P5a-live regression tests built from REAL provider response shapes (sanitised; no keys or account data).

Fixtures: tests/fixtures/intel/live_shapes/ (captured 2026-11-22 for the approved indicators only).
Offline: respx mocks every request; the network-block fixture stays active."""
from __future__ import annotations

import json
import os
from pathlib import Path

import httpx
import pytest
import respx

from app.intel import base as B
from app.intel.config import IntelConfig
from app.intel.providers import PROVIDER_CLASSES

FX = Path(__file__).resolve().parents[1] / "fixtures" / "intel" / "live_shapes"
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"


def _fx(name: str) -> dict:
    return json.loads((FX / name).read_text())


def _cfg(**kw) -> IntelConfig:
    base = dict(offline=False, virustotal_api_key="test-key-not-real", abuseipdb_api_key="test-key-not-real",
                shodan_api_key="test-key-not-real", ipinfo_token="test-key-not-real")
    base.update(kw)
    return IntelConfig(**base)


@pytest.fixture(autouse=True)
def _fresh_limiters():
    B._limiters.clear()
    yield
    B._limiters.clear()


def _lookup(provider: str, indicator: str, itype: str, payload: dict, cfg: IntelConfig | None = None):
    cfg = cfg or _cfg()
    with respx.mock(assert_all_called=True) as m:
        m.get(url__regex=r"https://.*").mock(return_value=httpx.Response(200, json=payload))
        return PROVIDER_CLASSES[provider](cfg).lookup(indicator, itype, consent=True)


# ── VirusTotal ─────────────────────────────────────────────────────────────
def test_vt_single_engine_detection_on_benign_ip_is_not_flagged():
    """Live 8.8.8.8: 1 malicious of 92 engines, reputation +567. Previously reported as FLAGGED."""
    r = _lookup("virustotal", "8.8.8.8", "ip", _fx("virustotal_ip_8.8.8.8.json"))
    assert r.status == B.RECORD_FOUND
    assert r.data["malicious"] == 1 and r.data["flag_threshold"] == 3 and r.data["reputation"] > 0
    assert "below the flag threshold of 3" in r.message and "not proof of safety" in r.message
    assert r.data["as_owner"] and r.data["asn"] == 15169


def test_vt_threshold_is_configurable():
    r = _lookup("virustotal", "8.8.8.8", "ip", _fx("virustotal_ip_8.8.8.8.json"), _cfg(vt_flag_min_engines=1))
    assert r.status == B.MALICIOUS_OR_FLAGGED


def test_vt_eicar_hash_real_shape_is_flagged_and_counts_verdict_engines():
    """Hash lookup only: the EICAR file/string is never stored. Extra stats keys (type-unsupported, failure,
    confirmed-timeout) exist in the real shape and are not counted as verdicts."""
    payload = _fx("virustotal_file_eicar_hash.json")
    assert "type-unsupported" in payload["data"]["attributes"]["last_analysis_stats"]
    r = _lookup("virustotal", EICAR_SHA256, "hash", payload)
    assert r.status == B.MALICIOUS_OR_FLAGGED
    assert r.data["malicious"] == 65 and r.data["engines_total"] == 67 and r.data["size_bytes"] == 68


def test_vt_domain_real_shape_parses():
    r = PROVIDER_CLASSES["virustotal"](_cfg())
    with respx.mock(assert_all_called=True) as m:
        m.get(url__regex=r"https://.*").mock(return_value=httpx.Response(200, json=_fx("virustotal_domain_example.com.json")))
        res = r._fetch("example.com", "domain")          # the service path refuses documentation domains
    assert res.status == B.REPORTED_CLEAN_NO_FLAGS and res.data["registrar"]


def test_documentation_domain_is_refused_before_any_network_call():
    with respx.mock(assert_all_called=False) as m:
        route = m.get(url__regex=r"https://.*").mock(return_value=httpx.Response(200, json={}))
        r = PROVIDER_CLASSES["virustotal"](_cfg()).lookup("example.com", "domain", consent=True)
    assert r.status == B.NOT_APPLICABLE_INDICATOR and not route.called


# ── AbuseIPDB, Shodan, IPinfo ──────────────────────────────────────────────
def test_abuseipdb_real_shape_reports_below_threshold():
    r = _lookup("abuseipdb", "8.8.8.8", "ip", _fx("abuseipdb_check_8.8.8.8.json"))
    assert r.status == B.RECORD_FOUND and r.data["total_reports"] > 0 and r.data["abuse_confidence_score"] == 0
    assert "not proof of safety" in r.message


def test_shodan_real_shape_record_found():
    r = _lookup("shodan", "8.8.8.8", "ip", _fx("shodan_host_8.8.8.8.json"))
    assert r.status == B.RECORD_FOUND and r.data["open_ports"] and r.data["org"]


def test_ipinfo_anycast_real_shape():
    """Live 8.8.8.8 is anycast; the free plan returns no privacy block (flags stay 'unavailable', not false)."""
    r = _lookup("ipinfo", "8.8.8.8", "ip", _fx("ipinfo_8.8.8.8.json"))
    assert r.status == B.RECORD_FOUND
    assert r.data["anycast"] is True and "ANYCAST" in r.data["caveat"] and "Anycast address" in r.message
    assert r.data["is_vpn"] == "unavailable" and r.data["privacy_flags_returned"] is False
    assert r.data["approx_coordinates"] and r.data["asn"] == "AS15169"


# ── request audit hook (off by default; never logs secrets) ───────────────
def test_request_audit_hook_is_off_by_default_and_redacts(tmp_path, monkeypatch):
    assert B._request_audit_hook("shodan") is None
    log = tmp_path / "req.jsonl"
    monkeypatch.setenv("INTEL_REQUEST_LOG", str(log))
    secret = "s3cr3t-" + os.urandom(6).hex()
    cfg = _cfg(shodan_api_key=secret, abuseipdb_api_key=secret)
    with respx.mock(assert_all_called=False) as m:
        m.get(url__regex=r"https://api\.shodan\.io/.*").mock(return_value=httpx.Response(200, json=_fx("shodan_host_8.8.8.8.json")))
        m.get(url__regex=r"https://api\.abuseipdb\.com/.*").mock(return_value=httpx.Response(200, json=_fx("abuseipdb_check_8.8.8.8.json")))
        PROVIDER_CLASSES["shodan"](cfg).lookup("8.8.8.8", "ip", consent=True)
        PROVIDER_CLASSES["abuseipdb"](cfg).lookup("8.8.8.8", "ip", consent=True)
    text = log.read_text()
    assert secret not in text and "key=" not in text
    lines = [json.loads(x) for x in text.splitlines()]
    assert lines[0]["path"] == "/shodan/host/8.8.8.8" and "key" in lines[0]["query_param_names"]
    assert "key" not in lines[0]["query_values"]
    assert lines[1]["query_values"]["ipAddress"] == "8.8.8.8" and "key" in lines[1]["header_names"]
    assert all(x["body_bytes"] == 0 and x["method"] == "GET" for x in lines)


# ── downstream consumers of the real IPinfo shape ──────────────────────────
def test_attack_source_type_ignores_unavailable_ipinfo_privacy_flags():
    """Live defect: the free IPinfo plan returns no privacy block, so is_vpn/is_proxy/is_tor are the string
    'unavailable'. The ATT&CK source-type engine read them as truthy and marked 8.8.8.8 'anonymised infrastructure:
    likely' ('IPinfo privacy flags: vpn, proxy, tor'). Only an explicit True may count."""
    from app.attack.engine import Inputs, compute
    r = _lookup("ipinfo", "8.8.8.8", "ip", _fx("ipinfo_8.8.8.8.json")).to_dict()
    assert r["data"]["is_tor"] == "unavailable"
    analysis = {"id": "a1", "detection_json": {"findings": []}, "auth_json": {}, "forensics_json": {"inconsistencies": []},
                "urls": [], "attachments": []}
    intel_run = {"run_id": "run1", "version": 1, "consent": {"granted": True}, "offline": False, "simulated": False,
                 "indicators": [{"indicator": "8.8.8.8", "indicator_type": "ip", "origins": ["verified originating IP"],
                                 "results": [r]}]}
    out = compute(Inputs(analysis, intel_run=intel_run))
    st = {h["hypothesis"]: h for h in out["source_type"]}
    assert st["anonymised_infrastructure"]["band"] == "not_indicated"
    assert not any("privacy flag" in (e.get("statement") or "") for e in out["evidence"])
    # an explicit True from a paid plan still counts
    r["data"]["is_tor"] = True
    st = {h["hypothesis"]: h for h in compute(Inputs(analysis, intel_run=intel_run))["source_type"]}
    assert st["anonymised_infrastructure"]["band"] == "likely"


def test_geo_point_carries_anycast_from_real_ipinfo_shape():
    from app.geo.service import _from_ipinfo
    r = _lookup("ipinfo", "8.8.8.8", "ip", _fx("ipinfo_8.8.8.8.json")).to_dict()
    p = _from_ipinfo(r, False)
    assert p["anycast"] is True and p["lat"] is not None and p["simulated"] is False
    r["data"].pop("anycast")
    assert _from_ipinfo(r, False)["anycast"] is False
