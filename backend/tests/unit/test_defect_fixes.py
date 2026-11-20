"""Regression tests for the audit defects fixed on 2026-11-18 (all offline)."""
from __future__ import annotations

import hashlib
import sys
import types
from pathlib import Path

import httpx
import respx
from fastapi.testclient import TestClient

import app.auth as A
import app.cases.service as svc
import app.enrichment.engine as E
from app.core.db import SessionLocal
from app.core.models import Analysis
from app.enrichment.config import EnrichmentConfig
from app.enrichment.iocs import Ioc
from app.ingestion.parser import parse_eml
from app.main import create_app
from tests.authutil import authed_client  # noqa: E402

FIX = Path(__file__).resolve().parents[1] / "fixtures" / "eml"


# ── SPF: pyspf.check2 returns (result, explanation) ──────────────────────

def _fake_spf(monkeypatch, result):
    mod = types.ModuleType("spf")
    mod.check2 = lambda **kw: result
    monkeypatch.setitem(sys.modules, "spf", mod)


def test_spf_live_pass_is_not_swallowed(monkeypatch):
    _fake_spf(monkeypatch, ("pass", "sender SPF authorized"))
    assert A.check_spf_live("a@example.com", "192.0.2.1", "example.com") == ("pass", "live check")


def test_spf_live_fail_and_softfail(monkeypatch):
    _fake_spf(monkeypatch, ("fail", "not authorized"))
    assert A.check_spf_live("a@example.com", "192.0.2.1", "example.com")[0] == "fail"
    _fake_spf(monkeypatch, ("softfail", "x"))
    assert A.check_spf_live("a@example.com", "192.0.2.1", "example.com")[0] == "softfail"


def test_spf_verified_pass_reports_envelope_domain(monkeypatch):
    parsed = parse_eml((FIX / "multihop_auth.eml").read_bytes())
    seen = {}

    def fake(sender, ip, helo, resolver=None):
        seen["sender"] = sender
        return "pass", "live check"

    monkeypatch.setattr(A, "check_spf_live", fake)
    monkeypatch.setattr(A, "check_dkim_live", lambda raw, timeout=0: (None, "skipped in test"))
    monkeypatch.setattr(A, "dmarc_record_lookup", lambda *a, **k: (None, "NXDOMAIN"))
    res = A.run_auth_analysis(parsed, b"", relay_origin_ip="192.0.2.10", live=True).to_dict()
    assert res["spf"]["status"] == "verified_pass"
    assert res["spf"]["detail"]["checked_domain"] == seen["sender"].rsplit("@", 1)[-1].lower()


# ── Enrichment switches + coordinates ────────────────────────────────────

def test_provider_switches_are_honoured():
    ip = Ioc(kind="ip", value="8.8.8.8", origin="test")
    dom = Ioc(kind="domain", value="example.com", origin="test")
    off = EnrichmentConfig(enable_dns=False, enable_rdap=False, enable_ipgeo=False)
    assert [n for n, _ in E._providers_for(dom, off)] == []
    assert "ipgeo_http" not in [n for n, _ in E._providers_for(ip, off)]
    assert "dns" not in [n for n, _ in E._providers_for(ip, off)]
    on = EnrichmentConfig(enable_dns=True, enable_rdap=True, enable_ipgeo=True)
    assert [n for n, _ in E._providers_for(dom, on)] == ["dns", "rdap"]
    assert "ipgeo_http" in [n for n, _ in E._providers_for(ip, on)]


@respx.mock
def test_ipgeo_requests_and_returns_coordinates():
    cfg = EnrichmentConfig()
    assert "lat" in cfg.ipgeo_base_url and "lon" in cfg.ipgeo_base_url
    respx.get(url__startswith="http://ip-api.com/json/8.8.8.8").mock(return_value=httpx.Response(200, json={
        "status": "success", "country": "United States", "regionName": "Virginia", "city": "Ashburn",
        "lat": 39.03, "lon": -77.5, "isp": "Google LLC", "org": "Google", "as": "AS15169", "query": "8.8.8.8"}))
    out = E.ipgeo_lookup("8.8.8.8", cfg)
    assert out["network_location"]["latitude"] == 39.03
    assert out["network_location"]["longitude"] == -77.5


# ── PDF: From header is escaped; raw evidence retained when policy=raw ───

INJECT = (b"From: \"<b>Evil</b> <font size=99>X</font> & Co\" <ceo@example.com>\r\n"
          b"To: a@example.org\r\nSubject: hi\r\nMessage-ID: <x@example.com>\r\n\r\nbody\r\n")


def test_pdf_escapes_from_display_name():
    c = authed_client()
    up = c.post("/api/v1/analyses", files={"file": ("x.eml", INJECT, "message/rfc822")}).json()
    case = c.post(f"/api/v1/investigations/from-analysis/{up['id']}").json()
    r = c.get(f"/api/v1/investigations/{case['id']}/report/{up['id']}")
    assert r.status_code == 200, r.text[:300]
    assert r.content.startswith(b"%PDF-")


def test_raw_policy_retains_evidence_and_integrity_matches(monkeypatch):
    monkeypatch.setattr(svc, "CASE_EVIDENCE_STORE", "raw")
    monkeypatch.setattr(svc, "CASE_EVIDENCE_STORE_KEY", "")
    raw = (FIX / "benign.eml").read_bytes()
    c = authed_client()
    up = c.post("/api/v1/analyses", files={"file": ("b.eml", raw, "message/rfc822")}).json()
    with SessionLocal() as db:
        rec = db.get(Analysis, up["id"])
        assert rec.evidence_blob == raw
        assert hashlib.sha256(rec.evidence_blob).hexdigest() == rec.raw_sha256
    case = c.post(f"/api/v1/investigations/from-analysis/{up['id']}").json()
    res = c.post(f"/api/v1/investigations/{case['id']}/evidence-integrity/{up['id']}").json()
    assert res["result"] == "match"


def test_hash_only_policy_stores_no_bytes(monkeypatch):
    monkeypatch.setattr(svc, "CASE_EVIDENCE_STORE", "hash_only")
    c = authed_client()
    up = c.post("/api/v1/analyses", files={"file": ("b.eml", (FIX / "benign.eml").read_bytes(),
                                                     "message/rfc822")}).json()
    with SessionLocal() as db:
        assert db.get(Analysis, up["id"]).evidence_blob is None
