"""P5g: infrastructure geolocation views, analytics aggregates, health hardening and demo geo seeding."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.config import get_settings
from app.core.migrations import upgrade
from app.core.models import (
    Analysis, AssessmentVersion, AttackMapping, Campaign, CampaignMember, GeoObservation, ThreatIntelRun,
)
from app.geo import analytics
from app.geo.service import DISCLAIMER, RELAY_ORDER_LABEL, analysis_geo, campaign_geo

ORIGIN, TOR, NOLOC, PRIVATE, URLIP = "93.184.216.34", "185.220.101.1", "151.101.1.69", "10.0.0.5", "104.16.1.1"


@pytest.fixture
def db(tmp_path):
    eng = create_engine(f"sqlite:///{tmp_path / 'geo.sqlite'}")
    upgrade(eng)
    s = sessionmaker(bind=eng)()
    yield s
    s.close()
    eng.dispose()


_n = 0


def _analysis(db, **kw) -> Analysis:
    global _n
    _n += 1
    a = Analysis(raw_sha256=f"{_n:064x}", raw_size_bytes=100, subject=kw.pop("subject", "s"),
                 from_domain=kw.pop("from_domain", "x.test"),
                 detection_score=kw.pop("score", 0), detection_verdict=kw.pop("verdict", "minimal"), **kw)
    db.add(a)
    db.commit()
    return a


def _forensics() -> dict:
    return {"relay_chain": [
        {"index": 0, "from_ip": ORIGIN, "trusted": False},
        {"index": 1, "from_ip": PRIVATE, "trusted": False},
        {"index": 2, "from_ip": NOLOC, "trusted": False},
        {"index": 3, "from_ip": TOR, "trusted": True},
    ], "earliest_candidate_ip": ORIGIN, "candidate_ips": [ORIGIN, NOLOC]}


def _enrichment() -> dict:
    return {"results": [
        {"provider": "ipgeo_http", "ioc": {"kind": "ip", "value": ORIGIN}, "status": "ok", "evidence": {
            "status": "ok", "network_location": {"country": "United States", "region": "MA", "city": "Norwell",
                                                 "latitude": 42.15, "longitude": -70.82, "isp": "Edgecast",
                                                 "org": "Example Org", "as": "AS15133 Edgecast Inc."}}},
        {"provider": "ipgeo_http", "ioc": {"kind": "ip", "value": PRIVATE}, "status": "ok", "evidence": {
            "network_location": {"latitude": 1.0, "longitude": 1.0}}},
        {"provider": "dns", "ioc": {"kind": "hostname", "value": "cdn.example.test"}, "status": "ok",
         "evidence": {"records": {"A": [URLIP, "192.168.1.1"]}}},
    ]}


def _run(db, analysis_id: str, *, consent=True, simulated=True, version=1) -> ThreatIntelRun:
    ipinfo = {"provider": "ipinfo", "status": "malicious_or_flagged", "fetched_at": "2026-11-01T00:00:00+00:00",
              "cache_state": "stale", "data": {"approx_coordinates": "52.37,4.89", "country": "NL", "city": "Amsterdam",
                                               "region": "North Holland", "org": "AS64501 Example", "asn": "AS64501",
                                               "privacy_flags_returned": True, "is_vpn": False, "is_proxy": False,
                                               "is_tor": True, "is_relay": "unavailable", "is_hosting": True}}
    tor = {"provider": "tor", "status": "malicious_or_flagged", "data": {}}
    r = ThreatIntelRun(analysis_id=analysis_id, version=version, consent_granted=consent, consent_source="on_demand",
                       providers_requested=["ipinfo", "tor"], offline=False,
                       result_json={"simulated": simulated, "indicators": [
                           {"indicator": TOR, "indicator_type": "ip", "results": [ipinfo, tor]}]})
    db.add(r)
    db.commit()
    return r


# ── analysis geo shaping ────────────────────────────────────────────────────
def test_points_unlocated_private_and_flags(db):
    a = _analysis(db, forensics_json=_forensics(), enrichment_json=_enrichment(),
                  urls=[{"url": "https://cdn.example.test/x", "host": "cdn.example.test"}])
    _run(db, a.id)
    g = analysis_geo(db, a)
    assert g["disclaimer"] == DISCLAIMER
    assert g["relay_order_label"] == RELAY_ORDER_LABEL
    assert PRIVATE not in json.dumps(g) and "192.168.1.1" not in json.dumps(g)       # never private IPs
    pts = {p["ip"]: p for p in g["points"]}
    assert set(pts) == {ORIGIN, TOR}
    o = pts[ORIGIN]
    assert (o["role"], o["hop"], o["lat"], o["country"], o["asn"]) == ("origin_candidate", 0, 42.15, "United States", "AS15133")
    assert o["source"].startswith("ip-api.com") and o["stale"] is False and o["simulated"] is False
    t = pts[TOR]
    assert (t["role"], t["hop"], t["lat"], t["lon"]) == ("trusted_relay", 3, 52.37, 4.89)
    assert t["stale"] is True and t["simulated"] is True and t["source"].startswith("IPinfo")
    un = {u["ip"]: u for u in g["unlocated"]}
    assert set(un) == {NOLOC, URLIP} and un[NOLOC]["reason"] == "no location data"
    assert un[URLIP]["role"] == "url_host_ip" and un[URLIP]["via_host"] == "cdn.example.test"
    assert g["relay_order"] == [ORIGIN, TOR]
    assert g["provenance"]["lookups_performed"] is False and g["provenance"]["intel_run"]["simulated"] is True
    assert g["provenance"]["stale_present"] is True and g["provenance"]["simulated_present"] is True


def test_anonymity_only_when_backed_by_stored_data(db):
    a = _analysis(db, forensics_json=_forensics(), enrichment_json=_enrichment())
    _run(db, a.id)
    sig = {x["ip"]: x for x in analysis_geo(db, a)["anonymity"]}
    tor = sig[TOR]["signals"]
    assert tor["tor"]["value"] is True and tor["vpn"]["value"] is False and tor["hosting"]["value"] is True
    assert tor["relay"]["value"] is None                         # provider said "unavailable": not available
    for s in sig[ORIGIN]["signals"].values():                    # no provider data → not available, never False
        assert s == {"value": None, "source": None}
    assert sig[ORIGIN]["any_data"] is False


def test_candidate_ips_do_not_contradict_the_hop_classification(db):
    a = _analysis(db, forensics_json={"earliest_candidate_ip": TOR, "candidate_ips": [TOR],
                                      "relay_chain": [{"index": 0, "from_ip": TOR, "trusted": True}]})
    g = analysis_geo(db, a)
    assert g["unlocated"][0]["roles"] == ["origin_candidate", "trusted_relay"]


def test_declined_runs_are_ignored(db):
    a = _analysis(db, forensics_json=_forensics(), enrichment_json={})
    _run(db, a.id, consent=False)
    g = analysis_geo(db, a)
    assert g["points"] == [] and {u["ip"] for u in g["unlocated"]} == {ORIGIN, NOLOC, TOR}
    assert g["provenance"]["intel_run"] is None


def test_simulated_observation_fallback_and_labels(db):
    a = _analysis(db, forensics_json={"relay_chain": [{"index": 0, "from_ip": NOLOC, "trusted": True}]})
    db.add(GeoObservation(analysis_id=a.id, ip=NOLOC, latitude=1.29, longitude=103.85, country="SG",
                          asn="AS64503", org="SIMULATED", anonymity_json={"hosting": True}, source="simulated-demo",
                          simulated=True))
    db.commit()
    g = analysis_geo(db, a)
    p = g["points"][0]
    assert p["simulated"] is True and "SIMULATED" in p["source"]
    s = g["anonymity"][0]
    assert s["simulated"] is True and s["signals"]["hosting"]["value"] is True and s["signals"]["tor"]["value"] is None


def test_invalid_coordinates_go_to_the_table(db):
    enr = {"results": [{"provider": "ipgeo_http", "ioc": {"value": ORIGIN}, "status": "ok",
                        "evidence": {"network_location": {"latitude": 123.0, "longitude": 5.0, "country": "X"}}}]}
    a = _analysis(db, forensics_json={"earliest_candidate_ip": ORIGIN}, enrichment_json=enr)
    g = analysis_geo(db, a)
    assert g["points"] == [] and g["unlocated"][0]["country"] == "X"


def test_campaign_geo_dedupes_ips_with_member_counts(db):
    c = Campaign(number=1, label="C-0001", confidence="medium", confidence_score=0.8, fingerprint="f")
    db.add(c)
    db.commit()
    for _ in range(3):
        a = _analysis(db, forensics_json={"earliest_candidate_ip": ORIGIN,
                                          "relay_chain": [{"index": 0, "from_ip": ORIGIN, "trusted": True}]},
                      enrichment_json=_enrichment())
        db.add(CampaignMember(campaign_id=c.id, analysis_id=a.id))
    b = _analysis(db, forensics_json={"earliest_candidate_ip": NOLOC})
    db.add(CampaignMember(campaign_id=c.id, analysis_id=b.id))
    db.commit()
    g = campaign_geo(db, c)
    assert [(p["ip"], p["member_count"]) for p in g["points"]] == [(ORIGIN, 3)]
    assert [(u["ip"], u["member_count"]) for u in g["unlocated"]] == [(NOLOC, 1)]
    assert g["counts"]["members"] == 4 and g["disclaimer"] == DISCLAIMER


# ── analytics ───────────────────────────────────────────────────────────────
def test_analytics_known_fixture(db):
    now = datetime.now(timezone.utc)
    a1 = _analysis(db, score=100, verdict="phishing_fraud_likely", from_domain="evil.test", created_at=now,
                   forensics_json={"earliest_candidate_ip": ORIGIN}, enrichment_json=_enrichment())
    a2 = _analysis(db, score=45, verdict="suspicious", from_domain="gmail.com", created_at=now - timedelta(days=1))
    _analysis(db, score=5, verdict="minimal", from_domain="evil.test", created_at=now - timedelta(days=40))
    db.add(AssessmentVersion(id="v1", analysis_id=a1.id, version=1, source="upload",
                             ml_json={"status": "ok", "label": "phishing"}))
    db.add(AssessmentVersion(id="v2", analysis_id=a1.id, version=2, source="upload",
                             ml_json={"status": "ok", "label": "impersonated"}))
    for aid, v, tids in ((a1.id, 1, ["T1566"]), (a1.id, 2, ["T1566.002", "T1534"]), (a2.id, 1, ["T1534"])):
        db.add(AttackMapping(analysis_id=aid, version=v, source="auto", mapping_engine_version="1", catalog_version="c",
                             fingerprint=f"{aid}{v}", results_json={"mappings": [
                                 {"technique_id": t, "name": f"name {t}"} for t in tids]}))
    c = Campaign(number=7, label="C-0007", confidence="low", confidence_score=0.6, fingerprint="g")
    db.add(c)
    db.commit()
    db.add_all([CampaignMember(campaign_id=c.id, analysis_id=a1.id), CampaignMember(campaign_id=c.id, analysis_id=a2.id)])
    db.add(ThreatIntelRun(analysis_id=a2.id, version=1, consent_granted=True, consent_source="upload",
                          offline=True, result_json={"simulated": True}))
    db.commit()

    s = analytics.summary(db, days=7)
    assert s["window"]["total_analyses"] == 3 and s["window"]["days"] == 7
    assert {v["verdict"]: v["count"] for v in s["verdicts"]} == {"phishing_fraud_likely": 1, "suspicious": 1, "minimal": 1}
    assert {m["label"]: m["count"] for m in s["ml_classes"]} == {"impersonated": 1, "not_assessed": 2}   # latest version wins
    assert len(s["per_day"]) == 7 and sum(d["count"] for d in s["per_day"]) == 2                       # 40-day-old excluded
    assert s["per_day"][-1]["count"] == 1
    hist = {h["bucket"]: h["count"] for h in s["score_histogram"]}
    assert hist["90-100"] == 1 and hist["40-49"] == 1 and hist["0-9"] == 1 and len(hist) == 10
    doms = {d["domain"]: d for d in s["top_sender_domains"]}
    assert doms["evil.test"]["count"] == 2 and doms["evil.test"]["generic"] is False and doms["gmail.com"]["generic"] is True
    assert s["geo"]["coverage"] == {"with_geo": 1, "analyses_considered": 3}
    assert s["geo"]["countries"] == [{"country": "United States", "count": 1}] and s["geo"]["asns"][0]["asn"] == "AS15133"
    tech = {t["technique_id"]: t["count"] for t in s["attack_techniques"]}
    assert tech == {"T1566.002": 1, "T1534": 2}                                                        # latest only
    assert s["campaigns"]["candidates"] == 1
    assert {b["bucket"]: b["count"] for b in s["campaigns"]["candidate_size_distribution"]}["2"] == 1
    assert s["intel_coverage"] == {"analyses_with_consented_lookups": 1, "analyses_considered": 3,
                                   "runs_total": 1, "simulated_runs": 1}


def test_analytics_is_bounded_and_has_no_message_content(db, monkeypatch):
    for i in range(15):
        _analysis(db, from_domain=f"d{i}.test", subject=None)
    monkeypatch.setattr(analytics, "MAX_WINDOW", 5)
    s = analytics.summary(db, days=10_000)
    assert s["window"]["days"] == analytics.MAX_DAYS and len(s["per_day"]) == analytics.MAX_DAYS
    assert s["window"]["analyses_considered"] == 5 and s["window"]["capped"] is True
    assert len(s["top_sender_domains"]) == analytics.TOP_N
    text = json.dumps(s)
    assert "subject" not in text and "body" not in text and "@" not in text


# ── API (active dialect: SQLite by default, PostgreSQL with TEST_DATABASE_URL) ──
def test_geo_and_analytics_endpoints_require_auth(anon_client):
    for path in ("/api/v1/analyses/x/geo", "/api/v1/campaigns/x/geo", "/api/v1/analytics/summary", "/api/v1/system/info"):
        assert anon_client.get(path).status_code == 401, path


def test_endpoints_for_viewer_and_404(client):
    from tests.authutil import authed_client
    from app.main import create_app
    viewer = authed_client(create_app(), "viewer")
    with open("tests/fixtures/demo/campaign/campaign_member_1.eml", "rb") as f:
        aid = client.post("/api/v1/analyses", files={"file": ("m.eml", f.read())}).json()["id"]
    g = viewer.get(f"/api/v1/analyses/{aid}/geo")
    assert g.status_code == 200 and g.json()["disclaimer"] == DISCLAIMER
    assert g.json()["provenance"]["lookups_performed"] is False
    assert viewer.get("/api/v1/analyses/nope/geo").status_code == 404
    assert viewer.get("/api/v1/campaigns/nope/geo").status_code == 404
    r = viewer.get("/api/v1/analytics/summary", params={"days": 14})
    assert r.status_code == 200 and len(r.json()["per_day"]) == 14
    assert viewer.get("/api/v1/analytics/summary", params={"days": 0}).status_code == 400   # uniform validation envelope
    assert viewer.get("/api/v1/analytics/summary", params={"days": 9999}).status_code == 400


def test_demo_seed_writes_simulated_geo_only_for_fixtures(monkeypatch, capsys):
    from app import cli
    from app.core.db import SessionLocal
    monkeypatch.setattr(get_settings(), "env", "dev")
    assert cli.main(["seed-demo-campaign"]) == 0
    assert "SIMULATED geo observations added" in capsys.readouterr().out
    with SessionLocal() as s:
        rows = s.query(GeoObservation).all()
        assert rows and all(r.simulated and r.source == "simulated-demo" for r in rows)
        assert all(r.asn is None or 64496 <= int(r.asn[2:]) <= 64511 for r in rows)   # RFC 5398 documentation ASNs
        # the campaign that contains the seeded fixture (labels depend on which tests ran first)
        import hashlib
        sha = hashlib.sha256(open("tests/fixtures/demo/campaign/campaign_member_1.eml", "rb").read()).hexdigest()
        member = s.query(Analysis).filter_by(raw_sha256=sha).first()
        link = s.query(CampaignMember).filter_by(analysis_id=member.id).first() if member else None
        camp = s.get(Campaign, link.campaign_id) if link else None
        assert camp is not None
        if camp is not None:
            g = campaign_geo(s, camp)
            assert g["points"] and g["provenance"]["simulated_present"] is True
    assert cli.main(["seed-demo-campaign"]) == 0                       # idempotent
    assert "SIMULATED geo observations added: 0" in capsys.readouterr().out
