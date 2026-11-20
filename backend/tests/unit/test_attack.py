"""P5d: ATT&CK catalog, deterministic mapping rules, source-type hypotheses, API, PDF 7C."""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import app.attack.service as attack_service
from app.attack.catalog import get_catalog
from app.attack.engine import DISCLAIMER, EMPTY_TEXT, ENGINE_VERSION, Inputs, compute
from app.core.db import Base, get_db
from app.core.models import Analysis, AttackMapping, AuditEvent, ThreatIntelRun, utcnow
from app.main import create_app
from tests.authutil import auth_headers, make_user

FIX = Path(__file__).resolve().parents[1] / "fixtures"
SNAP = json.loads((FIX / "attack" / "verified_fields_enterprise_20.1.json").read_text())
ENGINE_SRC = (Path(__file__).resolve().parents[2] / "app" / "attack" / "engine.py").read_text()


# ── fixtures ─────────────────────────────────────────────────────────────
@pytest.fixture
def app_db():
    eng = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(eng)
    db = sessionmaker(bind=eng)()
    app = create_app()
    app.dependency_overrides[get_db] = lambda: db
    yield app, db
    db.close()


def _client(app, db, role="analyst"):
    u, _ = make_user(db, role)
    c = TestClient(app)
    c.headers.update(auth_headers(u))
    return c, u


def _upload(c, path: Path) -> dict:
    r = c.post("/api/v1/analyses", files={"file": (path.name, path.read_bytes(), "message/rfc822")})
    assert r.status_code == 201, r.text
    return r.json()


def _ids(result) -> set[str]:
    return {m["technique_id"] for m in result["mappings"]}


def F(rule_id, knowledge="heuristic", severity="medium"):
    return {"rule_id": rule_id, "knowledge": knowledge, "severity": severity, "title": rule_id, "evidence": "x"}


def A(findings=(), auth=None, inc=(), urls=(), atts=(), **kw):
    return {"id": "a1", "detection_json": {"findings": list(findings)}, "auth_json": auth or {},
            "forensics_json": {"inconsistencies": [{"rule_id": r, "severity": "medium", "evidence": "e"} for r in inc]},
            "urls": list(urls), "attachments": list(atts), **kw}


def run(consent=True, offline=False, results=(), origins=("verified originating IP",), simulated=False):
    return {"run_id": "run1", "version": 1, "consent": {"granted": consent}, "offline": offline, "simulated": simulated,
            "indicators": [{"indicator": "185.220.101.1", "indicator_type": "ip", "origins": list(origins),
                            "results": list(results)}]}


def R(provider, status, **data):
    return {"provider": provider, "provider_label": provider, "status": status, "data": data, "cache_state": "none"}


URL = {"host": "login.example-verify.test", "scheme": "https", "url": "https://login.example-verify.test/x"}
ATT = {"filename": "inv.docm", "content_type": "application/vnd.ms-word", "sha256": "a" * 64}


# ── catalog ──────────────────────────────────────────────────────────────
def test_catalog_matches_verified_official_snapshot():
    cat = get_catalog()
    assert cat.attack_version == SNAP["attack_version"] == "20.1" and cat.verified is True
    assert cat.meta["retrieved"] and cat.meta["bundle_sha256"] == SNAP["bundle_sha256"]
    for t in cat.techniques:
        off = SNAP["techniques"].get(t["technique_id"])
        assert off is not None, f"{t['technique_id']} unknown to the official snapshot"
        expected = f"{off['parent_name']}: {off['name']}" if off.get("parent_name") else off["name"]
        assert t["name"] == expected and t["tactics"] == off["tactics"] and t["url"] == off["url"]
        assert not off["revoked"] and not off["deprecated"] and t["description"]
    assert cat.ids == set(SNAP["techniques"])


def test_engine_only_uses_catalog_ids_and_no_revoked_ids():
    used = set(re.findall(r'"(T\d{4}(?:\.\d{3})?)"', ENGINE_SRC))
    assert used and used <= get_catalog().ids
    assert not {"T1656", "T1672"} & used                       # revoked in ATT&CK 20.x


# ── mapping rules: positive / negative ───────────────────────────────────
def test_no_evidence_no_mapping_and_empty_state():
    out = compute(Inputs(A()))
    assert out["mappings"] == [] and out["empty_state"] == EMPTY_TEXT and out["evidence"] == []
    assert out["disclaimer"] == DISCLAIMER and "approximates business-email-compromise" in out["note"]


def test_ml_only_never_creates_a_mapping():
    out = compute(Inputs(A(), ml={"status": "ok", "label": "phishing", "confidence": 0.99, "assessment_id": "as1"}))
    assert out["mappings"] == []


def test_m01_attachment_delivery_observed():
    assert _ids(compute(Inputs(A([F("risky_attachment_type", "fact", "high")], atts=[ATT])))) == {"T1566.001"}
    assert compute(Inputs(A([F("risky_attachment_type", "fact")], atts=[ATT])))["mappings"][0]["basis"] == "observed"
    assert _ids(compute(Inputs(A(atts=[ATT])))) == set()                 # plain attachment: nothing


def test_m02_link_delivery_requires_link_and_indicator():
    assert _ids(compute(Inputs(A([F("url_obfuscation")], urls=[URL])))) == {"T1566.002"}
    assert _ids(compute(Inputs(A(urls=[URL])))) == set()                 # a link alone is not phishing
    assert _ids(compute(Inputs(A([F("url_obfuscation")])))) == set()     # rule without any URL record
    m = compute(Inputs(A([F("credential_request")], urls=[URL])))
    link = next(x for x in m["mappings"] if x["technique_id"] == "T1566.002")
    assert link["basis"] == "observed" and link["confidence"] == "low"


def test_m03_m04_phishing_for_information():
    assert "T1598.003" in _ids(compute(Inputs(A([F("credential_request")], urls=[URL]))))
    out = compute(Inputs(A([F("credential_request")])))
    assert _ids(out) == {"T1598"} and out["mappings"][0]["basis"] == "inferred"
    assert _ids(compute(Inputs(A([F("urgency_language")])))) == set()


def test_m05_impersonation_needs_content_and_identity_signal():
    both = compute(Inputs(A([F("payment_diversion"), F("sender_reply_to_mismatch", "fact")])))
    imp = next(m for m in both["mappings"] if m["technique_id"] == "T1684.001")
    assert imp["basis"] == "inferred" and imp["confidence"] == "medium"
    assert "T1684.001" not in _ids(compute(Inputs(A([F("payment_diversion")]))))
    assert "T1684.001" not in _ids(compute(Inputs(A([F("sender_reply_to_mismatch", "fact")]))))


def test_m06_spoofing_observed_only_with_verified_failure():
    verified = compute(Inputs(A([F("auth_verified_fail", "fact")], auth={"dmarc": {"status": "verified_fail"}})))
    m = next(x for x in verified["mappings"] if x["technique_id"] == "T1684.002")
    assert m["basis"] == "observed" and m["confidence"] == "high"
    claimed = compute(Inputs(A([F("auth_failure_support", "fact")], inc=["returnpath_mismatch"],
                               auth={"spf": {"status": "parsed", "claims": ["fail"]}})))
    m = next(x for x in claimed["mappings"] if x["technique_id"] == "T1684.002")
    assert m["basis"] == "inferred" and m["confidence"] == "low"
    assert "T1684.002" not in _ids(compute(Inputs(A([F("auth_failure_support", "fact")]))))   # claim alone


def test_m07_financial_theft_intent():
    out = compute(Inputs(A([F("payment_diversion")])))
    assert _ids(out) == {"T1657"} and "intent only" in out["mappings"][0]["limitations"]


def test_m08_m09_user_execution_only_with_provider_flags():
    base = A([F("risky_attachment_type", "fact")], atts=[ATT])
    assert "T1204.002" not in _ids(compute(Inputs(base)))
    flagged = {"run_id": "r", "consent": {"granted": True}, "indicators": [
        {"indicator": "a" * 64, "indicator_type": "hash", "origins": ["attachment SHA-256"],
         "results": [R("virustotal", "malicious_or_flagged", malicious=9)]}]}
    out = compute(Inputs(base, intel_run=flagged))
    assert {"T1566.001", "T1204.002"} <= _ids(out)
    assert next(m for m in out["mappings"] if m["technique_id"] == "T1566.001")["confidence"] == "high"
    link_run = {"run_id": "r", "consent": {"granted": True}, "indicators": [
        {"indicator": URL["host"], "indicator_type": "domain", "origins": ["URL host"],
         "results": [R("virustotal", "malicious_or_flagged", malicious=4)]}]}
    out = compute(Inputs(A(urls=[URL]), intel_run=link_run))
    assert {"T1566.002", "T1204.001"} <= _ids(out)


def test_m10_compromised_account_low_only():
    auth = {"spf": {"status": "verified_pass"}, "dkim": {"status": "verified_pass"},
            "alignment": {"spf": "aligned", "dkim": "aligned"}}
    out = compute(Inputs(A([F("payment_diversion")], auth=auth)))
    m = next(x for x in out["mappings"] if x["technique_id"] == "T1586.002")
    assert m["confidence"] == "low" and m["basis"] == "inferred"
    assert "T1586.002" not in _ids(compute(Inputs(A([F("payment_diversion"), F("lookalike_domain")], auth=auth))))
    assert "T1586.002" not in _ids(compute(Inputs(A(auth=auth))))


def test_m11_reply_mailbox_and_m12_domains():
    assert "T1585.002" in _ids(compute(Inputs(A([F("sender_reply_to_mismatch", "fact"), F("credential_request")]))))
    assert "T1585.002" not in _ids(compute(Inputs(A([F("sender_reply_to_mismatch", "fact")]))))
    low = compute(Inputs(A([F("lookalike_domain")])))
    assert next(m for m in low["mappings"] if m["technique_id"] == "T1583.001")["confidence"] == "low"
    med = compute(Inputs(A([F("domain_no_mx_shortlived")])))
    assert next(m for m in med["mappings"] if m["technique_id"] == "T1583.001")["confidence"] == "medium"


def test_m13_tor_only_for_origin_candidates():
    tor = run(results=[R("tor_exit_list", "malicious_or_flagged", listed=True)])
    assert "T1090.003" in _ids(compute(Inputs(A(), intel_run=tor)))
    url_tor = run(results=[R("tor_exit_list", "malicious_or_flagged", listed=True)], origins=["URL host"])
    assert "T1090.003" not in _ids(compute(Inputs(A(), intel_run=url_tor)))


def test_evidence_ids_resolve_and_are_deterministic():
    inp = Inputs(A([F("payment_diversion"), F("sender_reply_to_mismatch", "fact"), F("credential_request"),
                    F("url_obfuscation")], urls=[URL], inc=["replyto_mismatch"]),
                 ml={"status": "ok", "label": "fraud", "confidence": 0.7, "assessment_id": "as1"})
    a, b = compute(inp), compute(inp)
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)
    ev = {e["id"]: e for e in a["evidence"]}
    for m in a["mappings"]:
        assert m["evidence_ids"] and set(m["evidence_ids"] + m["supporting_evidence_ids"]) <= set(ev)
        assert all(ev[i]["category"] != "model" for i in m["evidence_ids"])    # ML only as support
    assert any(m["supporting_evidence_ids"] for m in a["mappings"])
    assert [e["id"] for e in a["evidence"]] == [f"A{i}" for i in range(1, len(ev) + 1)]


def _resolve(field: str, rec: Analysis, db) -> object:
    m = re.fullmatch(r"detection\.findings\[(\d+)\]", field)
    if m:
        return rec.detection_json["findings"][int(m.group(1))]
    m = re.fullmatch(r"forensics\.inconsistencies\[(\d+)\]", field)
    if m:
        return rec.forensics_json["inconsistencies"][int(m.group(1))]
    m = re.fullmatch(r"(urls|attachments)\[(\d+)\]", field)
    if m:
        return getattr(rec, m.group(1))[int(m.group(2))]
    m = re.fullmatch(r"auth\.(spf|dkim|dmarc)", field)
    if m:
        return rec.auth_json[m.group(1)]
    m = re.fullmatch(r"auth\.alignment\.(spf|dkim)", field)
    if m:
        return rec.auth_json["alignment"][m.group(1)]
    m = re.fullmatch(r"threat_intel\[(\w+)\]\.indicators\[(\d+)\]\.results\[(\d+)\]", field)
    if m:
        row = db.get(ThreatIntelRun, m.group(1))
        return row.result_json["indicators"][int(m.group(2))]["results"][int(m.group(3))]
    raise AssertionError(f"unresolvable source_field {field}")


# ── pipeline fixtures ────────────────────────────────────────────────────
EXPECTED = {
    "demo/legitimate_invoice.eml": set(),
    "eml/benign.eml": set(),
    "demo/attack/synthetic_macro_attachment.eml": {"T1566.001"},
    "demo/attack/synthetic_tor_origin.eml": {"T1566.002", "T1598.003"},
    "eml/multihop_auth.eml": {"T1684.002"},
    "demo/bec_wire_change.eml": {"T1684.001", "T1657", "T1585.002"},
    # From and Return-Path are both paypa1-secure.com: the upstream returnpath_mismatch is an artefact, so
    # no spoofing technique (see test_returnpath_artefact_is_not_used_as_spoofing_evidence)
    "eml/phishing_multipart.eml": {"T1566.002", "T1598.003", "T1684.001", "T1585.002", "T1583.001"},
}


def test_fixture_sets_and_evidence_resolution(app_db):
    app, db = app_db
    c, _ = _client(app, db)
    for rel, expected in EXPECTED.items():
        up = _upload(c, FIX / rel)
        att = c.get(f"/api/v1/analyses/{up['id']}/attack").json()
        assert _ids(att) == expected, rel
        assert att["version"] == 1 and att["source"] == "auto"
        if not expected:
            assert att["empty_state"] == EMPTY_TEXT
        rec = db.get(Analysis, up["id"])
        for e in att["evidence"]:
            assert _resolve(e["source_field"], rec, db) is not None, (rel, e)
    spoof = c.get(f"/api/v1/analyses/{db.query(Analysis).filter(Analysis.subject == 'Invoice attached').first().id}/attack").json()
    assert next(m for m in spoof["mappings"] if m["technique_id"] == "T1684.002")["basis"] == "inferred"


def _intel_run(db, analysis_id, result_json, version=1) -> ThreatIntelRun:
    row = ThreatIntelRun(analysis_id=analysis_id, version=version, consent_granted=result_json["consent"]["granted"],
                         consent_source="on_demand", providers_requested=[], offline=result_json.get("offline", False),
                         result_json=result_json, created_at=utcnow())
    db.add(row)
    db.commit()
    return row


def test_tor_scenario_with_intel_run_and_versioning(app_db):
    app, db = app_db
    c, _ = _client(app, db)
    up = _upload(c, FIX / "demo/attack/synthetic_tor_origin.eml")
    v1 = c.get(f"/api/v1/analyses/{up['id']}/attack").json()
    st = {h["hypothesis"]: h for h in v1["source_type"]}
    assert st["anonymised_infrastructure"]["band"] == "not_assessed"
    assert "not run" in st["anonymised_infrastructure"]["reason"]
    rj = run(simulated=True, results=[R("tor_exit_list", "malicious_or_flagged", listed=True),
                                      R("ipinfo", "record_found", is_tor=True, is_hosting=True)])
    row = _intel_run(db, up["id"], rj)
    rj["run_id"] = row.id
    row.result_json = dict(rj)
    db.commit()
    r = c.post(f"/api/v1/analyses/{up['id']}/attack/recompute").json()
    assert r["new_version"] is True and r["version"] == 2 and r["inputs"]["intel_run_id"] == row.id
    assert r["inputs"]["intel_simulated"] is True
    assert "T1090.003" in _ids(r)
    st = {h["hypothesis"]: h for h in r["source_type"]}
    assert st["anonymised_infrastructure"]["band"] == "likely"
    assert st["direct_malicious_infrastructure"]["band"] == "not_indicated"
    assert "not evidence of safety" in st["direct_malicious_infrastructure"]["rationale"]
    assert any("SIMULATED" in e["statement"] for e in r["evidence"])
    again = c.post(f"/api/v1/analyses/{up['id']}/attack/recompute").json()
    assert again["new_version"] is False and again["version"] == 2           # idempotent
    hist = c.get(f"/api/v1/analyses/{up['id']}/attack/history").json()
    assert [h["version"] for h in hist] == [2, 1] and hist[0]["intel_run_id"] == row.id
    old = c.get(f"/api/v1/analyses/{up['id']}/attack", params={"version": 1}).json()
    assert "T1090.003" not in _ids(old)
    assert c.get(f"/api/v1/analyses/{up['id']}/attack", params={"version": 9}).status_code == 404
    rec = db.get(Analysis, up["id"])
    for e in r["evidence"]:
        assert _resolve(e["source_field"], rec, db) is not None


# ── source-type hypotheses ───────────────────────────────────────────────
def _st(inp: Inputs) -> dict:
    return {h["hypothesis"]: h for h in compute(inp)["source_type"]}


@pytest.mark.parametrize("intel,reason", [
    (None, "not run"),
    (run(consent=False), "declined"),
    (run(offline=True, results=[R("abuseipdb", "not_attempted_offline")]), "offline"),
    (run(results=[R("abuseipdb", "provider_error"), R("tor_exit_list", "timeout")]), "failed"),
])
def test_intel_dependent_hypotheses_not_assessed_never_not_indicated(intel, reason):
    st = _st(Inputs(A(), intel_run=intel))
    for key in ("anonymised_infrastructure", "direct_malicious_infrastructure"):
        assert st[key]["band"] == "not_assessed" and reason in st[key]["reason"]
        assert "not evidence of safety" in st[key]["rationale"]


def test_spoofed_domain_bands():
    assert _st(Inputs(A(auth={"dmarc": {"status": "verified_fail"}})))["spoofed_domain"]["band"] == "likely"
    assert _st(Inputs(A([F("auth_failure_support", "fact")], inc=["returnpath_mismatch"])))["spoofed_domain"]["band"] == "possible"
    passed = {"dmarc": {"status": "verified_pass"}}
    assert _st(Inputs(A(auth=passed)))["spoofed_domain"]["band"] == "not_indicated"
    und = _st(Inputs(A()))["spoofed_domain"]
    assert und["band"] == "undetermined" and und["missing_data"]


def test_compromised_account_bands():
    auth = {"dkim": {"status": "verified_pass"}, "alignment": {"dkim": "aligned"}}
    assert _st(Inputs(A([F("payment_diversion")], auth=auth)))["compromised_account"]["band"] == "possible"
    assert _st(Inputs(A([F("payment_diversion")], auth={"dmarc": {"status": "verified_fail"}})))[
        "compromised_account"]["band"] == "not_indicated"
    assert _st(Inputs(A([F("payment_diversion")])))["compromised_account"]["band"] == "undetermined"
    bands = {_st(Inputs(A([F(r) for r in rules], auth=auth)))["compromised_account"]["band"]
             for rules in ([], ["payment_diversion"], ["credential_request", "sender_reply_to_mismatch"])}
    assert "likely" not in bands                                              # never above possible


def test_anonymised_and_malicious_infrastructure_bands():
    tor = run(results=[R("tor_exit_list", "malicious_or_flagged", listed=True)])
    assert _st(Inputs(A(), intel_run=tor))["anonymised_infrastructure"]["band"] == "likely"
    hosting = run(results=[R("abuseipdb", "record_found", usage_type="Data Center/Web Hosting/Transit")])
    assert _st(Inputs(A(), intel_run=hosting))["anonymised_infrastructure"]["band"] == "possible"
    clean = run(results=[R("abuseipdb", "no_record"), R("virustotal", "reported_clean_no_flags", malicious=0)])
    st = _st(Inputs(A(), intel_run=clean))
    assert st["anonymised_infrastructure"]["band"] == "not_indicated"
    assert st["direct_malicious_infrastructure"]["band"] == "not_indicated"
    one = run(results=[R("abuseipdb", "malicious_or_flagged", abuse_confidence_score=90)])
    assert _st(Inputs(A(), intel_run=one))["direct_malicious_infrastructure"]["band"] == "possible"
    two = run(results=[R("abuseipdb", "malicious_or_flagged"), R("virustotal", "malicious_or_flagged", malicious=5)])
    assert _st(Inputs(A(), intel_run=two))["direct_malicious_infrastructure"]["band"] == "likely"


def test_hypotheses_are_not_mutually_exclusive():
    tor = run(results=[R("tor_exit_list", "malicious_or_flagged", listed=True), R("abuseipdb", "malicious_or_flagged")])
    st = _st(Inputs(A(auth={"dmarc": {"status": "verified_fail"}}), intel_run=tor))
    assert st["spoofed_domain"]["band"] == "likely" and st["anonymised_infrastructure"]["band"] == "likely"
    assert st["direct_malicious_infrastructure"]["band"] == "possible"


def test_wording_never_identifies_people():
    out = compute(Inputs(A([F("payment_diversion"), F("sender_reply_to_mismatch", "fact")])))
    text = json.dumps(out).lower()
    for bad in ("the attacker is", "identified the sender", "same person", "located in"):
        assert bad not in text
    assert "never identify a person" in out["disclaimer"]


# ── persistence, isolation, LLM separation ───────────────────────────────
def test_backfill_idempotent(app_db, monkeypatch):
    app, db = app_db
    c, _ = _client(app, db)
    for rel in ("demo/bec_wire_change.eml", "eml/benign.eml"):
        _upload(c, FIX / rel)
    db.query(AttackMapping).delete()
    db.commit()
    first = attack_service.backfill(db)
    second = attack_service.backfill(db)
    assert first["versions_created"] == 2 and second["versions_created"] == 0 and second["unchanged"] == 2
    assert first["total_versions"] == second["total_versions"] == 2
    row = db.query(AttackMapping).first()
    assert row.mapping_engine_version == ENGINE_VERSION and row.catalog_version == get_catalog().version


def test_mapping_failure_is_isolated(app_db, monkeypatch):
    app, db = app_db
    c, _ = _client(app, db)
    normal = _upload(c, FIX / "demo/bec_wire_change.eml")

    def boom(*a, **k):
        raise RuntimeError("synthetic mapper failure")

    monkeypatch.setattr(attack_service, "compute", boom)
    broken = _upload(c, FIX / "demo/bec_wire_change.eml")
    strip = lambda d: {k: v for k, v in d.items() if k not in ("id", "created_at")}  # noqa: E731
    assert strip(normal) == strip(broken)
    assert broken["detection"]["score"] == 100 and broken["detection"]["verdict"] == "phishing_fraud_likely"
    assert c.get(f"/api/v1/analyses/{broken['id']}/attack").status_code == 404


def test_attack_results_never_reach_the_llm(app_db):
    from app.api.llm_router import _analysis_dict
    from app.llm.evidence import build_pack
    app, db = app_db
    c, _ = _client(app, db)
    up = _upload(c, FIX / "eml/phishing_multipart.eml")
    assert c.get(f"/api/v1/analyses/{up['id']}/attack").json()["mappings"]
    pack = build_pack(_analysis_dict(db.get(Analysis, up["id"])), None, None)
    text = pack.known_text() + json.dumps(pack.items)
    assert not re.search(r"T1\d{3}", text) and "ATT&CK" not in text and "attack_mapping" not in text
    import app.llm as llm_pkg
    for f in Path(llm_pkg.__file__).parent.glob("*.py"):
        assert "app.attack" not in f.read_text(), f


# ── permissions ──────────────────────────────────────────────────────────
def test_permissions(app_db):
    app, db = app_db
    a, _ = _client(app, db, "analyst")
    aid = _upload(a, FIX / "demo/bec_wire_change.eml")["id"]
    anon = TestClient(app)
    for p in (f"/api/v1/analyses/{aid}/attack", f"/api/v1/analyses/{aid}/attack/history"):
        assert anon.get(p).status_code == 401
    assert anon.post(f"/api/v1/analyses/{aid}/attack/recompute").status_code == 401
    v, _ = _client(app, db, "viewer")
    assert v.get(f"/api/v1/analyses/{aid}/attack").status_code == 200
    assert v.get(f"/api/v1/analyses/{aid}/attack/history").status_code == 200
    assert v.post(f"/api/v1/analyses/{aid}/attack/recompute").status_code == 403
    r = a.post(f"/api/v1/analyses/{aid}/attack/recompute")
    assert r.status_code == 200 and r.json()["new_version"] is False
    assert db.query(AuditEvent).filter_by(event_type="attack_recomputed").count() == 1
    assert a.get("/api/v1/analyses/nope/attack").status_code == 404


# ── PDF 7C ───────────────────────────────────────────────────────────────
@pytest.fixture
def nocompress(monkeypatch):
    from reportlab import rl_config
    monkeypatch.setattr(rl_config, "pageCompression", 0)


def _pdf_text(pdf: bytes) -> str:
    out = []
    for block in re.findall(rb"\bBT\b(.*?)\bET\b", pdf, re.S):
        for line in re.split(rb"T\*", block):
            parts = re.findall(rb"\(((?:\\.|[^\\)])*)\)\s*Tj", line)
            if parts:
                text = b"".join(parts).decode("latin-1").replace("\\(", "(").replace("\\)", ")").strip()
                out.append(re.sub(r"([_.-]) ", r"\1", text))
    return " ".join(out)


def test_pdf_section_content_pinning_and_escaping(app_db, nocompress):
    app, db = app_db
    c, _ = _client(app, db)
    up = _upload(c, FIX / "demo/bec_wire_change.eml")
    case = c.post(f"/api/v1/investigations/from-analysis/{up['id']}").json()
    v1 = c.get(f"/api/v1/analyses/{up['id']}/attack").json()
    txt = _pdf_text(c.get(f"/api/v1/investigations/{case['id']}/report/{up['id']}",
                          params={"attack_id": v1["mapping_id"]}).content)
    assert "MITRE ATT" in txt and "T1684.001" in txt and "Impersonation" in txt and "INFERRED" in txt
    assert "NOT ASSESSED: threat-intel lookup was not run" in txt
    assert "never identify a person" in txt and "Enterprise 20.1" in txt
    ev = db.query(AuditEvent).filter_by(event_type="report_generated").one()
    assert ev.detail["attack_mapping_id"] == v1["mapping_id"] and ev.detail["attack_mapping_version"] == 1
    assert c.get(f"/api/v1/investigations/{case['id']}/report/{up['id']}",
                 params={"attack_id": "nope"}).status_code == 404

    from app.reports.pdf import build_report_pdf
    evil = {**v1, "mappings": [{**v1["mappings"][0], "rationale": "<b>bold</b> & <script>x</script>"}],
            "source_type": [{"label": "<i>L</i>", "band": "not_assessed", "reason": "<u>r</u>", "evidence_ids": [],
                             "rationale": "", "missing_data": []}]}
    txt = _pdf_text(build_report_pdf(case_dict={"case_number": "C"}, analysis_row={"id": "a", "sha256": "f" * 64},
                                     detection={}, forensics={}, auth={}, enrichment={},
                                     integrity={"result": "unavailable"}, report_id="R", attack=evil))
    assert "<b>bold</b>" in txt and "<script>x</script>" in txt and "NOT ASSESSED: <u>r</u>" in txt
    empty = _pdf_text(build_report_pdf(case_dict={"case_number": "C"}, analysis_row={"id": "a", "sha256": "f" * 64},
                                       detection={}, forensics={}, auth={}, enrichment={},
                                       integrity={"result": "unavailable"}, report_id="R",
                                       attack={**v1, "mappings": [], "empty_state": EMPTY_TEXT}))
    assert "No ATT&CK techniques could be mapped" in empty


def test_campaign_detail_aggregates_member_techniques(app_db):
    app, db = app_db
    c, _ = _client(app, db)
    for i in range(1, 3):
        _upload(c, FIX / "demo" / "campaign" / f"campaign_member_{i}.eml")
    camp = c.get("/api/v1/campaigns").json()["items"][0]
    agg = c.get(f"/api/v1/campaigns/{camp['id']}").json()["attack_aggregate"]
    assert agg["members_with_mapping"] == 2 and "Aggregated from member" in agg["label"]


def test_cli_backfill(monkeypatch, app_db, capsys):
    from app import cli
    app, db = app_db
    monkeypatch.setattr(cli, "_session", lambda: db)
    monkeypatch.setattr(db, "close", lambda: None)
    assert cli.main(["backfill-attack"]) == 0
    assert "versions_created: 0" in capsys.readouterr().out


def test_returnpath_artefact_is_not_used_as_spoofing_evidence():
    # upstream forensics can keep a trailing '>' and flag identical domains; the mapper re-checks
    same = A([F("auth_failure_support", "fact")], inc=["returnpath_mismatch"],
             from_domain="account-notice.test", return_path="<security@account-notice.test>")
    out = compute(Inputs(same))
    assert "T1684.002" not in _ids(out)
    assert out["suppressed_signals"] and "match after normalisation" in out["suppressed_signals"][0]
    assert {h["hypothesis"]: h for h in out["source_type"]}["spoofed_domain"]["band"] == "possible"   # claim only
    real = A([F("auth_failure_support", "fact")], inc=["returnpath_mismatch"],
             from_domain="legit-brand.com", return_path="<bounces@other-mailer.com>")
    assert "T1684.002" in _ids(compute(Inputs(real)))
