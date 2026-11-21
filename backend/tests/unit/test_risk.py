"""P5h: explainable combined risk assessment — combiner properties, bands, scenarios, persistence, API, PDF.

Engine tests are pure. API tests use the shared test database, so they run on SQLite by default and on
PostgreSQL with TEST_DATABASE_URL (make test-pg)."""
from __future__ import annotations

import itertools
import os
import re
import secrets
import time

import pytest

import app.risk.service as risk_service
from app.core import db as dbmod
from app.core.models import Analysis, AuditEvent, MlClassification, RiskAssessment, ThreatIntelRun, utcnow
from app.main import create_app
from app.risk.config import LEVELS, RiskConfig, get_config
from app.risk.engine import Inputs, compute, level_for, ml_to_score
from tests.authutil import authed_client

FIX = os.path.join(os.path.dirname(__file__), "..", "fixtures")
CFG = get_config()
RANK = {lvl: i for i, lvl in enumerate(LEVELS)}
ALL_RULES = ("ip_literal_url", "url_obfuscation", "suspicious_url_structure", "lookalike_domain",
             "sender_reply_to_mismatch", "urgency_language", "credential_request", "payment_diversion",
             "all_caps_pressure", "risky_attachment_type", "header_inconsistency", "auth_failure_support",
             "header_inconsistency_forensics", "auth_conflict", "auth_verified_fail", "auth_dmarc_misaligned",
             "ip_url_risky_lookup", "domain_no_mx_shortlived")


# ── helpers ────────────────────────────────────────────────────────────────
def det(score=0, rules=()):
    verdict = "phishing_fraud_likely" if score >= 60 else "suspicious" if score >= 25 else "minimal"
    return {"score": score, "verdict": verdict,
            "findings": [{"rule_id": r, "title": r.replace("_", " "), "contribution": 10} for r in rules]}


def ml(p_threat, label=None):
    legit = round(1 - p_threat, 4)
    probs = {"legitimate": legit, "suspicious": 0.0, "impersonated": 0.0, "phishing": round(p_threat, 4), "fraud": 0.0}
    top = max(probs, key=probs.get)
    return {"status": "ok", "label": label or top, "confidence": probs[top], "probabilities": probs,
            "model_version": "test@1", "source_kind": "upload_classification", "source_id": "m1"}


def intel(results=(), consent=True, simulated=False):
    return {"run_id": "run1", "version": 1, "consent": {"granted": consent}, "offline": False, "simulated": simulated,
            "indicators": [{"indicator": "203.0.113.9", "indicator_type": "ip",
                            "results": [{"provider": p, "status": s, "indicator": "203.0.113.9"} for p, s in results]}]}


def run(**kw):
    return compute(Inputs(**kw))


def score_of(r):
    return -1 if r["combined_score"] is None else r["combined_score"]


def comp(r, name):
    return next(c for c in r["components"] if c["name"] == name)


# ── bands and mapping ─────────────────────────────────────────────────────
@pytest.mark.parametrize("score,level", [(0, "minimal"), (9, "minimal"), (10, "low"), (24, "low"), (25, "medium"),
                                         (59, "medium"), (60, "high"), (84, "high"), (85, "critical"),
                                         (100, "critical"), (None, "indeterminate")])
def test_level_band_boundaries(score, level):
    assert level_for(score, CFG) == level


def test_ml_mapping_hits_edges_and_is_monotone():
    assert ml_to_score(0.0, CFG) == 0 and ml_to_score(1.0, CFG) == 100
    for t, edge in ((CFG.t_low, 10), (CFG.t_med, 25), (CFG.t_high, 60), (CFG.t_crit, 85)):
        assert abs(ml_to_score(t, CFG) - edge) < 1e-9
    vals = [ml_to_score(i / 1000, CFG) for i in range(1001)]
    assert all(b >= a for a, b in zip(vals, vals[1:]))


def test_config_keeps_monotonicity_constraint():
    assert CFG.t_low < CFG.t_med <= CFG.ml_side_threshold <= CFG.t_high < CFG.t_crit
    assert ml_to_score(CFG.ml_side_threshold, CFG) >= CFG.conflict_floor


# ── properties ─────────────────────────────────────────────────────────────
P_GRID = [i / 20 for i in range(21)]
S_GRID = [0, 10, 24, 25, 40, 59, 60, 80, 100]
RULE_SETS = [(), ("urgency_language",), ("payment_diversion",), ("payment_diversion", "sender_reply_to_mismatch"),
             ("risky_attachment_type",), ("auth_verified_fail", "lookalike_domain")]
INTEL_SETS = [None, intel([("abuseipdb", "no_record")]), intel([("tor_exit_list", "malicious_or_flagged")]),
              intel([("virustotal", "malicious_or_flagged")])]


@pytest.mark.parametrize("rules", RULE_SETS)
def test_monotonic_in_ml_threat_index(rules):
    for s in S_GRID:
        prev = None
        for p in P_GRID:
            r = run(detection=det(s, rules), ml=ml(p))
            if prev:
                assert score_of(r) >= score_of(prev) and RANK[r["level"]] >= RANK[prev["level"]], (s, p, rules)
            prev = r


@pytest.mark.parametrize("p", [None, 0.0, 0.2, 0.35, 0.49, 0.5, 0.7, 0.95])
def test_monotonic_in_rule_score(p):
    prev = None
    for s in range(0, 101, 5):
        r = run(detection=det(s), ml=ml(p) if p is not None else None)
        if prev:
            assert score_of(r) >= score_of(prev), (p, s)
        prev = r


@pytest.mark.parametrize("p", [None, 0.0, 0.3, 0.6, 0.95])
def test_adding_any_fired_rule_never_lowers(p):
    for base_rules in RULE_SETS:
        for extra in ALL_RULES:
            for s in (0, 30, 70):
                a = run(detection=det(s, base_rules), ml=ml(p) if p is not None else None)
                b = run(detection=det(s, (*base_rules, extra)), ml=ml(p) if p is not None else None)
                assert score_of(b) >= score_of(a), (p, base_rules, extra, s)


def test_adding_intel_flags_never_lowers_and_no_record_never_changes():
    for s, p in itertools.product((0, 30, 70), (None, 0.0, 0.4, 0.9)):
        kw = {"detection": det(s), "ml": ml(p) if p is not None else None}
        base = run(**kw)
        for statuses in (("no_record",), ("reported_clean_no_flags",), ("record_found",)):
            r = run(**kw, intel_run=intel([("abuseipdb", st) for st in statuses]))
            assert r["combined_score"] == base["combined_score"] and r["level"] == base["level"]
        prev = base
        for flags in ([("ipinfo", "malicious_or_flagged")],
                      [("ipinfo", "malicious_or_flagged"), ("virustotal", "malicious_or_flagged")],
                      [("ipinfo", "malicious_or_flagged"), ("virustotal", "malicious_or_flagged"),
                       ("abuseipdb", "malicious_or_flagged")]):
            r = run(**kw, intel_run=intel(flags))
            assert score_of(r) >= score_of(prev)
            prev = r


def test_hard_floors_hold_against_ml_legitimate_and_absent_intel():
    for rules, fid in ((("risky_attachment_type",), "H1_risky_attachment"),
                       (("auth_verified_fail", "lookalike_domain"), "H2_verified_auth_fail_identity"),
                       (("payment_diversion", "sender_reply_to_mismatch"), "H3_payment_or_credential_with_identity"),
                       (("credential_request", "auth_dmarc_misaligned"), "H3_payment_or_credential_with_identity")):
        for i in (None, intel([("abuseipdb", "no_record")]), intel(consent=False)):
            r = run(detection=det(0, rules), ml=ml(0.0), intel_run=i)
            assert r["combined_score"] >= 60 and RANK[r["level"]] >= RANK["high"], rules
            assert "hard_evidence_floor" in r["flags"] and fid in comp(r, "hard_evidence")["value"]
    # payment language alone (no sender-identity signal) is not a floor
    assert comp(run(detection=det(0, ("payment_diversion",)), ml=ml(0.0)), "hard_evidence")["value"] == []


def test_unavailable_never_implies_legitimate():
    for status in ("unavailable", "error", "not_applicable"):
        r = run(detection=det(0), ml={"status": status, "reason": "x"})
        assert r["level"] == "low" and r["confidence"] == "low" and "components_missing" in r["flags"]
        assert comp(r, "ml")["status"] in ("unavailable", "error") and comp(r, "ml")["role"] == "unavailable"
    r = run(detection=det(0), ml=None)
    assert r["level"] == "low" and comp(r, "ml")["status"] == "not_run"
    # rules missing, ML says legitimate: still never minimal
    r = run(detection={"error": "parse"}, ml=ml(0.01))
    assert r["level"] == "low" and r["confidence"] == "low" and "ml_only" in r["flags"]
    # never lower than the available component supports
    for s in S_GRID:
        r = run(detection=det(s), ml=None)
        assert r["combined_score"] >= s and RANK[r["level"]] >= RANK[level_for(s, CFG)]


def test_indeterminate_when_both_primaries_missing():
    for d, m in ((None, None), ({"error": "x"}, {"status": "unavailable"}), (None, {"status": "error"})):
        r = run(detection=d, ml=m, intel_run=intel([("virustotal", "malicious_or_flagged")]))
        assert r["level"] == "indeterminate" and r["combined_score"] is None and r["confidence"] == "low"
        assert "not an indication of safety" in r["explanation"][0]


def test_conflict_rules_high_ml_legitimate():
    r = run(detection=det(80), ml=ml(0.02))
    assert r["conflict"] == "rules_high_ml_legitimate" and r["agreement"] == "conflict"
    assert RANK[r["level"]] >= RANK["medium"] and r["confidence"] == "low"
    assert {"conflicting_signals", "analyst_review_recommended"} <= set(r["flags"])
    assert comp(r, "rules")["value"]["verdict"] == "phishing_fraud_likely"
    assert comp(r, "ml")["value"]["label"] == "legitimate"
    assert any("analyst review" in e for e in r["explanation"])


def test_conflict_ml_threat_rules_minimal():
    r = run(detection=det(0), ml=ml(0.55))
    assert r["conflict"] == "ml_threat_rules_minimal" and RANK[r["level"]] >= RANK["medium"]
    assert "conflicting_signals" in r["flags"]


def test_no_double_counting_rule_points_do_not_add_when_ml_available():
    for p in (0.0, 0.4, 0.7, 0.95):
        a = run(detection=det(26, ("urgency_language",)), ml=ml(p))
        b = run(detection=det(55, ("urgency_language", "all_caps_pressure")), ml=ml(p))
        assert a["combined_score"] == b["combined_score"], p


def test_intel_statuses_and_cap():
    assert comp(run(detection=det(0), ml=ml(0.1)), "threat_intel")["status"] == "not_run"
    assert comp(run(detection=det(0), ml=ml(0.1), intel_run=intel(consent=False)), "threat_intel")["status"] == "declined"
    r = run(detection=det(0), ml=ml(0.1), intel_run=intel([("virustotal", "provider_error"), ("ipinfo", "rate_limited")]))
    assert comp(r, "threat_intel")["status"] == "unavailable"
    r = run(detection=det(0), ml=ml(0.0), intel_run=intel([(p, "malicious_or_flagged") for p in
                                                            ("virustotal", "abuseipdb", "shodan", "ipinfo")]))
    assert comp(r, "threat_intel")["effect"] == "+15" and r["level"] == "medium"
    r = run(detection=det(0), ml=ml(0.0), intel_run=intel([("tor_exit_list", "malicious_or_flagged")], simulated=True))
    assert "intel_simulated" in r["flags"] and "SIMULATED" in comp(r, "threat_intel")["reason"] + " ".join(r["explanation"])


def test_deterministic_and_versioned():
    kw = {"detection": det(70, ("payment_diversion", "sender_reply_to_mismatch")), "ml": ml(0.6),
          "intel_run": intel([("virustotal", "malicious_or_flagged")]),
          "campaigns": [{"campaign_id": "c1", "label": "C-0001", "confidence": "medium"}],
          "attack": {"mapping_id": "m1", "version": 1, "techniques": ["T1566"], "hypotheses": []}}
    a, b = run(**kw), run(**kw)
    assert a == b and a["engine_version"] and a["config_version"]
    assert comp(a, "campaign")["effect"] == "none" and comp(a, "attack")["effect"] == "none"
    without_ctx = run(detection=kw["detection"], ml=kw["ml"], intel_run=kw["intel_run"])
    assert without_ctx["combined_score"] == a["combined_score"]


def test_engine_does_not_mutate_inputs():
    d, m = det(70, ("payment_diversion",)), ml(0.3)
    snap = (repr(d), repr(m))
    run(detection=d, ml=m)
    assert snap == (repr(d), repr(m))


def test_cues_listed_from_existing_rule_findings():
    r = run(detection=det(40, ("urgency_language", "payment_diversion")), ml=ml(0.9))
    cues = {c["rule_id"]: c["fired"] for c in comp(r, "rules")["cues"]}
    assert cues == {"urgency_language": True, "credential_request": False, "payment_diversion": True,
                    "all_caps_pressure": False}


def test_custom_config_changes_bands_only_through_versioned_config():
    cfg = RiskConfig(t_med=0.4)
    assert compute(Inputs(detection=det(0), ml=ml(0.38)), cfg)["level"] == "low"
    assert compute(Inputs(detection=det(0), ml=ml(0.38)))["level"] == "medium"


# ── API / pipeline (shared DB: SQLite and PostgreSQL) ──────────────────────
def _copy(name: str) -> bytes:
    data = open(os.path.join(FIX, name), "rb").read()
    return data.replace(b"Subject:", f"X-Test-Nonce: {secrets.token_hex(6)}\r\nSubject:".encode(), 1)


def _upload(client, data: bytes) -> dict:
    r = client.post("/api/v1/analyses", files={"file": ("m.eml", data, "message/rfc822")})
    assert r.status_code == 201, r.text
    return r.json()


MACRO_EML = (b"From: Accounts <ap@vendor-billing.example>\r\nTo: you@corp.example\r\nSubject: Invoice\r\n"
             b"Message-ID: <m@x>\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=B\r\n\r\n"
             b"--B\r\nContent-Type: text/plain\r\n\r\nPlease see the attached invoice.\r\n"
             b"--B\r\nContent-Type: application/vnd.ms-word.document.macroEnabled.12\r\n"
             b"Content-Disposition: attachment; filename=\"invoice.docm\"\r\nContent-Transfer-Encoding: base64\r\n\r\n"
             b"UEsDBAoAAAAAAA==\r\n--B--\r\n")


@pytest.fixture
def analyst():
    return authed_client(create_app(), "analyst")


@pytest.fixture
def viewer():
    return authed_client(create_app(), "viewer")


def test_upload_computes_risk_and_stores_ml_outcome_without_changing_rules(analyst):
    up = _upload(analyst, _copy("demo/bec_wire_change.eml"))
    assert up["detection"]["score"] == 100 and up["detection"]["verdict"] == "phishing_fraud_likely"
    r = analyst.get(f"/api/v1/analyses/{up['id']}/risk").json()
    assert r["version"] == 1 and r["source"] == "upload"
    assert comp(r, "ml")["status"] == "unavailable"           # tests run without model files
    assert r["level"] == "critical" and r["combined_score"] == 100 and "rules_only" in r["flags"]
    assert "H3_payment_or_credential_with_identity" in comp(r, "hard_evidence")["value"]
    with dbmod.SessionLocal() as db:
        rows = db.query(MlClassification).filter_by(analysis_id=up["id"]).all()
        assert len(rows) == 1 and rows[0].status == "unavailable" and rows[0].source == "upload"
        rec = db.get(Analysis, up["id"])
        assert rec.detection_score == 100 and rec.detection_verdict == "phishing_fraud_likely"
    lst = {a["id"]: a for a in analyst.get("/api/v1/analyses").json()}
    assert lst[up["id"]]["combined_level"] == "critical" and lst[up["id"]]["combined_score"] == 100
    assert lst[up["id"]]["detection_verdict"] == "phishing_fraud_likely"


@pytest.mark.parametrize("name,expect", [("eml/multihop_auth.eml", None), ("demo/legitimate_invoice.eml", "low"),
                                         ("eml/benign.eml", "low")])
def test_scenarios_without_ml_are_never_minimal(analyst, name, expect):
    up = _upload(analyst, _copy(name))
    r = analyst.get(f"/api/v1/analyses/{up['id']}/risk").json()
    assert r["level"] != "minimal" and r["confidence"] == "low"
    if expect:
        assert r["level"] == expect


def test_macro_attachment_floor(analyst):
    up = _upload(analyst, MACRO_EML.replace(b"<m@x>", f"<{secrets.token_hex(4)}@x>".encode()))
    assert any(f["rule_id"] == "risky_attachment_type" for f in up["detection"]["findings"])
    r = analyst.get(f"/api/v1/analyses/{up['id']}/risk").json()
    assert "H1_risky_attachment" in comp(r, "hard_evidence")["value"] and RANK[r["level"]] >= RANK["high"]


def _store_ml(aid: str, p: float):
    with dbmod.SessionLocal() as db:
        db.add(MlClassification(analysis_id=aid, source="upload", status="ok", model_version="test@1",
                                result_json=ml(p), created_at=utcnow()))
        db.commit()


def test_ml_legitimate_while_rules_high_is_conflict(analyst):
    up = _upload(analyst, _copy("demo/bec_wire_change.eml"))
    _store_ml(up["id"], 0.03)
    r = analyst.post(f"/api/v1/analyses/{up['id']}/risk/recompute").json()
    assert r["new_version"] is True and r["version"] == 2 and r["source"] == "recompute"
    assert r["conflict"] == "rules_high_ml_legitimate" and RANK[r["level"]] >= RANK["high"]   # H3 floor holds
    assert r["inputs"]["ml_source"]["kind"] == "upload_classification"


def test_rules_low_while_ml_high_is_conflict(analyst):
    up = _upload(analyst, _copy("demo/legitimate_invoice.eml"))
    assert up["detection"]["verdict"] == "minimal"
    _store_ml(up["id"], 0.92)
    r = analyst.post(f"/api/v1/analyses/{up['id']}/risk/recompute").json()
    assert r["conflict"] == "ml_threat_rules_minimal" and r["level"] == "critical"


def test_tor_scenario_with_simulated_intel(analyst):
    up = _upload(analyst, _copy("eml/multihop_auth.eml"))
    with dbmod.SessionLocal() as db:
        db.add(ThreatIntelRun(analysis_id=up["id"], version=1, consent_granted=True, consent_source="on_demand",
                              providers_requested=["tor_exit_list"], offline=False, created_at=utcnow(),
                              result_json=intel([("tor_exit_list", "malicious_or_flagged")], simulated=True)))
        db.commit()
    before = analyst.get(f"/api/v1/analyses/{up['id']}/risk").json()
    r = analyst.post(f"/api/v1/analyses/{up['id']}/risk/recompute").json()
    assert "intel_flagged" in r["flags"] and "intel_simulated" in r["flags"] and r["inputs"]["intel_simulated"]
    assert r["combined_score"] == min(100, before["combined_score"] + 5)


def test_versioning_recompute_idempotent_and_backfill(analyst):
    up = _upload(analyst, _copy("demo/phishing_account_verify.eml"))
    r = analyst.post(f"/api/v1/analyses/{up['id']}/risk/recompute").json()
    assert r["new_version"] is False and r["version"] == 1
    with dbmod.SessionLocal() as db:
        first = risk_service.backfill(db)
        second = risk_service.backfill(db)
        assert second["versions_created"] == 0 and second["total_versions"] == first["total_versions"]
        assert db.query(AuditEvent).filter_by(event_type="risk_recomputed", analysis_id=up["id"]).count() == 1
    hist = analyst.get(f"/api/v1/analyses/{up['id']}/risk/history").json()
    assert [h["version"] for h in hist] == [1]
    assert analyst.get(f"/api/v1/analyses/{up['id']}/risk", params={"version": 1}).json()["version"] == 1
    assert analyst.get(f"/api/v1/analyses/{up['id']}/risk", params={"version": 9}).status_code == 404
    assert analyst.get("/api/v1/analyses/nope/risk").status_code == 404


def _strip(d: dict) -> dict:
    return {k: v for k, v in d.items() if k not in ("id", "created_at")}


def test_failure_isolation_upload_identical(analyst, monkeypatch):
    data = _copy("demo/bec_wire_change.eml")
    ok = _upload(analyst, data)

    def boom(*a, **k):
        raise RuntimeError("forced")
    monkeypatch.setattr(risk_service, "compute", boom)
    monkeypatch.setattr(risk_service, "_classify", boom)
    bad = _upload(analyst, data)
    assert _strip(bad) == _strip(ok)
    assert analyst.get(f"/api/v1/analyses/{bad['id']}/risk").status_code == 404
    with dbmod.SessionLocal() as db:
        assert db.query(MlClassification).filter_by(analysis_id=bad["id"]).one().status == "error"
        assert db.get(Analysis, bad["id"]).detection_score == ok["detection"]["score"]


def test_upload_ml_timeout_is_bounded_and_stored(analyst, monkeypatch):
    monkeypatch.setattr(risk_service, "_timeout", lambda: 1.0)
    monkeypatch.setattr(risk_service, "_classify", lambda raw: (time.sleep(2), {"status": "ok"})[1])
    t0 = time.time()
    up = _upload(analyst, _copy("eml/benign.eml"))
    assert time.time() - t0 < 10
    with dbmod.SessionLocal() as db:
        row = db.query(MlClassification).filter_by(analysis_id=up["id"]).one()
        assert row.status == "error" and "exceeded" in row.result_json["reason"]


def test_upload_ml_success_is_used_and_can_be_disabled(analyst, monkeypatch):
    monkeypatch.setattr(risk_service, "_classify", lambda raw: ml(0.97, "phishing"))
    up = _upload(analyst, _copy("demo/phishing_account_verify.eml"))
    r = analyst.get(f"/api/v1/analyses/{up['id']}/risk").json()
    assert comp(r, "ml")["status"] == "available" and r["level"] == "critical"
    monkeypatch.setenv("AIPISH_ML_AT_UPLOAD", "0")
    up2 = _upload(analyst, _copy("eml/benign.eml"))
    with dbmod.SessionLocal() as db:
        assert db.query(MlClassification).filter_by(analysis_id=up2["id"]).count() == 0
    assert comp(analyst.get(f"/api/v1/analyses/{up2['id']}/risk").json(), "ml")["status"] == "not_run"


def test_permissions_and_audit(analyst, viewer, anon_client):
    up = _upload(analyst, _copy("demo/bec_wire_change.eml"))
    aid = up["id"]
    assert viewer.get(f"/api/v1/analyses/{aid}/risk").status_code == 200
    assert viewer.get(f"/api/v1/analyses/{aid}/risk/history").status_code == 200
    assert viewer.post(f"/api/v1/analyses/{aid}/risk/recompute").status_code == 403
    assert anon_client.get(f"/api/v1/analyses/{aid}/risk").status_code == 401
    assert analyst.post(f"/api/v1/analyses/{aid}/risk/recompute").status_code == 200
    with dbmod.SessionLocal() as db:
        ev = db.query(AuditEvent).filter_by(event_type="risk_recomputed", analysis_id=aid).one()
        assert ev.detail["new_version"] is False and ev.outcome == "success"


def test_viewer_response_is_masked_and_contains_no_addresses(analyst, viewer):
    up = _upload(analyst, _copy("demo/bec_wire_change.eml"))
    txt = viewer.get(f"/api/v1/analyses/{up['id']}/risk").text
    for addr in ("dana@internal-corp.example", "finance-team@internal-corp.example", "Dana Finance Director"):
        assert addr not in txt
    assert analyst.get(f"/api/v1/analyses/{up['id']}/risk").json()["level"] == "critical"


def test_search_and_analytics_include_combined_levels(analyst):
    up = _upload(analyst, _copy("demo/bec_wire_change.eml"))
    s = analyst.get("/api/v1/search", params={"q": up["sha256"][:12], "type": "analysis"}).json()
    item = next(i for i in s["results"]["analysis"]["items"] if i["id"] == up["id"])
    assert item["combined_level"] == "critical" and item["detection_verdict"] == "phishing_fraud_likely"
    a = analyst.get("/api/v1/analytics/summary").json()
    levels = {x["level"]: x["count"] for x in a["combined_levels"]}
    assert set(levels) == {"minimal", "low", "medium", "high", "critical", "indeterminate", "not_computed"}
    assert levels["critical"] >= 1


def test_erasure_covers_risk_and_ml_rows(analyst):
    from app.retention import service as retention
    assert RiskAssessment in retention.dependent_models() and MlClassification in retention.dependent_models()
    up = _upload(analyst, _copy("demo/bec_wire_change.eml"))
    with dbmod.SessionLocal() as db:
        retention.delete_analysis(db, db.get(Analysis, up["id"]))
        db.commit()
        assert db.query(RiskAssessment).filter_by(analysis_id=up["id"]).count() == 0
        assert db.query(MlClassification).filter_by(analysis_id=up["id"]).count() == 0


# ── PDF 8A ────────────────────────────────────────────────────────────────
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


def test_pdf_section_8a_pinned_masked_and_escaped(analyst, viewer, nocompress):
    up = _upload(analyst, _copy("demo/bec_wire_change.eml"))
    case = analyst.post(f"/api/v1/investigations/from-analysis/{up['id']}").json()
    v1 = analyst.get(f"/api/v1/analyses/{up['id']}/risk").json()
    _store_ml(up["id"], 0.03)
    analyst.post(f"/api/v1/analyses/{up['id']}/risk/recompute")
    pinned = _pdf_text(analyst.get(f"/api/v1/investigations/{case['id']}/report/{up['id']}",
                                   params={"risk_id": v1["risk_id"]}).content)
    assert "8A" in pinned and "Combined Risk Assessment" in pinned and "CRITICAL" in pinned
    assert "(version 1" in pinned and "not a probability" in pinned and "UNAVAILABLE" in pinned
    latest = _pdf_text(viewer.get(f"/api/v1/investigations/{case['id']}/report/{up['id']}").content)
    assert "(version 2" in latest and "conflicting_signals" in latest and "MASKED VIEW" in latest
    with dbmod.SessionLocal() as db:
        evs = db.query(AuditEvent).filter_by(event_type="report_generated", analysis_id=up["id"]).all()
        assert sorted(e.detail["risk_version"] for e in evs) == [1, 2]
    assert analyst.get(f"/api/v1/investigations/{case['id']}/report/{up['id']}",
                       params={"risk_id": "nope"}).status_code == 404

    from app.reports.pdf import build_report_pdf
    evil = {**v1, "explanation": ["<b>bold</b> & <script>x</script>"],
            "components": [{**v1["components"][0], "label": "<i>L</i>"}]}
    txt = _pdf_text(build_report_pdf(case_dict={"case_number": "C"}, analysis_row={"id": "a", "sha256": "f" * 64},
                                     detection={}, forensics={}, auth={}, enrichment={},
                                     integrity={"result": "unavailable"}, report_id="R", risk=evil))
    assert "<b>bold</b>" in txt and "<script>x</script>" in txt and "<i>L</i>" in txt
    none = _pdf_text(build_report_pdf(case_dict={"case_number": "C"}, analysis_row={"id": "a", "sha256": "f" * 64},
                                      detection={}, forensics={}, auth={}, enrichment={},
                                      integrity={"result": "unavailable"}, report_id="R"))
    assert "Combined risk: NOT COMPUTED" in none
