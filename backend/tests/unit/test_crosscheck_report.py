"""P5k-lite: mail-parser cross-check (R43) and the Jinja2 HTML report (R55).

Shared test database: runs on SQLite by default and on PostgreSQL with TEST_DATABASE_URL (make test-pg)."""
from __future__ import annotations

import builtins
import json
import os
import re
import secrets
import time

import pytest

import app.ingestion.crosscheck as cc
from app.core import db as dbmod
from app.core.models import Analysis, AuditEvent, MlClassification, RiskAssessment, ThreatIntelRun, utcnow
from app.ingestion.parser import parse_eml
from app.main import create_app
from tests.authutil import authed_client

FIX = os.path.join(os.path.dirname(__file__), "..", "fixtures")
H = b"To: v@corp.example\r\nSubject: test\r\nDate: Sat, 10 Oct 2026 09:14:30 +0000\r\nMessage-ID: <m1@x.test>\r\n"
SAMPLES = {
    "dup_from": b"From: Boss <boss@corp.example>\r\nFrom: Attacker <evil@attacker.test>\r\n" + H + b"\r\nbody\r\n",
    "dup_return_path": (b"Return-Path: <a@good.test>\r\nReturn-Path: <b@evil.test>\r\nFrom: a@good.test\r\n" + H
                        + b"\r\nbody\r\n"),
    "folded_from": b"From: \"Pay\r\n roll\" <payroll@corp.example>,\r\n\tevil@attacker.test\r\n" + H + b"\r\nbody\r\n",
    "unclosed_boundary": (b"From: a@x.test\r\n" + H + b"MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"B1\""
                          b"\r\n\r\n--B1\r\nContent-Type: text/plain\r\n\r\nhello\r\n--B1\r\nContent-Type: "
                          b"application/octet-stream\r\nContent-Disposition: attachment; filename=\"a.bin\"\r\n"
                          b"Content-Transfer-Encoding: base64\r\n\r\nQUJDREVGR0g=\r\n"),
    "nested_reused_boundary": (b"From: a@x.test\r\n" + H + b"MIME-Version: 1.0\r\nContent-Type: multipart/mixed; "
                               b"boundary=\"X\"\r\n\r\n--X\r\nContent-Type: multipart/alternative; boundary=\"X\"\r\n\r\n"
                               b"--X\r\nContent-Type: text/plain\r\n\r\ninner\r\n--X--\r\n--X\r\nContent-Type: "
                               b"application/octet-stream\r\nContent-Disposition: attachment; filename=\"p.exe\"\r\n"
                               b"Content-Transfer-Encoding: base64\r\n\r\nTVqQAAMAAAAEAAAA\r\n--X--\r\n"),
    "duplicate_date": b"From: a@x.test\r\nDate: Sun, 11 Oct 2026 10:00:00 +0000\r\n" + H + b"\r\nbody\r\n",
    "malformed_received": (b"Received: garbage-without-structure\r\nReceived: from evil.test [203.0.113.66] by mx.test "
                           b"id 1 Sat 10 Oct\r\nReceived: \r\nFrom: a@x.test\r\n" + H + b"\r\nbody\r\n"),
}
EXPECTED = {
    "dup_from": ("security_relevant_differences", {("duplicate_header:from", "security_relevant")}),
    "dup_return_path": ("security_relevant_differences", {("return_path", "security_relevant"),
                                                          ("duplicate_header:return-path", "security_relevant")}),
    "folded_from": ("security_relevant_differences", {("from", "security_relevant")}),
    "unclosed_boundary": ("security_relevant_differences", {("mime_structure", "security_relevant")}),
    "nested_reused_boundary": ("security_relevant_differences", {("attachments", "security_relevant"),
                                                                 ("mime_structure", "security_relevant")}),
    "duplicate_date": ("minor_differences", {("duplicate_header:date", "info")}),
    # both parsers keep the raw Received clauses, so these malformed headers do not differ (documented limit)
    "malformed_received": ("agree", set()),
}
NORMAL = ["demo/bec_wire_change.eml", "demo/legitimate_invoice.eml", "demo/phishing_account_verify.eml",
          "demo/attack/synthetic_macro_attachment.eml", "demo/attack/synthetic_tor_origin.eml",
          "eml/benign.eml", "eml/multihop_auth.eml", "eml/multipart_html.eml"]
PII = ("boss@corp.example", "evil@attacker.test", "a@good.test", "b@evil.test", "payroll@corp.example", "Attacker",
       "a.bin", "p.exe")


def _xc(raw: bytes) -> dict:
    return cc.run_crosscheck(raw, parse_eml(raw))


# ── cross-check: results ─────────────────────────────────────────────────
@pytest.mark.parametrize("name", NORMAL)
def test_normal_fixtures_agree(name):
    r = _xc(open(os.path.join(FIX, name), "rb").read())
    assert r["status"] == "agree" and r["differences"] == [] and r["secondary"] == "mail-parser"
    assert r["secondary_version"] == "4.10.0"


@pytest.mark.parametrize("name", list(SAMPLES))
def test_crafted_differentials(name):
    r = _xc(SAMPLES[name])
    status, fields = EXPECTED[name]
    assert r["status"] == status, r
    assert {(d["field"], d["severity"]) for d in r["differences"]} == fields
    assert [d["evidence_id"] for d in r["differences"]] == [f"P{i}" for i in range(1, len(fields) + 1)]
    blob = json.dumps(r)
    for bad in PII:
        assert bad not in blob, (name, bad)


def test_compare_received_order_length_and_attachment_type():
    base = {"from": [], "to": [], "cc": [], "reply_to": [], "return_path": None, "subject": None, "date": None,
            "message_id": None, "received": [("mx.a", ("1.1.1.1",)), ("mx.b", ())], "attachments": [],
            "leaf_parts": 1, "multipart_depth": 0, "charsets": [], "defects": []}
    rev = {**base, "received": list(reversed(base["received"]))}
    assert [d["description"] for d in cc.compare(base, rev, {})] == ["Received hops are the same but in a different order."]
    short = {**base, "received": base["received"][:1]}
    assert cc.compare(base, short, {})[0]["description"] == "Received chain length differs (2 vs 1 hops)."
    att = {"type": "application/pdf", "size": 3, "sha256": "x", "name": "n"}
    d = cc.compare({**base, "attachments": [att]}, {**base, "attachments": [{**att, "type": "application/x-msdownload"}]}, {})
    assert [(x["field"], x["severity"]) for x in d] == [("attachments", "security_relevant")]


def test_import_failure_parse_error_timeout_and_size_limit(monkeypatch):
    raw = open(os.path.join(FIX, "eml/benign.eml"), "rb").read()
    real_import = builtins.__import__

    def no_mailparser(name, *a, **k):
        if name == "mailparser":
            raise ImportError("blocked for test")
        return real_import(name, *a, **k)
    monkeypatch.setattr(builtins, "__import__", no_mailparser)
    r = _xc(raw)
    assert r["status"] == "unavailable" and "could not be imported" in r["reason"]
    monkeypatch.setattr(builtins, "__import__", real_import)

    monkeypatch.setattr(cc, "secondary_view", lambda raw: (_ for _ in ()).throw(ValueError("boom")))
    r = _xc(raw)
    assert r["status"] == "unavailable" and r["reason"] == "cross-check unavailable: parse failed (ValueError)"

    monkeypatch.setattr(cc, "_timeout", lambda: 0.5)
    monkeypatch.setattr(cc, "secondary_view", lambda raw: (time.sleep(1.5), {})[1])
    t0 = time.time()
    r = _xc(raw)
    assert r["status"] == "unavailable" and "exceeded" in r["reason"] and time.time() - t0 < 1.4
    time.sleep(1.2)                                       # let the worker finish before the next test

    monkeypatch.setenv("PARSER_CROSSCHECK_MAX_MB", "0.0001")
    r = _xc(raw)
    assert r["status"] == "unavailable" and "larger than" in r["reason"]


# ── cross-check: pipeline ────────────────────────────────────────────────
@pytest.fixture
def analyst():
    return authed_client(create_app(), "analyst")


@pytest.fixture
def viewer():
    return authed_client(create_app(), "viewer")


def _upload(client, data: bytes) -> dict:
    r = client.post("/api/v1/analyses", files={"file": ("m.eml", data, "message/rfc822")})
    assert r.status_code == 201, r.text
    return r.json()


def _nonce(name: str) -> bytes:
    data = open(os.path.join(FIX, name), "rb").read()
    return data.replace(b"Subject:", f"X-Test-Nonce: {secrets.token_hex(6)}\r\nSubject:".encode(), 1)


def test_stored_exposed_and_never_changes_scores_risk_or_alerts(analyst, viewer, monkeypatch):
    data = SAMPLES["dup_from"].replace(b"Message-ID: <m1@x.test>", f"Message-ID: <{secrets.token_hex(4)}@x.test>".encode())
    with_xc = _upload(analyst, data)
    assert with_xc["parser_crosscheck"]["status"] == "security_relevant_differences"
    monkeypatch.setattr(cc, "secondary_view", lambda raw: (_ for _ in ()).throw(RuntimeError("off")))
    without = _upload(analyst, data)
    assert without["parser_crosscheck"]["status"] == "unavailable"
    assert with_xc["detection"] == without["detection"]
    r1 = analyst.get(f"/api/v1/analyses/{with_xc['id']}/risk").json()
    r2 = analyst.get(f"/api/v1/analyses/{without['id']}/risk").json()
    assert (r1["level"], r1["combined_score"], r1["flags"]) == (r2["level"], r2["combined_score"], r2["flags"])
    with dbmod.SessionLocal() as db:
        from app.core.models import Alert
        a1 = sorted((a.type, a.severity) for a in db.query(Alert).filter_by(analysis_id=with_xc["id"]))
        a2 = sorted((a.type, a.severity) for a in db.query(Alert).filter_by(analysis_id=without["id"]))
        assert a1 == a2
        assert db.get(Analysis, with_xc["id"]).parser_crosscheck["status"] == "security_relevant_differences"
    v = viewer.get(f"/api/v1/analyses/{with_xc['id']}").json()
    assert v["parser_crosscheck"]["differences"][0]["field"] == "duplicate_header:from"
    assert "boss@corp.example" not in json.dumps(v["parser_crosscheck"])


def test_bec_outputs_unchanged(analyst):
    up = _upload(analyst, _nonce("demo/bec_wire_change.eml"))
    assert up["detection"]["score"] == 100 and up["detection"]["verdict"] == "phishing_fraud_likely"
    assert up["parser_crosscheck"]["status"] == "agree"


def test_migration_step_is_idempotent():
    from sqlalchemy import inspect
    from app.core.migrations import upgrade
    upgrade(dbmod.engine)
    upgrade(dbmod.engine)
    assert "parser_crosscheck" in {c["name"] for c in inspect(dbmod.engine).get_columns("analysis")}


# ── HTML report ──────────────────────────────────────────────────────────
EVIL = "<script>alert(1)</script>"
XSS_EML = ("From: \"<img src=x onerror=alert(1)>\" <boss@corp.example>\r\nTo: v@corp.example\r\n"
           f"Subject: {EVIL}\r\nMessage-ID: <\"><svg onload=x>@x.test>\r\nDate: Sat, 10 Oct 2026 09:14:30 +0000\r\n"
           "Received: from <b>evil</b>.test (x [198.51.100.7]) by mx.test; Sat, 10 Oct 2026 09:14:30 +0000\r\n"
           "MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"B\"\r\n\r\n--B\r\nContent-Type: text/plain\r\n\r\n"
           f"Please wire funds {EVIL} https://x-<i>.example/login\r\n--B\r\nContent-Type: application/octet-stream\r\n"
           "Content-Disposition: attachment; filename=\"<script>x</script>.exe\"\r\nContent-Transfer-Encoding: base64\r\n"
           "\r\nTVqQAAMAAAAEAAAA\r\n--B--\r\n").encode()
FORBIDDEN_TAGS = {"script", "link", "img", "iframe", "object", "embed", "svg", "base", "form", "audio", "video",
                  "source", "picture", "frame", "applet"}


def remote_refs(html: str) -> list[str]:
    """Real tags/attributes only (escaped text is not markup): forbidden tags, non-anchor src/href/action/etc.,
    and CSS url()/@import inside <style>."""
    from html.parser import HTMLParser
    found: list[str] = []

    class P(HTMLParser):
        in_style = False

        def handle_starttag(self, tag, attrs):
            if tag in FORBIDDEN_TAGS:
                found.append(f"<{tag}>")
            for k, v in attrs:
                if k in ("src", "href", "action", "poster", "data", "srcset", "background") and not (v or "").startswith("#"):
                    found.append(f"{k}={v}")
                if k.startswith("on"):
                    found.append(f"{k}=")
            self.in_style = tag == "style"

        def handle_endtag(self, tag):
            self.in_style = False

        def handle_data(self, data):
            if self.in_style and re.search(r"url\(|@import", data, re.I):
                found.append("css url/import")
    P().feed(html)
    return found


def _html(client, aid: str, **params):
    r = client.get(f"/api/v1/analyses/{aid}/report.html", params=params)
    return r


def test_html_report_headers_no_external_resources_and_escaping(analyst, anon_client):
    up = _upload(analyst, XSS_EML.replace(b"Subject:", f"X-N: {secrets.token_hex(4)}\r\nSubject:".encode(), 1))
    r = _html(analyst, up["id"])
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/html")
    assert r.headers["content-disposition"].startswith('attachment; filename="forensic-report-')
    assert "default-src 'none'" in r.headers["content-security-policy"]
    assert "script-src 'none'" in r.headers["content-security-policy"]
    assert r.headers["x-content-type-options"] == "nosniff"
    html = r.text
    assert remote_refs(html) == []
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html                       # subject escaped
    assert "&lt;img src=x onerror=alert(1)&gt;" in html                          # display name escaped
    assert "onerror=alert(1)>" not in html and "<svg" not in html
    assert anon_client.get(f"/api/v1/analyses/{up['id']}/report.html").status_code == 401
    assert analyst.get("/api/v1/analyses/nope/report.html").status_code == 404


def test_render_escapes_provider_llm_and_hostname_strings():
    from app.reports.html import render_report_html
    run = {"run_id": "r1", "version": 1, "simulated": True, "consent": {"granted": True, "providers": ["abuseipdb"]},
           "counts": {}, "indicators": [{"indicator": "<b>1.2.3.4</b>", "indicator_type": "ip", "state": "looked_up",
                                         "results": [{"provider": "abuseipdb", "provider_label": EVIL, "status": "no_record",
                                                      "cache_state": "stale", "fetched_at": "2026-11-01T00:00:00Z",
                                                      "message": EVIL, "data": {"isp": EVIL}}]}],
           "disclaimer": "d"}
    assessment = {"version": 1, "assessment_id": "a1", "ml": {"status": "ok", "label": "phishing", "confidence": 0.9,
                                                               "probabilities": {"phishing": 0.9}},
                  "explanation": {"status": "unavailable", "reason": EVIL},
                  "forensic_summary": {"status": "ok", "summary": EVIL, "assessment": EVIL,
                                       "findings": [{"statement": EVIL, "evidence_ids": ["E1"], "basis": "verified"}],
                                       "recommendations": [{"kind": "general", "text": EVIL, "origin": "model"}],
                                       "evidence": [{"id": "E1", "category": "verified", "source": EVIL, "statement": EVIL}]}}
    forensics = {"relay_chain": [{"index": 0, "from_host": "<b>evil.host</b>", "from_ip": "198.51.100.7",
                                  "by_host": EVIL, "trusted": False, "confidence": 0.5}]}
    html = render_report_html({"report_id": "R", "view_notes": [], "case_dict": {}, "detection": {}, "forensics": forensics,
                               "auth": {}, "enrichment": {}, "integrity": {"result": "unavailable"},
                               "analysis_row": {"sha256": "f" * 64, "subject": EVIL}, "intel": run,
                               "assessment": assessment, "correlation": None, "attack": None, "risk": None},
                              iocs={"urls": [], "attachments": [], "redacted": False}, geo=None,
                              custody={"guarantee": "g", "integrity_note": "n"})
    assert EVIL not in html and "<b>evil.host</b>" not in html and "<b>1.2.3.4</b>" not in html
    assert remote_refs(html) == [] and html.count("&lt;script&gt;") >= 8
    assert "SIMULATED" in html and "STALE cache" in html and "not proof of safety" in html
    assert "SHAP covers only the explained component" in html


def test_masked_view_parity_redaction_permissions_and_audit(analyst, viewer):
    up = _upload(analyst, _nonce("demo/bec_wire_change.eml"))
    full = _html(analyst, up["id"]).text
    masked = _html(viewer, up["id"]).text
    assert "dana@internal-corp.example" in full and "Dana Finance Director" in full
    assert "MASKED VIEW" in masked and "MASKED VIEW" not in full
    for pii in ("dana@internal-corp.example", "finance-team@internal-corp.example", "Dana Finance Director"):
        assert pii not in masked
    with dbmod.SessionLocal() as db:
        evs = db.query(AuditEvent).filter_by(event_type="report_generated", analysis_id=up["id"]).order_by(AuditEvent.seq).all()
        assert [e.detail["format"] for e in evs] == ["html", "html"]
        assert [e.detail["masked"] for e in evs] == [False, True]
        assert all(e.actor_user_id for e in evs) and evs[0].detail["risk_version"] == 1
        from app.retention import service as retention
        retention.redact_analysis(db, db.get(Analysis, up["id"]))
        db.commit()
    red = _html(analyst, up["id"]).text
    assert "Content redacted per retention policy" in red and "Parser cross-check: redacted per retention policy." in red
    assert "dana@internal-corp.example" not in red


def test_version_pinning_and_pdf_parity(analyst):
    from tests.unit.test_risk import _pdf_text
    up = _upload(analyst, _nonce("demo/bec_wire_change.eml"))
    v1 = analyst.get(f"/api/v1/analyses/{up['id']}/risk").json()
    with dbmod.SessionLocal() as db:
        probs = {"legitimate": 0.97, "suspicious": 0.0, "impersonated": 0.0, "phishing": 0.03, "fraud": 0.0}
        db.add(MlClassification(analysis_id=up["id"], source="upload", status="ok", model_version="t@1", created_at=utcnow(),
                                result_json={"status": "ok", "label": "legitimate", "confidence": 0.97, "probabilities": probs}))
        db.commit()
    analyst.post(f"/api/v1/analyses/{up['id']}/risk/recompute")
    pinned = _html(analyst, up["id"], risk_id=v1["risk_id"]).text
    latest = _html(analyst, up["id"]).text
    assert "(version 1," in pinned and "(version 2," in latest and "conflicting_signals" in latest
    assert _html(analyst, up["id"], risk_id="nope").status_code == 404
    assert _html(analyst, up["id"], intel_run_id="nope").status_code == 404
    case = analyst.post(f"/api/v1/investigations/from-analysis/{up['id']}").json()
    from reportlab import rl_config
    old, rl_config.pageCompression = rl_config.pageCompression, 0
    try:
        pdf = _pdf_text(analyst.get(f"/api/v1/investigations/{case['id']}/report/{up['id']}",
                                    params={"risk_id": v1["risk_id"]}).content)
    finally:
        rl_config.pageCompression = old
    att = analyst.get(f"/api/v1/analyses/{up['id']}/attack").json()
    for key in ("PHISHING_FRAUD_LIKELY", "100/100", "CRITICAL", *[m["technique_id"] for m in att["mappings"]]):
        assert key in pdf.upper() and key in pinned.upper(), key
    assert "Parser cross-check" in pdf and "AGREE" in pdf


def test_simulated_and_stale_intel_labels_in_html(analyst):
    up = _upload(analyst, _nonce("eml/multihop_auth.eml"))
    with dbmod.SessionLocal() as db:
        db.add(ThreatIntelRun(analysis_id=up["id"], version=1, consent_granted=True, consent_source="on_demand",
                              providers_requested=["abuseipdb"], offline=False, created_at=utcnow(), result_json={
                                  "consent": {"granted": True, "providers": ["abuseipdb"]}, "simulated": True,
                                  "counts": {"total": 1}, "disclaimer": "Informational only.",
                                  "indicators": [{"indicator": "96.7.128.175", "indicator_type": "ip", "state": "looked_up",
                                                  "results": [{"provider": "abuseipdb", "status": "no_record",
                                                               "cache_state": "stale", "fetched_at": "2026-11-01T00:00:00Z"}]}]}))
        db.commit()
    html = _html(analyst, up["id"]).text
    assert "SIMULATED" in html and "STALE cache" in html and "No record / no reports (not proof of safety)" in html
