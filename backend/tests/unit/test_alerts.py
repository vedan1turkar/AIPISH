"""P5f: risk-based alerts — rules, dedupe/lifecycle, transitions, campaigns, privacy, e-mail, retention, API.

Uses the shared test database (SQLite by default, PostgreSQL with TEST_DATABASE_URL / make test-pg).
E-mail tests use an in-process fake SMTP server on 127.0.0.1; nothing is sent over a real network."""
from __future__ import annotations

import json
import logging
import os
import secrets
import socket
import socketserver
import ssl
import threading
from datetime import timedelta

import pytest

import app.alerts.service as alerts
from app.alerts import notify
from app.alerts.config import get_alert_config
from app.core import db as dbmod
from app.core.models import (
    Alert, AlertEvent, Analysis, AuditEvent, Campaign, CampaignMember, MlClassification, RiskAssessment, utcnow,
)
from app.main import create_app
from tests.authutil import authed_client

FIX = os.path.join(os.path.dirname(__file__), "..", "fixtures")
BEC = "demo/bec_wire_change.eml"
PII = ("dana@internal-corp.example", "finance-team@internal-corp.example", "dana.doe.personal+urgent@fastmail-temp.net",
       "Dana Finance Director", "please action before end of day", "Confidential: urgent supplier wire change",
       "internal-corp.example", "fastmail-temp.net")


def _copy(name: str) -> bytes:
    data = open(os.path.join(FIX, name), "rb").read()
    return data.replace(b"Subject:", f"X-Test-Nonce: {secrets.token_hex(6)}\r\nSubject:".encode(), 1)


def _upload(client, data: bytes) -> dict:
    r = client.post("/api/v1/analyses", files={"file": ("m.eml", data, "message/rfc822")})
    assert r.status_code == 201, r.text
    return r.json()


def _alerts(aid: str, type_: str | None = None) -> list[Alert]:
    with dbmod.SessionLocal() as db:
        q = db.query(Alert).filter(Alert.analysis_id == aid)
        if type_:
            q = q.filter(Alert.type == type_)
        rows = q.order_by(Alert.created_at).all()
        db.expunge_all()
        return rows


def _by_key(key: str) -> list[Alert]:
    with dbmod.SessionLocal() as db:
        rows = db.query(Alert).filter(Alert.dedupe_key == key).order_by(Alert.created_at).all()
        db.expunge_all()
        return rows


def _events(alert_id: str) -> list[str]:
    with dbmod.SessionLocal() as db:
        return [e.action for e in db.query(AlertEvent).filter_by(alert_id=alert_id).order_by(AlertEvent.created_at).all()]


def _store_ml(aid: str, p: float):
    legit = round(1 - p, 4)
    probs = {"legitimate": legit, "suspicious": 0.0, "impersonated": 0.0, "phishing": round(p, 4), "fraud": 0.0}
    top = max(probs, key=probs.get)
    with dbmod.SessionLocal() as db:
        db.add(MlClassification(analysis_id=aid, source="upload", status="ok", model_version="t@1", created_at=utcnow(),
                                result_json={"status": "ok", "label": top, "confidence": probs[top], "probabilities": probs}))
        db.commit()


MACRO = (b"From: Accounts <ap@vendor-billing.example>\r\nTo: you@corp.example\r\nSubject: Invoice\r\n"
         b"Message-ID: <NONCE@x>\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=B\r\n\r\n"
         b"--B\r\nContent-Type: text/plain\r\n\r\nPlease see the attached invoice.\r\n"
         b"--B\r\nContent-Type: application/vnd.ms-word.document.macroEnabled.12\r\n"
         b"Content-Disposition: attachment; filename=\"invoice.docm\"\r\nContent-Transfer-Encoding: base64\r\n\r\n"
         b"UEsDBAoAAAAAAA==\r\n--B--\r\n")


def _macro() -> bytes:
    return MACRO.replace(b"NONCE", secrets.token_hex(6).encode())


@pytest.fixture
def analyst():
    return authed_client(create_app(), "analyst")


@pytest.fixture
def viewer():
    return authed_client(create_app(), "viewer")


@pytest.fixture
def admin():
    return authed_client(create_app(), "admin")


@pytest.fixture(autouse=True)
def _clean_mail_env(monkeypatch):
    for k in list(os.environ):
        if k.startswith(("ALERT", "APP_BASE_URL")):
            monkeypatch.delenv(k, raising=False)
    notify.reset_rate_limit()
    yield
    notify.wait_idle(10)


# ── rules ─────────────────────────────────────────────────────────────────
def test_bec_raises_one_critical_high_risk_alert_and_rules_unchanged(analyst):
    up = _upload(analyst, _copy(BEC))
    assert up["detection"]["score"] == 100 and up["detection"]["verdict"] == "phishing_fraud_likely"
    rows = _alerts(up["id"])
    assert [(a.type, a.severity, a.status) for a in rows] == [("high_risk_analysis", "critical", "new")]
    s = rows[0].summary_json
    assert s["combined_level"] == "critical" and s["combined_score"] == 100 and s["rule_verdict"] == "phishing_fraud_likely"
    assert "H3_payment_or_credential_with_identity" in s["floors"] and rows[0].risk_id
    assert _events(rows[0].id) == ["raised"]


def test_legitimate_sample_raises_nothing(analyst):
    up = _upload(analyst, _copy("demo/legitimate_invoice.eml"))
    assert _alerts(up["id"]) == []


def test_floor_alert_when_level_below_minimum(analyst, monkeypatch):
    monkeypatch.setenv("ALERT_MIN_LEVEL", "critical")
    up = _upload(analyst, _macro())
    rows = _alerts(up["id"])
    assert [(a.type, a.severity) for a in rows] == [("hard_evidence_floor", "high")]
    assert "H1_risky_attachment" in rows[0].summary_json["floors"]
    monkeypatch.setenv("ALERT_FLOOR_ENABLED", "0")
    up2 = _upload(analyst, _macro())
    assert _alerts(up2["id"]) == []


def test_conflict_alert_configurable(analyst, monkeypatch):
    up = _upload(analyst, _copy("demo/legitimate_invoice.eml"))
    _store_ml(up["id"], 0.92)
    analyst.post(f"/api/v1/analyses/{up['id']}/risk/recompute")
    types = {(a.type, a.severity) for a in _alerts(up["id"])}
    assert types == {("high_risk_analysis", "critical"), ("review_conflict", "low")}
    monkeypatch.setenv("ALERT_CONFLICT_ENABLED", "0")
    up2 = _upload(analyst, _copy("demo/legitimate_invoice.eml"))
    _store_ml(up2["id"], 0.92)
    analyst.post(f"/api/v1/analyses/{up2['id']}/risk/recompute")
    assert {a.type for a in _alerts(up2["id"])} == {"high_risk_analysis"}


def test_global_disable_flag(analyst, monkeypatch):
    monkeypatch.setenv("ALERTS_ENABLED", "0")
    up = _upload(analyst, _copy(BEC))
    assert _alerts(up["id"]) == []


# ── dedupe and lifecycle ──────────────────────────────────────────────────
def test_identical_reupload_increments_occurrence_only(analyst):
    data = _copy(BEC)
    a1, a2 = _upload(analyst, data), _upload(analyst, data)
    assert a1["sha256"] == a2["sha256"] and a1["id"] != a2["id"]
    rows = _by_key(f"high_risk_analysis:{a1['sha256']}")
    assert len(rows) == 1 and rows[0].occurrence_count == 2 and rows[0].status == "new"
    assert rows[0].summary_json["analysis_ids"] == [a1["id"], a2["id"]]
    assert _events(rows[0].id) == ["raised", "occurrence"]


def test_escalation_reopens_acknowledged(analyst):
    up = _upload(analyst, _macro())
    [a] = _alerts(up["id"], "high_risk_analysis")
    assert a.severity == "high"
    assert analyst.post(f"/api/v1/alerts/{a.id}/acknowledge").json()["status"] == "acknowledged"
    _store_ml(up["id"], 0.97)
    analyst.post(f"/api/v1/analyses/{up['id']}/risk/recompute")
    [b] = _alerts(up["id"], "high_risk_analysis")
    assert b.id == a.id and b.severity == "critical" and b.status == "new" and b.acknowledged_by is None
    assert _events(a.id)[-1] == "escalated"


def test_lower_level_never_auto_resolves(analyst):
    up = _upload(analyst, _copy(BEC))
    [a] = _alerts(up["id"], "high_risk_analysis")
    _store_ml(up["id"], 0.03)                      # rules high vs ML legitimate: H3 floor keeps it at high
    analyst.post(f"/api/v1/analyses/{up['id']}/risk/recompute")
    analyst.post(f"/api/v1/analyses/{up['id']}/risk/recompute")
    [b] = _alerts(up["id"], "high_risk_analysis")
    assert b.status == "new" and b.severity == "critical"
    assert _events(a.id).count("level_lowered") == 1
    assert len(_alerts(up["id"], "review_conflict")) == 1


def test_resolved_same_level_no_new_alert_higher_level_opens_new(analyst):
    up = _upload(analyst, _macro())
    [a] = _alerts(up["id"], "high_risk_analysis")
    r = analyst.post(f"/api/v1/alerts/{a.id}/resolve", json={"note": "benign vendor macro, verified by phone"})
    assert r.status_code == 200 and r.json()["status"] == "resolved"
    analyst.post(f"/api/v1/analyses/{up['id']}/risk/recompute")
    assert len(_alerts(up["id"], "high_risk_analysis")) == 1
    _store_ml(up["id"], 0.97)
    analyst.post(f"/api/v1/analyses/{up['id']}/risk/recompute")
    rows = _alerts(up["id"], "high_risk_analysis")
    assert [(x.status, x.severity) for x in rows] == [("resolved", "high"), ("new", "critical")]
    assert "supersedes" in _events(rows[1].id)


def test_invalid_transitions_and_reopen_conflict(analyst):
    up = _upload(analyst, _macro())
    [a] = _alerts(up["id"], "high_risk_analysis")
    assert analyst.post(f"/api/v1/alerts/{a.id}/resolve").status_code == 400          # note required
    assert analyst.post(f"/api/v1/alerts/{a.id}/resolve", json={"note": "x" * 1001}).status_code == 400
    assert analyst.post(f"/api/v1/alerts/{a.id}/reopen").status_code == 409            # new -> reopen invalid
    assert analyst.post(f"/api/v1/alerts/{a.id}/resolve", json={"note": "ok"}).status_code == 200
    assert analyst.post(f"/api/v1/alerts/{a.id}/acknowledge").json()["error"]["code"] == "INVALID_TRANSITION"
    stale = analyst.post(f"/api/v1/alerts/{a.id}/reopen", json={"version": 1})
    assert stale.status_code == 409 and stale.json()["error"]["code"] == "CONFLICT"
    _store_ml(up["id"], 0.97)
    analyst.post(f"/api/v1/analyses/{up['id']}/risk/recompute")                   # opens a new active alert
    r = analyst.post(f"/api/v1/alerts/{a.id}/reopen")
    assert r.status_code == 409 and r.json()["error"]["code"] == "ACTIVE_ALERT_EXISTS"
    assert analyst.post("/api/v1/alerts/nope/acknowledge").status_code == 404


def test_concurrent_transitions_exactly_one_wins(analyst):
    up = _upload(analyst, _macro())
    [a] = _alerts(up["id"], "high_risk_analysis")
    results, barrier = [], threading.Barrier(2)

    def worker(action, note):
        db = dbmod.SessionLocal()
        try:
            barrier.wait(5)
            alerts.transition(db, a.id, action, None, note, expected_version=a.version)
            results.append("ok")
        except alerts.TransitionError as exc:
            results.append(exc.code)
        except Exception as exc:  # noqa: BLE001 - e.g. SQLite busy
            results.append(type(exc).__name__)
        finally:
            db.close()
    ts = [threading.Thread(target=worker, args=("acknowledge", None)),
          threading.Thread(target=worker, args=("resolve", "done"))]
    [t.start() for t in ts]
    [t.join(20) for t in ts]
    assert results.count("ok") == 1 and len(results) == 2, results
    with dbmod.SessionLocal() as db:
        assert db.get(Alert, a.id).version == a.version + 1


# ── campaigns ─────────────────────────────────────────────────────────────
def _campaign(db, confidence: str, members: int) -> Campaign:
    n = (db.query(Campaign.number).order_by(Campaign.number.desc()).first() or (0,))[0] + 1000 + secrets.randbelow(10_000)
    c = Campaign(number=n, label=f"Candidate campaign T-{n}", status="candidate", confidence=confidence,
                 confidence_score=0.5, reasons={}, fingerprint=secrets.token_hex(8), version=1)
    db.add(c)
    db.flush()
    for _ in range(members):
        db.add(CampaignMember(campaign_id=c.id, analysis_id=secrets.token_hex(16)))
    db.commit()
    return c


def test_campaign_new_and_growth_debounced():
    cfg0 = get_alert_config()
    import dataclasses
    with dbmod.SessionLocal() as db:
        low, med = _campaign(db, "low", 2), _campaign(db, "medium", 3)
        alerts.evaluate_campaigns(db, "test", dataclasses.replace(cfg0, growth_debounce_minutes=0))
        db.commit()
        assert _by_key(f"new_campaign:{low.id}") == []
        [new] = _by_key(f"new_campaign:{med.id}")
        assert new.severity == "medium" and new.summary_json["member_count"] == 3
        assert set(new.summary_json) == {"campaign_id", "campaign_label", "campaign_confidence", "member_count"}
        alerts.evaluate_campaigns(db, "test", dataclasses.replace(cfg0, growth_debounce_minutes=0))
        db.commit()
        assert _by_key(f"campaign_growth:{med.id}") == []                    # no growth, nothing
        db.add(CampaignMember(campaign_id=med.id, analysis_id=secrets.token_hex(16)))
        db.commit()
        alerts.evaluate_campaigns(db, "test", dataclasses.replace(cfg0, growth_debounce_minutes=60))
        db.commit()
        assert _by_key(f"campaign_growth:{med.id}") == []                    # debounced (alert is fresh)
        alerts.evaluate_campaigns(db, "test", dataclasses.replace(cfg0, growth_debounce_minutes=0))
        db.commit()
        [g] = _by_key(f"campaign_growth:{med.id}")
        assert g.summary_json["member_count"] == 4 and g.summary_json["previous_member_count"] == 3
        for _ in range(3):                                                  # repeated passes never flood
            db.add(CampaignMember(campaign_id=med.id, analysis_id=secrets.token_hex(16)))
            db.commit()
            alerts.evaluate_campaigns(db, "test", dataclasses.replace(cfg0, growth_debounce_minutes=0))
            db.commit()
        rows = _by_key(f"campaign_growth:{med.id}")
        assert len(rows) == 1 and rows[0].occurrence_count == 4


def test_campaign_alert_through_the_real_pipeline(analyst):
    for i in range(1, 4):
        _upload(analyst, open(os.path.join(FIX, "demo", "campaign", f"campaign_member_{i}.eml"), "rb").read())
    with dbmod.SessionLocal() as db:
        camps = db.query(Campaign).filter(Campaign.status == "candidate", Campaign.confidence.in_(("medium", "high"))).all()
        assert camps
        assert all(db.query(Alert).filter_by(dedupe_key=f"new_campaign:{c.id}").count() == 1 for c in camps)


def test_backfill_creates_no_alerts_by_default(analyst):
    up = _upload(analyst, _copy(BEC))
    with dbmod.SessionLocal() as db:
        db.query(AlertEvent).filter(AlertEvent.analysis_id == up["id"]).delete()
        db.query(Alert).filter(Alert.analysis_id == up["id"]).delete()
        db.query(RiskAssessment).filter(RiskAssessment.analysis_id == up["id"]).delete()
        db.commit()
        before = db.query(Alert).count()
        from app.risk.service import backfill
        backfill(db)
        assert db.query(Alert).count() == before
        backfill(db, alerts=True)
        assert db.query(Alert).filter(Alert.analysis_id == up["id"]).count() == 1


# ── failure isolation ─────────────────────────────────────────────────────
def test_alert_engine_failure_never_alters_upload_or_risk(analyst, monkeypatch):
    data = _copy(BEC)
    ok = _upload(analyst, data)

    def boom(*a, **k):
        raise RuntimeError("forced")
    monkeypatch.setattr(alerts, "evaluate_analysis", boom)
    monkeypatch.setattr(alerts, "evaluate_campaigns", boom)
    bad = _upload(analyst, data)
    strip = lambda d: {k: v for k, v in d.items() if k not in ("id", "created_at")}  # noqa: E731
    assert strip(bad) == strip(ok)
    r_ok = analyst.get(f"/api/v1/analyses/{ok['id']}/risk").json()
    r_bad = analyst.get(f"/api/v1/analyses/{bad['id']}/risk").json()
    assert (r_bad["level"], r_bad["combined_score"]) == (r_ok["level"], r_ok["combined_score"])
    assert analyst.post(f"/api/v1/analyses/{bad['id']}/risk/recompute").status_code == 200
    with dbmod.SessionLocal() as db:
        assert db.query(AuditEvent).filter_by(event_type="alert_engine_error").count() >= 2


# ── API and permissions ───────────────────────────────────────────────────
def test_api_permissions_filters_summary_and_audit(analyst, viewer, admin, anon_client):
    up = _upload(analyst, _copy(BEC))
    [a] = _alerts(up["id"])
    assert anon_client.get("/api/v1/alerts").status_code == 401
    assert anon_client.get("/api/v1/alerts/summary").status_code == 401
    lst = viewer.get("/api/v1/alerts", params={"analysis_id": up["id"]}).json()
    assert lst["total"] == 1 and lst["items"][0]["id"] == a.id and "real time" in lst["note"]
    assert viewer.get("/api/v1/alerts", params={"severity": "critical", "type": "high_risk_analysis",
                                                "status": "open", "page_size": 5}).json()["page_size"] == 5
    assert viewer.get("/api/v1/alerts", params={"page_size": 101}).status_code == 400
    assert viewer.get("/api/v1/alerts", params={"type": "nope"}).status_code == 400
    s = viewer.get("/api/v1/alerts/summary").json()
    assert s["new"] >= 1 and set(s["by_status"]) == {"new", "acknowledged", "resolved"}
    d = viewer.get(f"/api/v1/alerts/{a.id}").json()
    assert d["history"][0]["action"] == "raised" and d["analysis_redacted"] is False
    assert viewer.post(f"/api/v1/alerts/{a.id}/acknowledge").status_code == 403
    assert viewer.get("/api/v1/admin/alerts/config").status_code == 403
    assert analyst.get("/api/v1/admin/alerts/config").status_code == 403
    r = analyst.post(f"/api/v1/alerts/{a.id}/acknowledge", json={"note": "looking"})
    assert r.status_code == 200 and r.json()["acknowledged_by"].startswith("t-analyst")
    assert r.json()["history"][-1]["actor"].startswith("t-analyst")
    with dbmod.SessionLocal() as db:
        ev = db.query(AuditEvent).filter_by(event_type="alert_acknowledged", target_id=a.id).one()
        assert ev.actor_user_id and ev.detail["from_state"] == "new" and ev.detail["to_state"] == "acknowledged"
    cfg = admin.get("/api/v1/admin/alerts/config").json()
    assert cfg["email"]["enabled"] is False and "smtp_password" not in json.dumps(cfg).replace("smtp_password_set", "")


def test_admin_config_never_returns_secrets(admin, monkeypatch):
    pw, user = secrets.token_urlsafe(18), "mailer-" + secrets.token_hex(4)      # generated: no literal secret
    monkeypatch.setenv("ALERT_SMTP_PASSWORD", pw)
    monkeypatch.setenv("ALERT_SMTP_USERNAME", user)
    txt = admin.get("/api/v1/admin/alerts/config").text
    assert pw not in txt and user not in txt
    assert json.loads(txt)["email"]["smtp_password_set"] is True


# ── privacy ───────────────────────────────────────────────────────────────
def test_alerts_events_audit_and_email_hold_no_message_content(analyst, viewer):
    up = _upload(analyst, _copy(BEC))
    [a] = _alerts(up["id"])
    analyst.post(f"/api/v1/alerts/{a.id}/acknowledge")
    blobs = [viewer.get(f"/api/v1/alerts/{a.id}").text, viewer.get("/api/v1/alerts", params={"analysis_id": up["id"]}).text]
    with dbmod.SessionLocal() as db:
        alert = db.get(Alert, a.id)
        blobs.append(json.dumps({"title": alert.title, "summary": alert.summary_json}))
        blobs += [json.dumps(e.detail_json) for e in db.query(AlertEvent).filter_by(alert_id=a.id).all()]
        blobs += [json.dumps(e.detail) for e in db.query(AuditEvent).filter_by(target_type="alert", target_id=a.id).all()]
        cfg = get_alert_config()
        subject, text, html = notify.render(alert, cfg)
        blobs += [subject, text, html]
    for blob in blobs:
        for bad in PII:
            assert bad not in blob, bad


# ── e-mail (fake in-process SMTP; no network) ─────────────────────────────
class _SMTPHandler(socketserver.StreamRequestHandler):
    def handle(self):
        srv = self.server
        w = lambda s: self.wfile.write((s + "\r\n").encode())  # noqa: E731
        w("220 fake.local ESMTP")
        data, in_data = [], False
        while True:
            line = self.rfile.readline()
            if not line:
                return
            text = line.decode("utf-8", "replace").rstrip("\r\n")
            if in_data:
                if text == ".":
                    in_data = False
                    srv.messages.append({"rcpt": list(srv.rcpt), "data": "\r\n".join(data)})
                    data.clear()
                    w("250 OK queued")
                else:
                    data.append(text[1:] if text.startswith("..") else text)
                continue
            cmd = text.upper()
            if cmd.startswith(("EHLO", "HELO")):
                w("250-fake.local")
                w("250 8BITMIME")
            elif cmd.startswith("MAIL FROM"):
                srv.rcpt = []
                w("250 OK")
            elif cmd.startswith("RCPT TO"):
                srv.rcpt.append(text.split(":", 1)[1].strip())
                w("250 OK")
            elif cmd == "DATA":
                in_data = True
                w("354 go ahead")
            elif cmd == "QUIT":
                w("221 bye")
                return
            else:
                w("250 OK")


@pytest.fixture
def smtp_sink(monkeypatch):
    class Srv(socketserver.ThreadingTCPServer):
        allow_reuse_address = True
        daemon_threads = True
    srv = Srv(("127.0.0.1", 0), _SMTPHandler)
    srv.messages, srv.rcpt = [], []
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    monkeypatch.setenv("ALERT_EMAIL_ENABLED", "1")
    monkeypatch.setenv("ALERT_SMTP_HOST", "127.0.0.1")
    monkeypatch.setenv("ALERT_SMTP_PORT", str(srv.server_address[1]))
    monkeypatch.setenv("ALERT_SMTP_SECURITY", "none")
    monkeypatch.setenv("ALERT_EMAIL_FROM", "aipish-alerts@example.test")
    monkeypatch.setenv("ALERT_EMAIL_TO", "soc@example.test,lead@example.test")
    monkeypatch.setenv("ALERT_SMTP_TIMEOUT_SECONDS", "5")
    monkeypatch.setenv("APP_BASE_URL", "https://aipish.example.test")
    yield srv
    srv.shutdown()
    srv.server_close()


def _delivery(alert_id: str) -> dict:
    with dbmod.SessionLocal() as db:
        return (db.get(Alert, alert_id).delivery_json or {}).get("email") or {}


@pytest.mark.enable_socket
@pytest.mark.allow_hosts(["127.0.0.1"])
def test_email_sent_with_limited_content_and_no_email_on_occurrence(analyst, smtp_sink):
    data = _copy(BEC)
    up = _upload(analyst, data)
    notify.wait_idle(15)
    [a] = _alerts(up["id"])
    assert _delivery(a.id)["status"] == "sent"
    assert len(smtp_sink.messages) == 1
    m = smtp_sink.messages[0]
    assert sorted(m["rcpt"]) == ["<lead@example.test>", "<soc@example.test>"]
    raw = m["data"]
    import email
    msg = email.message_from_string(raw)
    assert msg["Subject"] == f"[AIPISH] CRITICAL alert: High-risk analysis ({a.id[:8]})"
    text = msg.get_payload()[0].get_payload(decode=True).decode()
    html = msg.get_payload()[1].get_payload(decode=True).decode()
    for body in (text, html):
        assert a.id in body and up["id"] in body and "critical 100/100" in body
        assert "phishing_fraud_likely" in body and "H3_payment_or_credential_with_identity" in body
        assert f"https://aipish.example.test/#alerts/{a.id}" in body
        assert "does not monitor mailboxes in real time" in body
        for bad in PII:
            assert bad not in body
    with dbmod.SessionLocal() as db:
        assert db.query(AuditEvent).filter_by(event_type="alert_email_sent", target_id=a.id).count() == 1
    _upload(analyst, data)                                 # occurrence increment: no new email
    notify.wait_idle(15)
    assert len(smtp_sink.messages) == 1


@pytest.mark.enable_socket
@pytest.mark.allow_hosts(["127.0.0.1"])
def test_email_escalation_sends_once_per_state_change(analyst, smtp_sink):
    up = _upload(analyst, _macro())
    notify.wait_idle(15)
    assert len(smtp_sink.messages) == 1                       # high >= default min severity (high)
    _store_ml(up["id"], 0.97)
    analyst.post(f"/api/v1/analyses/{up['id']}/risk/recompute")
    analyst.post(f"/api/v1/analyses/{up['id']}/risk/recompute")
    notify.wait_idle(15)
    assert len(smtp_sink.messages) == 2                       # escalation once, not per recompute


def test_email_below_threshold_disabled_and_not_configured(analyst, monkeypatch):
    up = _upload(analyst, _copy(BEC))
    [a] = _alerts(up["id"])
    assert _delivery(a.id)["status"] == "disabled"
    monkeypatch.setenv("ALERT_EMAIL_ENABLED", "1")
    assert notify.dispatch(a.id, "x1") == "not_configured"
    monkeypatch.setenv("ALERT_SMTP_HOST", "127.0.0.1")
    monkeypatch.setenv("ALERT_EMAIL_FROM", "a@example.test")
    monkeypatch.setenv("ALERT_EMAIL_TO", "b@example.test")
    monkeypatch.setenv("ALERT_EMAIL_MIN_SEVERITY", "critical")
    with dbmod.SessionLocal() as db:
        db.get(Alert, a.id).severity = "high"
        db.commit()
    assert notify.dispatch(a.id, "x2") == "below_threshold"


@pytest.mark.enable_socket
@pytest.mark.allow_hosts(["127.0.0.1"])
def test_smtp_down_is_isolated_and_secrets_never_logged(analyst, monkeypatch, caplog):
    pw, user = secrets.token_urlsafe(18), "u-" + secrets.token_hex(4)       # generated: no literal secret
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()                                                   # nothing listens here
    for k, v in {"ALERT_EMAIL_ENABLED": "1", "ALERT_SMTP_HOST": "127.0.0.1", "ALERT_SMTP_PORT": str(port),
                 "ALERT_SMTP_SECURITY": "none", "ALERT_EMAIL_FROM": "a@example.test", "ALERT_EMAIL_TO": "b@example.test",
                 "ALERT_SMTP_USERNAME": user, "ALERT_SMTP_PASSWORD": pw,
                 "ALERT_SMTP_TIMEOUT_SECONDS": "2"}.items():
        monkeypatch.setenv(k, v)
    caplog.set_level(logging.DEBUG)
    up = _upload(analyst, _copy(BEC))
    notify.wait_idle(20)
    [a] = _alerts(up["id"])
    d = _delivery(a.id)
    assert d["status"] == "failed" and "SMTP delivery failed" in d["reason"]
    with dbmod.SessionLocal() as db:
        audit = [json.dumps(e.detail) for e in db.query(AuditEvent).filter_by(target_id=a.id).all()]
    for blob in (caplog.text, json.dumps(d), *audit):
        assert pw not in blob and user not in blob


@pytest.mark.enable_socket
@pytest.mark.allow_hosts(["127.0.0.1"])
def test_rate_limit_and_header_injection(analyst, smtp_sink, monkeypatch):
    monkeypatch.setenv("ALERT_EMAIL_MAX_PER_MINUTE", "1")
    a1 = _upload(analyst, _copy(BEC))
    a2 = _upload(analyst, _copy(BEC))
    notify.wait_idle(15)
    s1, s2 = _delivery(_alerts(a1["id"])[0].id)["status"], _delivery(_alerts(a2["id"])[0].id)["status"]
    assert sorted((s1, s2)) == ["rate_limited", "sent"] and len(smtp_sink.messages) == 1
    with pytest.raises(notify.UnsafeHeader):
        notify.safe_header("x\r\nBcc: evil@example.test")
    notify.reset_rate_limit()
    monkeypatch.setenv("ALERT_EMAIL_MAX_PER_MINUTE", "10")
    monkeypatch.setenv("ALERT_EMAIL_FROM", "a@example.test\r\nBcc: evil@example.test")
    a3 = _upload(analyst, _copy(BEC))
    notify.wait_idle(15)
    d = _delivery(_alerts(a3["id"])[0].id)
    assert d["status"] == "failed" and "could not be built" in d["reason"]
    assert all("evil@example.test" not in json.dumps(m) for m in smtp_sink.messages)


def test_template_autoescape_and_tls_defaults():
    a = Alert(id="a" * 32, type="new_campaign", severity="medium", status="new", title="t",
              summary_json={"campaign_label": "<script>x</script>", "campaign_confidence": "medium", "member_count": 3})
    _s, text, html = notify.render(a, get_alert_config())
    assert "<script>" not in html and "&lt;script&gt;" in html
    ctx = notify.tls_context()
    assert ctx.verify_mode == ssl.CERT_REQUIRED and ctx.check_hostname is True


# ── retention ─────────────────────────────────────────────────────────────
def test_retention_delete_removes_alerts_redact_keeps_them(analyst, viewer):
    from app.retention import service as retention
    assert Alert in retention.dependent_models() and AlertEvent in retention.dependent_models()
    gone = _upload(analyst, _copy(BEC))
    kept = _upload(analyst, _copy(BEC))
    [ga], [ka] = _alerts(gone["id"]), _alerts(kept["id"])
    analyst.post(f"/api/v1/alerts/{ga.id}/acknowledge")
    with dbmod.SessionLocal() as db:
        retention.delete_analysis(db, db.get(Analysis, gone["id"]))
        retention.redact_analysis(db, db.get(Analysis, kept["id"]))
        db.commit()
        assert db.query(Alert).filter_by(id=ga.id).count() == 0
        assert db.query(AlertEvent).filter_by(alert_id=ga.id).count() == 0
        assert db.query(AlertEvent).filter(AlertEvent.analysis_id == gone["id"]).count() == 0
        assert db.query(AuditEvent).filter_by(target_id=ga.id).count() >= 2        # audit is never purged
    d = viewer.get(f"/api/v1/alerts/{ka.id}").json()
    assert d["analysis_redacted"] is True and d["status"] == "new"
