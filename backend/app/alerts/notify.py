"""Optional alert email notification (P5f). OFF by default (ALERT_EMAIL_ENABLED=0).

- Content is limited to: alert id, type, severity, status, analysis id or campaign label, combined level and
  score, rule verdict label, ML class label, floors fired, a link and the standard disclaimer. Never message
  subject, body, recipients, addresses, domains or IPs.
- Jinja2 templates (``templates/``) with autoescape ON; stdlib smtplib/email for sending.
- Headers contain only system values (validated against CR/LF); recipients come only from configuration.
- TLS verification is on (ssl.create_default_context) for STARTTLS and SSL.
- Sending runs outside the request path in a daemon thread with a socket timeout and one retry; failures are
  recorded on the alert (delivery status) and audited, never raised. Secrets are never logged or stored.
- At most one email per alert per state change; at most N per minute (in-process window).
"""
from __future__ import annotations

import logging
import smtplib
import ssl
import threading
import time
from collections import deque
from email.message import EmailMessage
from email.utils import formatdate, make_msgid, parseaddr
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, StrictUndefined

from app.alerts.config import SEVERITY_RANK, AlertConfig, get_alert_config
from app.core.models import Alert, utcnow

logger = logging.getLogger(__name__)
DISCLAIMER = ("Alerts are raised when an analysis is processed; this system does not monitor mailboxes in real "
              "time. Scores are investigative indicators (a risk index, not a probability) and never proof of "
              "identity or intent.")
_ENV = Environment(loader=FileSystemLoader(str(Path(__file__).parent / "templates")), autoescape=True,
                   undefined=StrictUndefined, trim_blocks=False, keep_trailing_newline=True)
_lock = threading.Lock()
_sent_times: deque[float] = deque()
_threads: list[threading.Thread] = []
SESSION_FACTORY = None          # tests may replace; defaults to app.core.db.SessionLocal


class UnsafeHeader(ValueError):
    pass


def _session():
    if SESSION_FACTORY is not None:
        return SESSION_FACTORY()
    from app.core.db import SessionLocal
    return SessionLocal()


def safe_header(value: str) -> str:
    if any(c in value for c in "\r\n\0"):
        raise UnsafeHeader("header value contains a line break")
    return value


def _addr(value: str) -> str:
    name, addr = parseaddr(safe_header(value))
    if not addr or "@" not in addr or any(c.isspace() for c in addr):
        raise UnsafeHeader("invalid address in configuration")
    return addr


def alert_context(alert: Alert, cfg: AlertConfig) -> dict:
    from app.alerts.service import TYPE_LABEL
    s = dict(alert.summary_json or {})
    allowed = {k: s.get(k) for k in ("analysis_id", "campaign_label", "campaign_confidence", "member_count",
                                     "combined_level", "combined_score", "rule_verdict", "ml_class", "floors")}
    base = cfg.app_base_url or "http://localhost:8080"
    return {"alert": {"id": alert.id, "severity": alert.severity, "status": alert.status, "type": alert.type},
            "type_label": TYPE_LABEL.get(alert.type, alert.type), "s": allowed,
            "link": f"{base}/#alerts/{alert.id}", "disclaimer": DISCLAIMER}


def render(alert: Alert, cfg: AlertConfig) -> tuple[str, str, str]:
    ctx = alert_context(alert, cfg)
    subject = safe_header(f"[AIPISH] {alert.severity.upper()} alert: {ctx['type_label']} ({alert.id[:8]})")
    return subject, _ENV.get_template("alert_email.txt.j2").render(**ctx), \
        _ENV.get_template("alert_email.html.j2").render(**ctx)


def build_message(alert: Alert, cfg: AlertConfig) -> EmailMessage:
    subject, text, html = render(alert, cfg)
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = _addr(cfg.smtp_from)
    msg["To"] = ", ".join(_addr(a) for a in cfg.email_to)
    msg["Date"] = formatdate(localtime=False)
    msg["Message-ID"] = make_msgid(domain="aipish.local")
    msg.set_content(text)
    msg.add_alternative(html, subtype="html")
    return msg


def tls_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()           # CERT_REQUIRED + hostname checking
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


def send_message(msg: EmailMessage, cfg: AlertConfig) -> None:
    t = cfg.smtp_timeout_seconds
    if cfg.smtp_security == "ssl":
        server: smtplib.SMTP = smtplib.SMTP_SSL(cfg.smtp_host, cfg.smtp_port, timeout=t, context=tls_context())
    else:
        server = smtplib.SMTP(cfg.smtp_host, cfg.smtp_port, timeout=t)
    try:
        server.ehlo()
        if cfg.smtp_security == "starttls":
            server.starttls(context=tls_context())
            server.ehlo()
        if cfg.smtp_username:
            server.login(cfg.smtp_username, cfg.smtp_password)
        server.send_message(msg, from_addr=_addr(cfg.smtp_from), to_addrs=[_addr(a) for a in cfg.email_to])
    finally:
        try:
            server.quit()
        except Exception:  # noqa: BLE001
            pass


def _rate_ok(cfg: AlertConfig) -> bool:
    now = time.monotonic()
    with _lock:
        while _sent_times and now - _sent_times[0] > 60:
            _sent_times.popleft()
        if len(_sent_times) >= cfg.email_max_per_minute:
            return False
        _sent_times.append(now)
        return True


def reset_rate_limit() -> None:
    with _lock:
        _sent_times.clear()


def _set_delivery(alert_id: str, status: str, state_key: str, reason: str | None = None, audit: bool = False) -> None:
    db = _session()
    try:
        a = db.get(Alert, alert_id)
        if a is None:
            return
        a.delivery_json = {**(a.delivery_json or {}),
                           "email": {"status": status, "state_key": state_key, "at": utcnow().isoformat(),
                                     **({"reason": reason} if reason else {})}}
        if audit:
            from app.cases.service import record_audit
            record_audit(db, f"alert_email_{status}", analysis_id=a.analysis_id, target_type="alert", target_id=a.id,
                         outcome="success" if status == "sent" else "failure",
                         detail={"alert_id": a.id, "state_key": state_key, **({"reason": reason} if reason else {})})
        db.commit()
    except Exception as exc:  # noqa: BLE001
        db.rollback()
        logger.warning("could not record alert delivery status (%s)", type(exc).__name__)
    finally:
        db.close()


def _deliver(alert_id: str, state_key: str, cfg: AlertConfig) -> None:
    db = _session()
    try:
        a = db.get(Alert, alert_id)
        if a is None:
            return
        msg = build_message(a, cfg)
    except Exception as exc:  # noqa: BLE001
        db.close()
        _set_delivery(alert_id, "failed", state_key, f"message could not be built ({type(exc).__name__})", audit=True)
        return
    finally:
        try:
            db.close()
        except Exception:  # noqa: BLE001
            pass
    last = None
    for attempt in (1, 2):                       # one retry
        try:
            send_message(msg, cfg)
            _set_delivery(alert_id, "sent", state_key, audit=True)
            return
        except Exception as exc:  # noqa: BLE001 — never propagate; reason is the exception class only
            last = type(exc).__name__
            if attempt == 1:
                time.sleep(1)
    _set_delivery(alert_id, "failed", state_key, f"SMTP delivery failed ({last})", audit=True)


def dispatch(alert_id: str, state_key: str, cfg: AlertConfig | None = None) -> str:
    """Decide and, if applicable, send in the background. Returns the recorded delivery status."""
    cfg = cfg or get_alert_config()
    try:
        db = _session()
        try:
            a = db.get(Alert, alert_id)
            if a is None:
                return "missing"
            prev = (a.delivery_json or {}).get("email") or {}
            if prev.get("state_key") == state_key and prev.get("status") in ("queued", "sent"):
                return "duplicate"                   # one email per alert per state change
            severity = a.severity
        finally:
            db.close()
        if not cfg.email_enabled:
            status = "disabled"
        elif not cfg.email_configured:
            status = "not_configured"
        elif SEVERITY_RANK.get(severity, 0) < SEVERITY_RANK[cfg.email_min_severity]:
            status = "below_threshold"
        elif not _rate_ok(cfg):
            status = "rate_limited"
        else:
            status = "queued"
        _set_delivery(alert_id, status, state_key, audit=status == "rate_limited")
        if status == "queued":
            t = threading.Thread(target=_deliver, args=(alert_id, state_key, cfg), name=f"alert-mail-{alert_id[:8]}",
                                 daemon=True)
            with _lock:
                _threads[:] = [x for x in _threads if x.is_alive()] + [t]
            t.start()
        return status
    except Exception as exc:  # noqa: BLE001
        logger.warning("alert email dispatch failed (%s); alert unaffected", type(exc).__name__)
        return "error"


def wait_idle(timeout: float = 15.0) -> None:
    """Test/CLI helper: wait for queued deliveries to finish."""
    end = time.monotonic() + timeout
    with _lock:
        threads = list(_threads)
    for t in threads:
        t.join(max(0.0, end - time.monotonic()))
