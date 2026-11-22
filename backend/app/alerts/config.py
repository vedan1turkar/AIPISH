"""Alert configuration (P5f). Everything comes from the environment with safe defaults; secrets are never
returned by ``public_dict`` (the admin config endpoint) or logged."""
from __future__ import annotations

from dataclasses import dataclass, field

from app.core.config import env

LEVEL_RANK = {"minimal": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
CONFIDENCE_RANK = {"low": 1, "medium": 2, "high": 3}
SECURITY = ("starttls", "ssl", "none")


def _flag(name: str, default: bool) -> bool:
    raw = env(name)
    if raw is None or str(raw).strip() == "":
        return default
    return str(raw).strip().lower() in ("1", "true", "yes", "on")


def _int(name: str, default: int, lo: int, hi: int) -> int:
    try:
        return max(lo, min(hi, int(str(env(name) or default).strip())))
    except ValueError:
        return default


def _choice(name: str, default: str, allowed) -> str:
    v = (env(name) or default).strip().lower()
    return v if v in allowed else default


@dataclass(frozen=True)
class AlertConfig:
    enabled: bool = True
    min_level: str = "high"                     # high_risk_analysis threshold
    floor_alerts: bool = True                   # hard_evidence_floor when below min_level
    conflict_alerts: bool = True                # review_conflict
    campaign_min_confidence: str = "medium"     # new_campaign threshold
    growth_min_new_members: int = 1
    growth_debounce_minutes: int = 60
    max_campaigns_per_pass: int = 200
    # email (optional; OFF by default)
    email_enabled: bool = False
    email_min_severity: str = "high"
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_security: str = "starttls"
    smtp_username: str = ""
    smtp_password: str = field(default="", repr=False)
    smtp_from: str = ""
    email_to: tuple[str, ...] = ()
    smtp_timeout_seconds: int = 10
    email_max_per_minute: int = 10
    app_base_url: str = ""

    @property
    def email_configured(self) -> bool:
        return bool(self.smtp_host and self.smtp_from and self.email_to)

    def public_dict(self) -> dict:
        """Effective configuration for the admin view: no password, username shown only as set/not set."""
        return {
            "enabled": self.enabled, "min_level": self.min_level, "floor_alerts": self.floor_alerts,
            "conflict_alerts": self.conflict_alerts, "campaign_min_confidence": self.campaign_min_confidence,
            "growth_min_new_members": self.growth_min_new_members,
            "growth_debounce_minutes": self.growth_debounce_minutes,
            "email": {"enabled": self.email_enabled, "configured": self.email_configured,
                      "min_severity": self.email_min_severity, "smtp_host": self.smtp_host or None,
                      "smtp_port": self.smtp_port, "smtp_security": self.smtp_security,
                      "smtp_username_set": bool(self.smtp_username), "smtp_password_set": bool(self.smtp_password),
                      "from": self.smtp_from or None, "recipients": len(self.email_to),
                      "max_per_minute": self.email_max_per_minute, "timeout_seconds": self.smtp_timeout_seconds,
                      "app_base_url": self.app_base_url or None},
            "trigger_note": "Alerts are raised when an analysis is processed; this system does not monitor "
                            "mailboxes in real time.",
        }


def get_alert_config() -> AlertConfig:
    """Read on every call (cheap) so tests and operators can change env without a restart of the module."""
    to = tuple(a.strip() for a in (env("ALERT_EMAIL_TO") or "").split(",") if a.strip())
    return AlertConfig(
        enabled=_flag("ALERTS_ENABLED", True),
        min_level=_choice("ALERT_MIN_LEVEL", "high", ("medium", "high", "critical")),
        floor_alerts=_flag("ALERT_FLOOR_ENABLED", True),
        conflict_alerts=_flag("ALERT_CONFLICT_ENABLED", True),
        campaign_min_confidence=_choice("ALERT_CAMPAIGN_MIN_CONFIDENCE", "medium", ("low", "medium", "high")),
        growth_min_new_members=_int("ALERT_CAMPAIGN_GROWTH_MIN_NEW", 1, 1, 1000),
        growth_debounce_minutes=_int("ALERT_CAMPAIGN_GROWTH_DEBOUNCE_MINUTES", 60, 0, 10080),
        email_enabled=_flag("ALERT_EMAIL_ENABLED", False),
        email_min_severity=_choice("ALERT_EMAIL_MIN_SEVERITY", "high", tuple(SEVERITY_RANK)),
        smtp_host=(env("ALERT_SMTP_HOST") or "").strip(),
        smtp_port=_int("ALERT_SMTP_PORT", 587, 1, 65535),
        smtp_security=_choice("ALERT_SMTP_SECURITY", "starttls", SECURITY),
        smtp_username=(env("ALERT_SMTP_USERNAME") or "").strip(),
        smtp_password=env("ALERT_SMTP_PASSWORD") or "",
        smtp_from=(env("ALERT_EMAIL_FROM") or "").strip(),
        email_to=to,
        smtp_timeout_seconds=_int("ALERT_SMTP_TIMEOUT_SECONDS", 10, 1, 120),
        email_max_per_minute=_int("ALERT_EMAIL_MAX_PER_MINUTE", 10, 1, 1000),
        app_base_url=(env("APP_BASE_URL") or "").strip().rstrip("/"),
    )
