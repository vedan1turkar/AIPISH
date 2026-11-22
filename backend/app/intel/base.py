"""Common threat-intel provider interface (P5a).

``Provider.lookup(indicator)`` always returns an ``IntelResult`` and never
raises. The order of checks is fixed and every exit has its own status:

    applicability → validation → consent → credentials → endpoint policy →
    fresh cache → offline (stale cache or not_attempted_offline) →
    local rate limit / daily quota → HTTPS GET (1 retry for 5xx/timeout) →
    normalise → cache

Statuses are deliberately never collapsed. "No record" and "no flags" are not
statements of safety, and every message says so.

Security invariants enforced here (and asserted by tests):
- only the validated bare indicator is sent; no email content or context;
- credentials go only into the provider's own auth header/param, are never
  logged, never stored, never placed in results or exception text;
- provider-supplied strings are sanitised and truncated before storage.
"""
from __future__ import annotations

import logging
import re
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from typing import Any

import httpx

from app.intel.config import LABELS, IntelConfig, get_intel_config
from app.intel.validate import reason_text, validate

# httpx/httpcore log request URLs at INFO/DEBUG; Shodan authenticates with a
# query parameter, so those loggers are capped to keep keys out of any log.
for _name in ("httpx", "httpcore"):
    logging.getLogger(_name).setLevel(logging.WARNING)

log = logging.getLogger("app.intel")


_SAFE_QUERY_PARAMS = frozenset({"ipAddress", "maxAgeInDays", "minify"})


def _request_audit_hook(provider: str):
    """Optional, OFF by default: when ``INTEL_REQUEST_LOG`` names a file, append one JSON line per outbound
    provider request with method, host, path, query-parameter NAMES, header NAMES and body length only.
    Never the query string, header values or body (Shodan's key travels in the query string; other providers
    send keys in headers). Used for the P5a-live transmission check; leave unset in normal operation."""
    import json
    from app.core.config import env
    target = (env("INTEL_REQUEST_LOG") or "").strip()
    if not target:
        return None

    def hook(request: httpx.Request) -> None:
        try:
            line = {"provider": provider, "method": request.method, "host": request.url.host,
                    "path": request.url.path, "query_param_names": sorted({k for k, _ in request.url.params.multi_items()}),
                    # values only for an explicit allowlist of non-secret parameters (never "key"/"token")
                    "query_values": {k: v for k, v in request.url.params.multi_items() if k in _SAFE_QUERY_PARAMS},
                    "header_names": sorted(request.headers.keys()), "body_bytes": len(request.content or b"")}
            with open(target, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(line) + "\n")
        except Exception:  # noqa: BLE001 — auditing must never break a lookup
            pass
    return hook

# ── statuses ──────────────────────────────────────────────────────────────
MALICIOUS_OR_FLAGGED = "malicious_or_flagged"
REPORTED_CLEAN_NO_FLAGS = "reported_clean_no_flags"
RECORD_FOUND = "record_found"
NO_RECORD = "no_record"
PROVIDER_ERROR = "provider_error"
RATE_LIMITED = "rate_limited"
AUTH_FAILED = "auth_failed"
TIMEOUT = "timeout"
MALFORMED_RESPONSE = "malformed_response"
NOT_PERMITTED = "not_permitted"
NOT_ATTEMPTED_CONSENT_DISABLED = "not_attempted_consent_disabled"
NOT_ATTEMPTED_OFFLINE = "not_attempted_offline"
NOT_ATTEMPTED_CAP_REACHED = "not_attempted_cap_reached"
MISSING_CREDENTIALS = "missing_credentials"
NOT_APPLICABLE_INDICATOR = "not_applicable_indicator"
QUOTA_EXHAUSTED = "quota_exhausted"

STATUSES = (
    MALICIOUS_OR_FLAGGED, REPORTED_CLEAN_NO_FLAGS, RECORD_FOUND, NO_RECORD, PROVIDER_ERROR,
    RATE_LIMITED, AUTH_FAILED, TIMEOUT, MALFORMED_RESPONSE, NOT_PERMITTED,
    NOT_ATTEMPTED_CONSENT_DISABLED, NOT_ATTEMPTED_OFFLINE, NOT_ATTEMPTED_CAP_REACHED,
    MISSING_CREDENTIALS, NOT_APPLICABLE_INDICATOR, QUOTA_EXHAUSTED,
)
# Results that describe the indicator (cacheable); everything else is a lookup state.
TERMINAL = frozenset({MALICIOUS_OR_FLAGGED, REPORTED_CLEAN_NO_FLAGS, RECORD_FOUND, NO_RECORD})
# Live failures that may fall back to an expired cache entry (labelled stale).
FALLBACK_ON = frozenset({PROVIDER_ERROR, RATE_LIMITED, TIMEOUT, MALFORMED_RESPONSE,
                         QUOTA_EXHAUSTED, AUTH_FAILED, NOT_PERMITTED})

NOT_PROOF = "This is not proof of safety."
DISCLAIMER = (
    "Threat-intelligence results are third-party, point-in-time data and are informational only: "
    "they do not change the rule score, ML classification or verdict. Absence of reports or flags "
    "is not proof of safety. An IP address or geolocation identifies network infrastructure, "
    "never a person."
)


def default_message(status: str, label: str, detail: str = "") -> str:
    d = f" {detail}" if detail else ""
    return {
        MALICIOUS_OR_FLAGGED: f"{label} flagged this indicator.{d}",
        REPORTED_CLEAN_NO_FLAGS: f"{label} returned data with no flags.{d} {NOT_PROOF}",
        RECORD_FOUND: f"{label} returned a record but gives no reputation verdict for it.{d} {NOT_PROOF}",
        NO_RECORD: f"No record or reports found at {label}.{d} {NOT_PROOF}",
        PROVIDER_ERROR: f"{label} returned an error; no result.{d}",
        RATE_LIMITED: f"{label} rate limit reached; not looked up.{d}",
        AUTH_FAILED: f"{label} rejected the configured credential; not looked up.{d}",
        TIMEOUT: f"{label} did not respond in time; no result.{d}",
        MALFORMED_RESPONSE: f"{label} returned a response that could not be read; no result.{d}",
        NOT_PERMITTED: f"{label} does not permit this lookup for the configured plan/policy.{d}",
        NOT_ATTEMPTED_CONSENT_DISABLED: "Not looked up: external lookups were not consented to for this analysis.",
        NOT_ATTEMPTED_OFFLINE: "Not looked up: offline mode blocks external calls and no cached result exists.",
        NOT_ATTEMPTED_CAP_REACHED: "Not looked up: per-analysis indicator cap reached.",
        MISSING_CREDENTIALS: f"Not looked up: no {label} credential is configured.",
        NOT_APPLICABLE_INDICATOR: f"Not applicable: {label} does not look up this indicator.{d}",
        QUOTA_EXHAUSTED: f"{label} daily quota exhausted; not looked up.{d}",
    }.get(status, f"{label}: {status}.{d}")


# ── sanitising untrusted provider strings ────────────────────────────────
_CTRL = re.compile(r"[\x00-\x1f\x7f-\x9f​-‏‪-‮⁦-⁩﻿]")
_WS = re.compile(r"\s+")


def clean_text(value: Any, cap: int = 120) -> str | None:
    if value is None or isinstance(value, (dict, list, tuple, set)):
        return None
    text = _WS.sub(" ", _CTRL.sub(" ", str(value))).strip()
    if not text:
        return None
    return text if len(text) <= cap else text[: cap - 1] + "…"


def clean_list(value: Any, items: int = 20, cap: int = 80) -> list[str]:
    if not isinstance(value, (list, tuple)):
        return []
    out = [c for c in (clean_text(v, cap) for v in value[: items * 2]) if c]
    return out[:items]


def clean_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    return None


def clean_bool(value: Any) -> bool | None:
    return value if isinstance(value, bool) else None


def epoch_iso(value: Any) -> str | None:
    n = clean_int(value)
    if n is None or n <= 0:
        return None
    try:
        return datetime.fromtimestamp(n, timezone.utc).isoformat()
    except (OverflowError, OSError, ValueError):
        return None


# ── result envelope ──────────────────────────────────────────────────────
def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _aware(d: datetime | None) -> datetime | None:
    if d is None:
        return None
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


@dataclass
class IntelResult:
    provider: str
    indicator: str
    indicator_type: str
    status: str
    fetched_at: str | None = None
    expires_at: str | None = None
    cache_state: str = "none"            # fresh | stale | none
    source: str = ""                     # endpoint name (never a URL with credentials)
    data: dict[str, Any] = field(default_factory=dict)
    error_code: str | None = None
    message: str = ""
    cache_age_seconds: int | None = None
    retry_after_seconds: int | None = None

    def to_dict(self) -> dict:
        return {
            "provider": self.provider,
            "provider_label": LABELS.get(self.provider, self.provider),
            "indicator": self.indicator,
            "indicator_type": self.indicator_type,
            "status": self.status,
            "fetched_at": self.fetched_at,
            "expires_at": self.expires_at,
            "cache_state": self.cache_state,
            "source": self.source,
            "data": self.data,
            "error_code": self.error_code,
            "message": self.message,
            "cache_age_seconds": self.cache_age_seconds,
            "retry_after_seconds": self.retry_after_seconds,
        }


# ── rate limiting + daily quota (per provider, per process) ──────────────
class Limiter:
    def __init__(self, per_minute: int, per_day: int):
        self.per_minute = per_minute
        self.per_day = per_day
        self.window: deque[float] = deque()
        self.day = ""
        self.day_count = 0
        self.cooldown_until = 0.0
        self.lock = threading.Lock()

    def acquire(self, now: float | None = None) -> tuple[str | None, int | None]:
        """Take one request slot. Returns (blocking_status, retry_after_seconds)."""
        now = time.time() if now is None else now
        with self.lock:
            if now < self.cooldown_until:
                return RATE_LIMITED, int(self.cooldown_until - now) + 1
            today = datetime.fromtimestamp(now, timezone.utc).strftime("%Y-%m-%d")
            if today != self.day:
                self.day, self.day_count = today, 0
            if self.per_day >= 0 and self.day_count >= self.per_day:
                return QUOTA_EXHAUSTED, None
            while self.window and now - self.window[0] >= 60:
                self.window.popleft()
            if self.per_minute >= 0 and len(self.window) >= self.per_minute:
                return RATE_LIMITED, int(60 - (now - self.window[0])) + 1
            self.window.append(now)
            self.day_count += 1
            return None, None

    def cool_down(self, seconds: int, now: float | None = None) -> None:
        now = time.time() if now is None else now
        with self.lock:
            self.cooldown_until = max(self.cooldown_until, now + max(1, seconds))

    def exhaust_today(self) -> None:
        with self.lock:
            self.day_count = max(self.day_count, self.per_day)


_limiters: dict[str, Limiter] = {}
_limiters_lock = threading.Lock()


def limiter_for(provider: str, cfg: IntelConfig) -> Limiter:
    per_minute, per_day = cfg.limits(provider)
    with _limiters_lock:
        lim = _limiters.get(provider)
        if lim is None or (lim.per_minute, lim.per_day) != (per_minute, per_day):
            lim = _limiters[provider] = Limiter(per_minute, per_day)
        return lim


def reset_limiters() -> None:
    with _limiters_lock:
        _limiters.clear()


def parse_retry_after(value: str | None) -> int | None:
    if not value:
        return None
    value = value.strip()
    if value.isdigit():
        return min(int(value), 86_400)
    try:
        d = parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None
    if d is None:
        return None
    return max(0, min(int((_aware(d) - utcnow()).total_seconds()), 86_400))


# ── DB cache ─────────────────────────────────────────────────────────────
def cache_key(provider: str, indicator_type: str, indicator: str) -> str:
    return f"{provider}:{indicator_type}:{indicator}"


def cache_get(db, provider: str, indicator_type: str, indicator: str):
    from app.core.models import IntelCacheEntry
    if db is None:
        return None
    try:
        return db.get(IntelCacheEntry, cache_key(provider, indicator_type, indicator))
    except Exception:            # cache problems must never break a lookup
        log.warning("intel cache read failed for provider=%s", provider)
        return None


def cache_put(db, provider: str, indicator_type: str, indicator: str, status: str,
              data: dict, message: str, fetched: datetime, ttl: int) -> None:
    from app.core.models import IntelCacheEntry
    if db is None:
        return
    try:
        key = cache_key(provider, indicator_type, indicator)
        row = db.get(IntelCacheEntry, key)
        if row is None:
            row = IntelCacheEntry(key=key, provider=provider, indicator_type=indicator_type,
                                  indicator=indicator)
            db.add(row)
        row.status, row.data_json, row.message = status, data, message
        row.fetched_at, row.expires_at = fetched, fetched + timedelta(seconds=ttl)
        db.commit()
    except Exception:
        db.rollback()
        log.warning("intel cache write failed for provider=%s", provider)


# ── provider base ────────────────────────────────────────────────────────
class Provider:
    name: str = ""
    types: frozenset[str] = frozenset()
    endpoint_name: str = ""

    def __init__(self, cfg: IntelConfig | None = None, client: httpx.Client | None = None,
                 sleep=time.sleep):
        self.cfg = cfg or get_intel_config()
        self.client = client
        self.sleep = sleep

    # -- hooks for subclasses ------------------------------------------------
    @property
    def label(self) -> str:
        return LABELS.get(self.name, self.name)

    def ttl(self, indicator_type: str) -> int:
        return {"ip": self.cfg.ttl_ip_seconds, "domain": self.cfg.ttl_domain_seconds,
                "hash": self.cfg.ttl_hash_seconds}.get(indicator_type, self.cfg.ttl_ip_seconds)

    def source(self, indicator_type: str) -> str:
        return self.endpoint_name

    def build_request(self, indicator: str, indicator_type: str, key: str | None
                      ) -> tuple[str, dict[str, str], dict[str, str]]:
        raise NotImplementedError

    def classify_http(self, resp: httpx.Response) -> str | None:
        """Map a non-200 response to a status; None means 'let parse decide'."""
        code = resp.status_code
        if code == 401:
            return AUTH_FAILED
        if code == 403:
            return NOT_PERMITTED
        if code == 404:
            return NO_RECORD
        if code == 429:
            return RATE_LIMITED
        if code >= 400:
            return PROVIDER_ERROR
        return None

    def parse(self, payload: Any, indicator: str, indicator_type: str
              ) -> tuple[str, dict[str, Any], str]:
        raise NotImplementedError

    # -- template ------------------------------------------------------------
    def _result(self, indicator: str, itype: str, status: str, **kw) -> IntelResult:
        kw.setdefault("message", default_message(status, self.label))
        kw.setdefault("source", self.source(itype))
        return IntelResult(provider=self.name, indicator=indicator, indicator_type=itype, status=status, **kw)

    def _from_cache(self, row, indicator: str, itype: str, state: str, now: datetime,
                    error_code: str | None = None, note: str = "") -> IntelResult:
        fetched = _aware(row.fetched_at)
        age = int((now - fetched).total_seconds()) if fetched else None
        msg = row.message or default_message(row.status, self.label)
        if state == "stale":
            msg = f"STALE cached result from {_age_text(age)} ago — {note} {msg}".replace("  ", " ")
        return self._result(indicator, itype, row.status, data=dict(row.data_json or {}),
                            fetched_at=fetched.isoformat() if fetched else None,
                            expires_at=_aware(row.expires_at).isoformat() if row.expires_at else None,
                            cache_state=state, cache_age_seconds=age, error_code=error_code, message=msg)

    def lookup(self, indicator: str, indicator_type: str | None = None, *, consent: bool = False,
               offline: bool | None = None, db=None) -> IntelResult:
        """Look up one bare indicator. Defaults are safe: no consent → no network."""
        try:
            return self._lookup(indicator, indicator_type, consent=consent,
                                offline=self.cfg.offline if offline is None else offline, db=db)
        except Exception as exc:   # never break the caller; never echo exception text
            log.warning("intel provider %s failed: %s", self.name, type(exc).__name__)
            return self._result(str(indicator)[:300], indicator_type or "unknown", PROVIDER_ERROR,
                                error_code=f"internal_{type(exc).__name__}")

    def _lookup(self, indicator: str, indicator_type: str | None, *, consent: bool, offline: bool,
                db) -> IntelResult:
        itype, norm, reason = validate(indicator, indicator_type)
        shown = norm or str(indicator)[:300]
        if itype not in self.types:
            return self._result(shown, itype or "unknown", NOT_APPLICABLE_INDICATOR,
                                error_code="indicator_type_not_supported")
        if norm is None:
            return self._result(shown, itype, NOT_APPLICABLE_INDICATOR, error_code=reason,
                                message=default_message(NOT_APPLICABLE_INDICATOR, self.label,
                                                        f"Rejected before any network call: {reason_text(reason)}."))
        if not consent:
            return self._result(norm, itype, NOT_ATTEMPTED_CONSENT_DISABLED)
        if not self.cfg.configured(self.name):
            return self._result(norm, itype, MISSING_CREDENTIALS)
        if not self.cfg.endpoint_ok(self.name):
            return self._result(norm, itype, NOT_PERMITTED, error_code="endpoint_not_allowed",
                                message=f"{self.label} endpoint is not HTTPS (or loopback); lookup refused by policy.")
        if not self.cfg.switched_on(self.name):
            return self._result(norm, itype, NOT_PERMITTED, error_code="provider_disabled",
                                message=f"{self.label} is disabled by configuration.")

        now = utcnow()
        row = cache_get(db, self.name, itype, norm)
        if row is not None and _aware(row.expires_at) > now:
            return self._from_cache(row, norm, itype, "fresh", now)
        if offline:
            if row is not None:
                return self._from_cache(row, norm, itype, "stale", now, error_code=NOT_ATTEMPTED_OFFLINE,
                                        note="offline mode, no live lookup.")
            return self._result(norm, itype, NOT_ATTEMPTED_OFFLINE)

        live = self._fetch(norm, itype)
        if live.status in TERMINAL:
            cache_put(db, self.name, itype, norm, live.status, live.data, live.message, now, self.ttl(itype))
            live.fetched_at = now.isoformat()
            live.expires_at = (now + timedelta(seconds=self.ttl(itype))).isoformat()
            return live
        if live.status in FALLBACK_ON and row is not None:
            return self._from_cache(row, norm, itype, "stale", now, error_code=live.status,
                                    note=f"live lookup failed ({live.status}).")
        return live

    def _fetch(self, indicator: str, itype: str) -> IntelResult:
        limiter = limiter_for(self.name, self.cfg)
        blocked, retry_after = limiter.acquire()
        if blocked:
            extra = f"Local limit; retry in about {retry_after}s." if retry_after else ""
            return self._result(indicator, itype, blocked, retry_after_seconds=retry_after,
                                error_code=f"local_{blocked}",
                                message=default_message(blocked, self.label, extra))
        url, headers, params = self.build_request(indicator, itype, self.cfg.credential(self.name))
        timeout = httpx.Timeout(self.cfg.read_timeout_seconds, connect=self.cfg.connect_timeout_seconds)
        hook = None if self.client is not None else _request_audit_hook(self.name)
        client = self.client or httpx.Client(timeout=timeout, follow_redirects=False,
                                             event_hooks={"request": [hook]} if hook else None)
        resp: httpx.Response | None = None
        failure: str | None = None
        try:
            for attempt in (0, 1):
                failure = None
                try:
                    resp = client.get(url, headers=headers, params=params, timeout=timeout)
                except httpx.TimeoutException:
                    failure = TIMEOUT
                except httpx.HTTPError as exc:
                    failure = PROVIDER_ERROR
                    err_name = type(exc).__name__
                else:
                    if resp.status_code < 500:
                        break
                    failure = PROVIDER_ERROR
                    err_name = f"http_{resp.status_code}"
                if attempt == 0:               # exactly one retry, for transient failures only
                    if limiter.acquire()[0]:
                        break
                    self.sleep(self.cfg.retry_backoff_seconds)
        finally:
            if self.client is None:
                client.close()

        if failure == TIMEOUT:
            return self._result(indicator, itype, TIMEOUT, error_code="timeout")
        if failure == PROVIDER_ERROR:
            return self._result(indicator, itype, PROVIDER_ERROR, error_code=err_name)
        assert resp is not None
        if resp.status_code != 200:
            status = self.classify_http(resp)
            if status == RATE_LIMITED:
                ra = parse_retry_after(resp.headers.get("Retry-After"))
                if self.is_quota_exhausted(resp):
                    limiter.exhaust_today()
                    return self._result(indicator, itype, QUOTA_EXHAUSTED, error_code="http_429_quota",
                                        retry_after_seconds=ra)
                limiter.cool_down(ra or 60)
                return self._result(indicator, itype, RATE_LIMITED, error_code="http_429",
                                    retry_after_seconds=ra or 60,
                                    message=default_message(RATE_LIMITED, self.label,
                                                            f"Provider asked to retry after {ra or 60}s."))
            if status == NO_RECORD:
                return self._result(indicator, itype, NO_RECORD,
                                    message=default_message(NO_RECORD, self.label, self.no_record_detail()))
            if status is not None:
                return self._result(indicator, itype, status, error_code=f"http_{resp.status_code}")
        try:
            payload = self.decode(resp)
            status, data, message = self.parse(payload, indicator, itype)
        except (ValueError, TypeError, KeyError, AttributeError):
            return self._result(indicator, itype, MALFORMED_RESPONSE, error_code="malformed")
        return self._result(indicator, itype, status, data=data,
                            message=message or default_message(status, self.label))

    def decode(self, resp: httpx.Response) -> Any:
        payload = resp.json()
        if not isinstance(payload, dict):
            raise ValueError("expected a JSON object")
        return payload

    def is_quota_exhausted(self, resp: httpx.Response) -> bool:
        return False

    def no_record_detail(self) -> str:
        return ""


def _age_text(seconds: int | None) -> str:
    if seconds is None:
        return "an unknown time"
    if seconds < 3600:
        return f"{max(1, seconds // 60)} min"
    if seconds < 172_800:
        return f"{seconds // 3600} h"
    return f"{seconds // 86_400} d"
