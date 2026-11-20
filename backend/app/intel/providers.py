"""Concrete threat-intel adapters (P5a): VirusTotal, AbuseIPDB, Shodan, IPinfo, Tor.

Every adapter sends exactly one bare, validated indicator in the request path
or a single query parameter — nothing else from the email. All requests are
HTTP GET. VirusTotal is used for read-only reputation lookups only: files,
attachments, emails and URLs are NEVER uploaded or submitted for scanning.
"""
from __future__ import annotations

import ipaddress
import re
from datetime import timedelta
from typing import Any
from urllib.parse import quote

import httpx

from app.intel.base import (
    MALFORMED_RESPONSE,
    MALICIOUS_OR_FLAGGED,
    NO_RECORD,
    NOT_APPLICABLE_INDICATOR,
    NOT_ATTEMPTED_CONSENT_DISABLED,
    NOT_ATTEMPTED_OFFLINE,
    NOT_PERMITTED,
    RECORD_FOUND,
    REPORTED_CLEAN_NO_FLAGS,
    TERMINAL,
    FALLBACK_ON,
    MISSING_CREDENTIALS,
    NOT_PROOF,
    IntelResult,
    Provider,
    _aware,
    cache_get,
    cache_put,
    clean_bool,
    clean_int,
    clean_list,
    clean_text,
    default_message,
    epoch_iso,
    utcnow,
)
from app.intel.validate import DOMAIN, HASH, IP, hash_kind, reason_text, validate


def _seg(value: str) -> str:
    """Percent-encode a validated indicator as one URL path segment."""
    return quote(value, safe="")


# ── VirusTotal (API v3, GET-only reputation) ─────────────────────────────
class VirusTotal(Provider):
    name = "virustotal"
    types = frozenset({IP, DOMAIN, HASH})
    _PATHS = {IP: "ip_addresses", DOMAIN: "domains", HASH: "files"}

    def source(self, indicator_type: str) -> str:
        return f"VirusTotal API v3 GET /{self._PATHS.get(indicator_type, '?')}/{{id}}"

    def build_request(self, indicator, indicator_type, key):
        url = f"{self.cfg.vt_base.rstrip('/')}/{self._PATHS[indicator_type]}/{_seg(indicator)}"
        return url, {"x-apikey": key or "", "Accept": "application/json"}, {}

    def is_quota_exhausted(self, resp: httpx.Response) -> bool:
        try:
            err = resp.json().get("error") or {}
        except (ValueError, AttributeError):
            return False
        if not isinstance(err, dict):
            return False
        # VT returns 429 QuotaExceededError for both per-minute and daily caps;
        # only an explicit daily signal is treated as quota exhaustion.
        return err.get("code") == "QuotaExceededError" and "daily" in str(err.get("message", "")).lower()

    def no_record_detail(self) -> str:
        return "VirusTotal has no object for this indicator."

    def parse(self, payload, indicator, indicator_type):
        attrs = payload["data"]["attributes"]
        if not isinstance(attrs, dict):
            raise ValueError("attributes")
        stats = attrs.get("last_analysis_stats")
        stats = stats if isinstance(stats, dict) else {}
        counts = {k: clean_int(stats.get(k)) or 0
                  for k in ("malicious", "suspicious", "harmless", "undetected", "timeout")}
        engines = sum(counts.values())
        data: dict[str, Any] = {
            "malicious": counts["malicious"], "suspicious": counts["suspicious"],
            "harmless": counts["harmless"], "undetected": counts["undetected"],
            "engines_total": engines,
            "reputation": clean_int(attrs.get("reputation")),
            "last_analysis_date": epoch_iso(attrs.get("last_analysis_date")),
            "tags": clean_list(attrs.get("tags"), 15, 40),
        }
        if indicator_type == IP:
            data.update(country=clean_text(attrs.get("country"), 8), as_owner=clean_text(attrs.get("as_owner")),
                        asn=clean_int(attrs.get("asn")), network=clean_text(attrs.get("network"), 50))
        elif indicator_type == DOMAIN:
            data.update(registrar=clean_text(attrs.get("registrar")),
                        creation_date=epoch_iso(attrs.get("creation_date")))
        else:
            data.update(hash_kind=hash_kind(indicator), type_description=clean_text(attrs.get("type_description"), 60),
                        size_bytes=clean_int(attrs.get("size")))
        flagged = counts["malicious"] + counts["suspicious"]
        if flagged:
            return (MALICIOUS_OR_FLAGGED, data,
                    f"VirusTotal: {counts['malicious']} engine(s) malicious, {counts['suspicious']} suspicious "
                    f"of {engines}.")
        if engines == 0:
            return NO_RECORD, data, default_message(NO_RECORD, self.label, "Object exists but has no analysis results.")
        return (REPORTED_CLEAN_NO_FLAGS, data,
                f"VirusTotal: 0 of {engines} engines flagged this indicator. {NOT_PROOF}")


# ── AbuseIPDB (API v2 /check) ────────────────────────────────────────────
class AbuseIPDB(Provider):
    name = "abuseipdb"
    types = frozenset({IP})
    endpoint_name = "AbuseIPDB API v2 GET /check"

    def build_request(self, indicator, indicator_type, key):
        return (f"{self.cfg.abuseipdb_base.rstrip('/')}/check",
                {"Key": key or "", "Accept": "application/json"},
                {"ipAddress": indicator, "maxAgeInDays": str(self.cfg.abuseipdb_max_age_days)})

    def classify_http(self, resp):
        if resp.status_code == 422:      # provider refused the parameter
            return NOT_APPLICABLE_INDICATOR
        return super().classify_http(resp)

    def is_quota_exhausted(self, resp: httpx.Response) -> bool:
        return resp.headers.get("X-RateLimit-Remaining") == "0"

    def parse(self, payload, indicator, indicator_type):
        d = payload["data"]
        if not isinstance(d, dict):
            raise ValueError("data")
        score = clean_int(d.get("abuseConfidenceScore"))
        reports = clean_int(d.get("totalReports"))
        if score is None or reports is None:
            raise ValueError("missing score")
        threshold = self.cfg.abuseipdb_flag_threshold
        data = {
            "abuse_confidence_score": score, "total_reports": reports,
            "distinct_reporters": clean_int(d.get("numDistinctUsers")),
            "country_code": clean_text(d.get("countryCode"), 8), "isp": clean_text(d.get("isp")),
            "usage_type": clean_text(d.get("usageType"), 60), "domain": clean_text(d.get("domain"), 80),
            "last_reported_at": clean_text(d.get("lastReportedAt"), 40),
            "is_tor_provider_reported": clean_bool(d.get("isTor")),
            "is_whitelisted": clean_bool(d.get("isWhitelisted")),
            "flag_threshold": threshold, "max_age_days": self.cfg.abuseipdb_max_age_days,
        }
        if reports == 0:
            return NO_RECORD, data, (f"AbuseIPDB: no reports found in the last {self.cfg.abuseipdb_max_age_days} "
                                     f"days. {NOT_PROOF}")
        if score >= threshold:
            return (MALICIOUS_OR_FLAGGED, data,
                    f"AbuseIPDB: confidence score {score}/100 from {reports} report(s) (flag threshold {threshold}).")
        return (RECORD_FOUND, data,
                f"AbuseIPDB: {reports} report(s) but confidence score {score}/100 is below the flag threshold "
                f"{threshold}. {NOT_PROOF}")


# ── Shodan (host lookup) ─────────────────────────────────────────────────
_SHODAN_RISK_TAGS = {"malware", "compromised", "c2", "botnet", "tor", "proxy", "vpn", "honeypot", "scanner"}


class Shodan(Provider):
    name = "shodan"
    types = frozenset({IP})
    endpoint_name = "Shodan API GET /shodan/host/{ip}"

    def ttl(self, indicator_type):
        return self.cfg.ttl_shodan_seconds

    def build_request(self, indicator, indicator_type, key):
        # Shodan authenticates only via the `key` query parameter. httpx URL
        # logging is capped (base.py) and URLs are never stored or returned.
        return (f"{self.cfg.shodan_base.rstrip('/')}/shodan/host/{_seg(indicator)}",
                {"Accept": "application/json"}, {"key": key or "", "minify": "true"})

    def no_record_detail(self) -> str:
        return "Shodan has no host record for this IP."

    def parse(self, payload, indicator, indicator_type):
        ports = payload.get("ports")
        if ports is not None and not isinstance(ports, list):
            raise ValueError("ports")
        tags = clean_list(payload.get("tags"), 15, 40)
        vulns = payload.get("vulns")
        data = {
            "open_ports": sorted({p for p in (clean_int(x) for x in (ports or [])) if p is not None})[:50],
            "org": clean_text(payload.get("org")), "isp": clean_text(payload.get("isp")),
            "asn": clean_text(payload.get("asn"), 16),
            "hostnames": clean_list(payload.get("hostnames"), 10, 100),
            "domains": clean_list(payload.get("domains"), 10, 100),
            "tags": tags,
            "country": clean_text(payload.get("country_name"), 60), "city": clean_text(payload.get("city"), 60),
            "last_update": clean_text(payload.get("last_update"), 40),
            "known_vulnerability_count": len(vulns) if isinstance(vulns, (list, dict)) else None,
        }
        risky = sorted({t.lower() for t in tags} & _SHODAN_RISK_TAGS)
        if risky:
            return MALICIOUS_OR_FLAGGED, data, f"Shodan tagged this host: {', '.join(risky)}."
        return RECORD_FOUND, data, (f"Shodan host record found ({len(data['open_ports'])} open port(s)); "
                                    f"Shodan gives no reputation verdict. {NOT_PROOF}")


# ── IPinfo ───────────────────────────────────────────────────────────────
_PRIVACY_FIELDS = ("vpn", "proxy", "tor", "relay", "hosting")


class IPinfo(Provider):
    name = "ipinfo"
    types = frozenset({IP})
    endpoint_name = "IPinfo API GET /{ip}/json"

    def build_request(self, indicator, indicator_type, key):
        return (f"{self.cfg.ipinfo_base.rstrip('/')}/{_seg(indicator)}/json",
                {"Authorization": f"Bearer {key or ''}", "Accept": "application/json"}, {})

    def parse(self, payload, indicator, indicator_type):
        if payload.get("bogon") is True:
            return NO_RECORD, {}, default_message(NO_RECORD, self.label, "IPinfo reports a bogon address.")
        if "ip" not in payload:
            raise ValueError("no ip field")
        org = clean_text(payload.get("org"))
        asn = None
        if org and (m := re.match(r"^(AS\d{1,10})\b", org)):
            asn = m.group(1)
        privacy = payload.get("privacy") if isinstance(payload.get("privacy"), dict) else None
        flags = {f: (clean_bool(privacy.get(f)) if privacy and clean_bool(privacy.get(f)) is not None else "unavailable")
                 for f in _PRIVACY_FIELDS}
        data = {
            "city": clean_text(payload.get("city"), 60), "region": clean_text(payload.get("region"), 60),
            "country": clean_text(payload.get("country"), 8), "approx_coordinates": clean_text(payload.get("loc"), 40),
            "org": org, "asn": asn, "hostname": clean_text(payload.get("hostname"), 120),
            "timezone": clean_text(payload.get("timezone"), 40),
            "privacy_flags_returned": privacy is not None,
            **{f"is_{f}": v for f, v in flags.items()},
            "privacy_service": clean_text(privacy.get("service"), 60) if privacy else None,
            "caveat": "approximate network location of infrastructure; does not identify a person",
        }
        on = [f for f, v in flags.items() if v is True]
        if on:
            return MALICIOUS_OR_FLAGGED, data, f"IPinfo privacy flags: {', '.join(on)}."
        if privacy is not None and all(v is False for v in flags.values()):
            return REPORTED_CLEAN_NO_FLAGS, data, f"IPinfo: no VPN/proxy/Tor/relay/hosting flags. {NOT_PROOF}"
        return RECORD_FOUND, data, ("IPinfo returned network/geo details; anonymity flags were not returned by this "
                                    f"plan (shown as unavailable, not false). {NOT_PROOF}")


# ── Tor bulk exit list ───────────────────────────────────────────────────
TOR_LIST_TYPE, TOR_LIST_KEY = "list", "bulk_exit_list"


def parse_tor_list(text: str) -> list[str]:
    out: set[str] = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            out.add(str(ipaddress.ip_address(line.split()[0])))
        except ValueError:
            continue
    return sorted(out)


class TorExitList(Provider):
    """Membership check against the public Tor bulk exit list.

    The list itself is fetched (no indicator is sent at all), cached with a TTL,
    and checked locally. Offline mode uses the cached list, labelled stale when
    expired, and never invents a result when no list is cached.
    """
    name = "tor_exit_list"
    types = frozenset({IP})
    endpoint_name = "Tor Project bulk exit list (check.torproject.org/torbulkexitlist)"

    def ttl(self, indicator_type):
        return self.cfg.ttl_tor_seconds

    def build_request(self, indicator, indicator_type, key):
        return self.cfg.tor_list_url, {"Accept": "text/plain"}, {}

    def decode(self, resp: httpx.Response) -> Any:
        if "html" in resp.headers.get("content-type", "").lower():
            raise ValueError("unexpected html")
        ips = parse_tor_list(resp.text)
        if not ips:
            raise ValueError("empty list")
        return ips

    def parse(self, payload, indicator, indicator_type):
        return RECORD_FOUND, {"ips": payload, "list_size": len(payload)}, "Tor exit list fetched."

    def _list(self, offline: bool, db) -> tuple[IntelResult | None, list[str], str, str | None, int | None, str | None]:
        """Returns (failure_or_None, ips, cache_state, fetched_at, age_s, error_code)."""
        now = utcnow()
        row = cache_get(db, self.name, TOR_LIST_TYPE, TOR_LIST_KEY)
        fresh = row is not None and _aware(row.expires_at) > now

        def from_row(state: str, code: str | None):
            fetched = _aware(row.fetched_at)
            return (None, list((row.data_json or {}).get("ips") or []), state, fetched.isoformat(),
                    int((now - fetched).total_seconds()), code)

        if fresh:
            return from_row("fresh", None)
        if offline:
            if row is not None:
                return from_row("stale", NOT_ATTEMPTED_OFFLINE)
            return (self._result(TOR_LIST_KEY, TOR_LIST_TYPE, NOT_ATTEMPTED_OFFLINE,
                                 message="Not checked: offline mode and no cached Tor exit list."),
                    [], "none", None, None, None)
        live = self._fetch(TOR_LIST_KEY, TOR_LIST_TYPE)
        if live.status in TERMINAL:
            cache_put(db, self.name, TOR_LIST_TYPE, TOR_LIST_KEY, live.status, live.data, live.message, now,
                      self.ttl(IP))
            return None, list(live.data["ips"]), "fresh", now.isoformat(), 0, None
        if live.status in FALLBACK_ON and row is not None:
            return from_row("stale", live.status)
        return live, [], "none", None, None, None

    def _lookup(self, indicator, indicator_type, *, consent, offline, db):
        itype, norm, reason = validate(indicator, indicator_type)
        if itype != IP or norm is None:
            return self._result(norm or str(indicator)[:300], itype or "unknown", NOT_APPLICABLE_INDICATOR,
                                error_code=reason or "indicator_type_not_supported",
                                message=default_message(NOT_APPLICABLE_INDICATOR, self.label,
                                                        reason_text(reason) if reason else ""))
        if not consent:
            return self._result(norm, itype, NOT_ATTEMPTED_CONSENT_DISABLED)
        if not self.cfg.endpoint_ok(self.name):
            return self._result(norm, itype, NOT_PERMITTED, error_code="endpoint_not_allowed",
                                message="Tor list URL is not HTTPS (or loopback); fetch refused by policy.")
        if not self.cfg.switched_on(self.name):
            return self._result(norm, itype, NOT_PERMITTED, error_code="provider_disabled",
                                message="Tor exit list check is disabled by configuration.")
        failure, ips, state, fetched_at, age, code = self._list(offline, db)
        if failure is not None:
            failure.indicator, failure.indicator_type = norm, itype
            return failure
        listed = norm in set(ips)
        expires = None
        if fetched_at:
            from datetime import datetime
            expires = (datetime.fromisoformat(fetched_at) + timedelta(seconds=self.ttl(IP))).isoformat()
        data = {"listed": listed, "list_fetched_at": fetched_at, "list_size": len(ips)}
        if listed:
            msg = "Listed in the Tor bulk exit list: traffic from this IP may come from any Tor user."
            status = MALICIOUS_OR_FLAGGED
        else:
            msg = f"Not in the Tor exit list snapshot. {NOT_PROOF}"
            status = NO_RECORD
        if state == "stale":
            msg = f"STALE Tor list ({age // 60 if age else 0} min old; {code}). " + msg
        return self._result(norm, itype, status, data=data, fetched_at=fetched_at, expires_at=expires,
                            cache_state=state, cache_age_seconds=age, error_code=code, message=msg)


PROVIDER_CLASSES: dict[str, type[Provider]] = {
    "virustotal": VirusTotal,
    "abuseipdb": AbuseIPDB,
    "shodan": Shodan,
    "ipinfo": IPinfo,
    "tor_exit_list": TorExitList,
}

__all__ = ["PROVIDER_CLASSES", "VirusTotal", "AbuseIPDB", "Shodan", "IPinfo", "TorExitList",
           "parse_tor_list", "MALFORMED_RESPONSE", "MISSING_CREDENTIALS"]
