"""Enrichment engine — provider calls with statuses, caching, provenance.

Every provider result is a ProviderResult:
    provider, ioc, status (ok | not_found | unavailable | skipped), latency_ms,
    evidence (facts found or skip reason), provenance (URLs/meanings).

Only DNS is mandatory; RDAP and IP-geolocation are optional (env-switchable,
keyless). Credential adapters ( AbuseIPDB / GeoLite2 db) return ``skipped``
with a clear reason when the env var is absent — analysis never crashes.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Callable

from app.enrichment.config import EnrichmentConfig, get_enrichment_config
from app.enrichment.iocs import Ioc, collect_iocs, is_private_ip
from app.ingestion.parser import ParsedEmail

PROVENANCE = {
    "dns": "public DNS lookups (A/AAAA/MX/TXT) — authoritative records, read-only",
    "rdap": "RDAP registration record (rdap.org bootstrap) — registrar/creation data",
    "ipgeo_http": "keyless IP geolocation HTTP API — network location of an IP, NOT a person",
    "abuseipdb": "IP abuse-confidence database — requires ABUSEIPDB_API_KEY env",
    "geoip2_file": "local MaxMind GeoLite2 database — requires MAXMIND_GEOIP2_DB env",
}


@dataclass
class ProviderResult:
    provider: str
    ioc_kind: str
    ioc_value: str
    status: str                     # ok | not_found | unavailable | skipped
    latency_ms: int
    evidence: dict[str, Any]
    provenance: str

    def to_dict(self) -> dict:
        return {
            "provider": self.provider,
            "ioc": {"kind": self.ioc_kind, "value": self.ioc_value},
            "status": self.status,
            "latency_ms": self.latency_ms,
            "evidence": self.evidence,
            "provenance": self.provenance,
        }


@dataclass
class EnrichmentResult:
    results: list[ProviderResult] = field(default_factory=list)
    skipped_reasons: list[str] = field(default_factory=list)
    degraded: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "results": [r.to_dict() for r in self.results],
            "degraded": sorted(set(self.degraded)),
        }


# ── cache ────────────────────────────────────────────────────────────────
_cache: dict[str, tuple[float, dict[str, Any]]] = {}


def _cache_get(key: str, ttl: int) -> dict[str, Any] | None:
    hit = _cache.get(key)
    if not hit:
        return None
    stored_ts, payload = hit
    if time.time() - stored_ts > ttl:
        _cache.pop(key, None)
        return None
    return payload


def _cache_put(key: str, payload: dict[str, Any], max_entries: int) -> None:
    if len(_cache) >= max_entries:
        # drop oldest (insertion order)
        next(iter(_cache)); _cache.pop(next(iter(_cache)))
    _cache[key] = (time.time(), payload)


# ── DNS provider (always) ────────────────────────────────────────────────

def dns_lookup(value: str, cfg: EnrichmentConfig, resolver: Any | None = None) -> dict[str, Any]:
    """A/AAAA/MX/TXT for one name. Returns evidence dict; never raises."""
    try:
        import dns.resolver
        rs = resolver or dns.resolver.Resolver()
        rs.lifetime = cfg.dns_timeout_seconds
        rs.timeout = cfg.dns_timeout_seconds
    except Exception as exc:  # dns not installed
        return {"status": "unavailable", "reason": f"dns-lib-error:{type(exc).__name__}"}

    out: dict[str, Any] = {"records": {}}
    missing = 0
    errored = 0
    for qtype in ("A", "AAAA", "MX", "TXT"):
        try:
            answer = rs.resolve(value, qtype, lifetime=cfg.dns_timeout_seconds)
            out["records"][qtype] = [r.to_text().strip('"') for r in answer][:5]
        except Exception as exc:
            name_t = type(exc).__name__
            if name_t in ("NXDOMAIN",):
                return {"status": "not_found", "reason": "NXDOMAIN"}
            missing += 1 if name_t in ("NoAnswer", "LifetimeTimeout") else 0
            errored += 1
            out["records"][qtype] = None
    if errored and not any(out["records"].values()):
        return {"status": "unavailable", "reason": f"dns-errors:{errored}",
                **({"dns_timeout": True} if "LifetimeTimeout" in str(out) else {})}
    if missing == 4:
        return {"status": "not_found", "reason": "no records of any type"}
    out["status"] = "ok"
    return out


# ── RDAP provider (optional, keyless) ────────────────────────────────────

def rdap_lookup(domain: str, cfg: EnrichmentConfig) -> dict[str, Any]:
    import httpx
    try:
        resp = httpx.get(cfg.rdap_base_url + domain, timeout=cfg.http_timeout_seconds,
                         follow_redirects=True)
        if resp.status_code == 404:
            return {"status": "not_found", "reason": "no RDAP record"}
        resp.raise_for_status()
        data = resp.json()
    except Exception as exc:
        code = getattr(exc, "response", None)
        if code is not None and code.status_code == 429:
            return {"status": "unavailable", "reason": "rate_limited", "retry_after": 60}
        return {"status": "unavailable", "reason": f"rdap-error:{type(exc).__name__}"}
    events = {e.get("eventAction"): e.get("eventDate") for e in data.get("events", []) if isinstance(e, dict)}
    registrar = next((ent.get("vcardArray") for ent in data.get("entities", [])
                      if "registrar" in (ent.get("roles") or [])), None)
    return {
        "status": "ok",
        "registrar_present": bool(registrar),
        "creation_date": events.get("registration"),
        "updated_date": events.get("last changed"),
    }


# ── IP geolocation (optional, keyless HTTP) ──────────────────────────────

def ipgeo_lookup(ip: str, cfg: EnrichmentConfig) -> dict[str, Any]:
    import httpx
    url = cfg.ipgeo_base_url.format(ip=ip)
    try:
        resp = httpx.get(url, timeout=cfg.http_timeout_seconds)
        if resp.status_code == 429:
            return {"status": "unavailable", "reason": "rate_limited", "retry_after": 60}
        resp.raise_for_status()
        data = resp.json()
    except Exception as exc:
        return {"status": "unavailable", "reason": f"ipgeo-error:{type(exc).__name__}"}
    if data.get("status") != "success":
        return {"status": "not_found", "reason": data.get("message") or "provider said not success"}
    return {
        "status": "ok",
        "network_location": {
            "country": data.get("country"),
            "region": data.get("regionName"),
            "city": data.get("city"),
            "isp": data.get("isp"),
            "org": data.get("org"),
            "as": data.get("as"),
        },
        "caveat": "infrastructure location only — does not identify a person",
    }


# ── gated adapters (credential-required → skipped without key) ───────────

def abuseipdb_lookup(ip: str, cfg: EnrichmentConfig) -> dict[str, Any]:
    if not cfg.abuseipdb_api_key:
        return {"status": "skipped", "reason": "ABUSEIPDB_API_KEY not configured"}
    return {"status": "skipped", "reason": "adapter not enabled in MVP — key present but client not implemented"}


def geoip2_lookup(ip: str, cfg: EnrichmentConfig) -> dict[str, Any]:
    if not cfg.maxmind_geoip2_db:
        return {"status": "skipped", "reason": "MAXMIND_GEOIP2_DB not configured"}
    return {"status": "skipped", "reason": "adapter not enabled in MVP — db-path present but reader not implemented"}


# ── orchestration ────────────────────────────────────────────────────────

_ENABLED_PROVIDERS: dict[str, Callable[[str, EnrichmentConfig], dict[str, Any]]] = {
    "dns": dns_lookup,
    "rdap": rdap_lookup,
    "ipgeo_http": ipgeo_lookup,
    "abuseipdb": abuseipdb_lookup,
    "geoip2_file": geoip2_lookup,
}


def _providers_for(ioc: Ioc, cfg: EnrichmentConfig) -> list[tuple[str, Callable]]:
    if ioc.kind == "hostname":
        return [("dns", _ENABLED_PROVIDERS["dns"])]
    if ioc.kind == "domain":
        return [("dns", _ENABLED_PROVIDERS["dns"]), ("rdap", _ENABLED_PROVIDERS["rdap"])]
    # ip
    outs: list[tuple[str, Callable]] = [("dns", _ENABLED_PROVIDERS["dns"])]  # PTR-ish: still A/TXT harmless, cheap skip via NXDOMAIN
    if not is_private_ip(ioc.value):
        outs.append(("ipgeo_http", _ENABLED_PROVIDERS["ipgeo_http"]))
        outs.append(("abuseipdb", _ENABLED_PROVIDERS["abuseipdb"]))
        outs.append(("geoip2_file", _ENABLED_PROVIDERS["geoip2_file"]))
    else:
        pass  # private: no public geo — deliberately not attempted
    return outs


def run_enrichment(
    parsed: ParsedEmail,
    forensic_ips: list[str] | None = None,
    cfg: EnrichmentConfig | None = None,
    limit_reason: str | None = None,
) -> tuple[EnrichmentResult, list[Ioc]]:
    """Returns (EnrichmentResult, normalized IOCs actually processed)."""
    cfg = cfg or get_enrichment_config()
    result = EnrichmentResult()

    iocs = collect_iocs(parsed, forensic_ips or [])
    # bound work
    if len(iocs) > cfg.max_iocs_per_analysis:
        result.degraded.append(f"ioc-count-truncated:{len(iocs)}→{cfg.max_iocs_per_analysis}")
        iocs = iocs[: cfg.max_iocs_per_analysis]

    budget = cfg.max_lookups_per_analysis
    for ioc in iocs:
        for pname, fn in _providers_for(ioc, cfg):
            if budget <= 0:
                result.degraded.append("lookup-budget-exhausted")
                return result, iocs
            cache_key = f"{pname}:{ioc.value}"
            raw = _cache_get(cache_key, cfg.cache_ttl_seconds)
            if raw is None:
                t0 = time.perf_counter()
                raw = fn(ioc.value, cfg)
                latency = int((time.perf_counter() - t0) * 1000)
                if raw.get("status") in ("ok", "not_found"):
                    _cache_put(cache_key, raw, cfg.cache_max_entries)
            else:
                latency = 0
            budget -= 1
            status = raw.get("status", "unavailable")
            result.results.append(ProviderResult(
                provider=pname,
                ioc_kind=ioc.kind,
                ioc_value=ioc.value,
                status=status,
                latency_ms=latency,
                evidence=raw,
                provenance=PROVENANCE.get(pname, pname),
            ))
            if status in ("unavailable", "skipped"):
                reason = raw.get("reason", "")
                if status == "unavailable":
                    result.degraded.append(f"{pname}:{reason}")
                else:
                    result.skipped_reasons.append(f"{pname}:{reason}")

    return result, iocs
