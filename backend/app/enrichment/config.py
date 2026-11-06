"""Enrichment configuration — env-only credentials and tuning, one place."""
from __future__ import annotations

import os
from dataclasses import dataclass, field


@dataclass(frozen=True)
class EnrichmentConfig:
    # ── Network behavior ────────────────────────────────────────────────
    dns_timeout_seconds: float = float(os.getenv("ENRICH_DNS_TIMEOUT", "10"))
    http_timeout_seconds: float = float(os.getenv("ENRICH_HTTP_TIMEOUT", "15"))
    cache_ttl_seconds: int = int(os.getenv("ENRICH_CACHE_TTL", "86400"))   # 24h
    cache_max_entries: int = int(os.getenv("ENRICH_CACHE_MAX", "512"))
    max_iocs_per_analysis: int = int(os.getenv("ENRICH_MAX_IOCS", "40"))
    max_lookups_per_analysis: int = int(os.getenv("ENRICH_MAX_LOOKUPS", "20"))

    # ── Adapter switches (present-key = enabled, so 'skipped' is explicit) ──
    enable_dns: bool = os.getenv("ENRICH_ENABLE_DNS", "1") not in ("0", "false")
    enable_rdap: bool = os.getenv("ENRICH_ENABLE_RDAP", "1") not in ("0", "false")
    enable_ipgeo: bool = os.getenv("ENRICH_ENABLE_IPGEO", "1") not in ("0", "false")
    # credibility adapters that REQUIRE credentials (skipped without them)
    abuseipdb_api_key: str | None = os.getenv("ABUSEIPDB_API_KEY") or None
    maxmind_geoip2_db: str | None = os.getenv("MAXMIND_GEOIP2_DB") or None

    rdap_base_url: str = os.getenv("ENRICH_RDAP_BASE", "https://rdap.org/domain/")
    ipgeo_base_url: str = os.getenv(
        "ENRICH_IPGEO_BASE", "http://ip-api.com/json/{ip}?fields=status,country,regionName,city,isp,org,as,query"
    )


_CONFIG: EnrichmentConfig | None = None


def get_enrichment_config() -> EnrichmentConfig:
    global _CONFIG
    if _CONFIG is None:
        _CONFIG = EnrichmentConfig()
    return _CONFIG
