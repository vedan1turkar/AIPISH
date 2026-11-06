"""Enrichment configuration — env-only credentials and tuning, one place.

Values are read when an EnrichmentConfig is created (not at import), through
app.core.config.env(): process environment first, then the repo-root .env.
Credential fields are excluded from repr so they never appear in logs.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from app.core.config import env


def _str(name: str, default: str) -> str:
    return env(name, default) or default


def _opt(name: str) -> str | None:
    return (env(name) or "").strip() or None


def _float(name: str, default: str) -> float:
    return float(_str(name, default))


def _int(name: str, default: str) -> int:
    return int(_str(name, default))


def _flag(name: str, default: str = "1") -> bool:
    return _str(name, default).strip().lower() not in ("0", "false")


def _secret():
    return field(default=None, repr=False)


@dataclass(frozen=True)
class EnrichmentConfig:
    # ── Network behavior ────────────────────────────────────────────────
    dns_timeout_seconds: float = field(default_factory=lambda: _float("ENRICH_DNS_TIMEOUT", "10"))
    http_timeout_seconds: float = field(default_factory=lambda: _float("ENRICH_HTTP_TIMEOUT", "15"))
    cache_ttl_seconds: int = field(default_factory=lambda: _int("ENRICH_CACHE_TTL", "86400"))   # 24h
    cache_max_entries: int = field(default_factory=lambda: _int("ENRICH_CACHE_MAX", "512"))
    max_iocs_per_analysis: int = field(default_factory=lambda: _int("ENRICH_MAX_IOCS", "40"))
    max_lookups_per_analysis: int = field(default_factory=lambda: _int("ENRICH_MAX_LOOKUPS", "20"))

    # ── Adapter switches (present-key = enabled, so 'skipped' is explicit) ──
    enable_dns: bool = field(default_factory=lambda: _flag("ENRICH_ENABLE_DNS"))
    enable_rdap: bool = field(default_factory=lambda: _flag("ENRICH_ENABLE_RDAP"))
    enable_ipgeo: bool = field(default_factory=lambda: _flag("ENRICH_ENABLE_IPGEO"))
    # credibility adapters that REQUIRE credentials (skipped without them)
    abuseipdb_api_key: str | None = field(default_factory=lambda: _opt("ABUSEIPDB_API_KEY"), repr=False)
    maxmind_geoip2_db: str | None = field(default_factory=lambda: _opt("MAXMIND_GEOIP2_DB"))
    # provider credentials loaded here; adapters not implemented yet
    virustotal_api_key: str | None = field(default_factory=lambda: _opt("VIRUSTOTAL_API_KEY"), repr=False)
    shodan_api_key: str | None = field(default_factory=lambda: _opt("SHODAN_API_KEY"), repr=False)
    ipinfo_token: str | None = field(default_factory=lambda: _opt("IPINFO_TOKEN"), repr=False)

    rdap_base_url: str = field(default_factory=lambda: _str("ENRICH_RDAP_BASE", "https://rdap.org/domain/"))
    ipgeo_base_url: str = field(default_factory=lambda: _str(
        "ENRICH_IPGEO_BASE", "http://ip-api.com/json/{ip}?fields=status,country,regionName,city,isp,org,as,query"
    ))

    def credential_status(self) -> dict[str, bool]:
        """Which credentials are configured — booleans only, never values."""
        return {
            "virustotal": self.virustotal_api_key is not None,
            "abuseipdb": self.abuseipdb_api_key is not None,
            "shodan": self.shodan_api_key is not None,
            "ipinfo": self.ipinfo_token is not None,
            "maxmind_geoip2_db": self.maxmind_geoip2_db is not None,
        }


_CONFIG: EnrichmentConfig | None = None


def get_enrichment_config() -> EnrichmentConfig:
    global _CONFIG
    if _CONFIG is None:
        _CONFIG = EnrichmentConfig()
    return _CONFIG


def reset_enrichment_config() -> None:
    """Forget the cached config so the next call re-reads the environment."""
    global _CONFIG
    _CONFIG = None
