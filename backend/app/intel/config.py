"""Threat-intel configuration — env-only credentials and tuning (P5a).

Read through app.core.config.env(): process environment first, then the
repo-root .env. Credentials live only in this object: they are excluded from
repr, never serialised, never logged and never returned by the API — the
status endpoint exposes booleans only.

Endpoint overrides (``INTEL_*_BASE``) exist so tests and the local simulated
provider can point adapters at a loopback stub. A base URL is accepted only if
it is HTTPS, or plain HTTP to a loopback host; anything else disables that
provider, so a mis-set variable can never send a key over cleartext.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urlsplit

from app.core.config import env, get_settings

PROVIDERS = ("virustotal", "abuseipdb", "shodan", "ipinfo", "tor_exit_list")
LABELS = {
    "virustotal": "VirusTotal",
    "abuseipdb": "AbuseIPDB",
    "shodan": "Shodan",
    "ipinfo": "IPinfo",
    "tor_exit_list": "Tor exit list",
}
# Externally blocked in P5a: shown as "not configured", never called.
NOT_CONFIGURED = {
    "maxmind_geoip2": "MaxMind GeoIP2 — no licence key / database configured (out of scope for P5a)",
    "misp": "MISP — no MISP instance available (out of scope for P5a)",
}


def _s(name: str, default: str) -> str:
    v = env(name, default)
    return default if v is None or not str(v).strip() else str(v).strip()


def _opt(name: str) -> str | None:
    return (env(name) or "").strip() or None


def _i(name: str, default: int) -> int:
    try:
        return int(_s(name, str(default)))
    except ValueError:
        return default


def _f(name: str, default: float) -> float:
    try:
        return float(_s(name, str(default)))
    except ValueError:
        return default


def _flag(name: str, default: bool) -> bool:
    return _s(name, "1" if default else "0").lower() not in ("0", "false", "no", "off")


def _secret(name: str):
    return field(default_factory=lambda: _opt(name), repr=False, compare=False)


def endpoint_allowed(url: str) -> bool:
    """HTTPS anywhere, or HTTP to a loopback host only (local stub / tests)."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return False
    if parts.username or parts.password or not parts.hostname:
        return False
    if parts.scheme == "https":
        return True
    return parts.scheme == "http" and parts.hostname in ("127.0.0.1", "localhost", "::1")


def _default_offline() -> bool:
    if (get_settings().env or "").lower() in ("offline", "demo"):     # P5i: the demo never calls providers
        return True
    return _flag("INTEL_OFFLINE", False)


@dataclass(frozen=True)
class IntelConfig:
    offline: bool = field(default_factory=_default_offline)

    connect_timeout_seconds: float = field(default_factory=lambda: _f("INTEL_CONNECT_TIMEOUT", 5.0))
    read_timeout_seconds: float = field(default_factory=lambda: _f("INTEL_READ_TIMEOUT", 10.0))
    retry_backoff_seconds: float = field(default_factory=lambda: _f("INTEL_RETRY_BACKOFF", 0.5))
    max_iocs_per_analysis: int = field(default_factory=lambda: max(1, _i("INTEL_MAX_IOCS", 20)))

    # cache TTLs (seconds)
    ttl_ip_seconds: int = field(default_factory=lambda: _i("INTEL_TTL_IP", 86_400))          # 24 h
    ttl_domain_seconds: int = field(default_factory=lambda: _i("INTEL_TTL_DOMAIN", 86_400))  # 24 h
    ttl_hash_seconds: int = field(default_factory=lambda: _i("INTEL_TTL_HASH", 604_800))     # 7 d
    ttl_shodan_seconds: int = field(default_factory=lambda: _i("INTEL_TTL_SHODAN", 86_400))  # 24 h
    ttl_tor_seconds: int = field(default_factory=lambda: _i("INTEL_TTL_TOR", 10_800))        # 3 h

    # per-provider rate limits (requests / minute) and daily quotas
    vt_per_minute: int = field(default_factory=lambda: _i("INTEL_VT_PER_MINUTE", 4))
    vt_per_day: int = field(default_factory=lambda: _i("INTEL_VT_PER_DAY", 500))
    abuseipdb_per_minute: int = field(default_factory=lambda: _i("INTEL_ABUSEIPDB_PER_MINUTE", 30))
    abuseipdb_per_day: int = field(default_factory=lambda: _i("INTEL_ABUSEIPDB_PER_DAY", 1000))
    shodan_per_minute: int = field(default_factory=lambda: _i("INTEL_SHODAN_PER_MINUTE", 60))
    shodan_per_day: int = field(default_factory=lambda: _i("INTEL_SHODAN_PER_DAY", 100))
    ipinfo_per_minute: int = field(default_factory=lambda: _i("INTEL_IPINFO_PER_MINUTE", 60))
    ipinfo_per_day: int = field(default_factory=lambda: _i("INTEL_IPINFO_PER_DAY", 1500))
    tor_per_minute: int = field(default_factory=lambda: _i("INTEL_TOR_PER_MINUTE", 2))
    tor_per_day: int = field(default_factory=lambda: _i("INTEL_TOR_PER_DAY", 48))

    abuseipdb_flag_threshold: int = field(default_factory=lambda: _i("INTEL_ABUSEIPDB_FLAG_THRESHOLD", 25))
    abuseipdb_max_age_days: int = field(default_factory=lambda: _i("INTEL_ABUSEIPDB_MAX_AGE_DAYS", 90))

    # endpoints (overridable for a loopback stub only — see endpoint_allowed)
    vt_base: str = field(default_factory=lambda: _s("INTEL_VT_BASE", "https://www.virustotal.com/api/v3"))
    abuseipdb_base: str = field(default_factory=lambda: _s("INTEL_ABUSEIPDB_BASE", "https://api.abuseipdb.com/api/v2"))
    shodan_base: str = field(default_factory=lambda: _s("INTEL_SHODAN_BASE", "https://api.shodan.io"))
    ipinfo_base: str = field(default_factory=lambda: _s("INTEL_IPINFO_BASE", "https://ipinfo.io"))
    tor_list_url: str = field(default_factory=lambda: _s(
        "INTEL_TOR_LIST_URL", "https://check.torproject.org/torbulkexitlist"))

    # switches (a provider runs only when enabled AND configured)
    enable_virustotal: bool = field(default_factory=lambda: _flag("INTEL_ENABLE_VIRUSTOTAL", True))
    enable_abuseipdb: bool = field(default_factory=lambda: _flag("INTEL_ENABLE_ABUSEIPDB", True))
    enable_shodan: bool = field(default_factory=lambda: _flag("INTEL_ENABLE_SHODAN", True))
    enable_ipinfo: bool = field(default_factory=lambda: _flag("INTEL_ENABLE_IPINFO", True))
    enable_tor_exit_list: bool = field(default_factory=lambda: _flag("INTEL_ENABLE_TOR", True))

    # Set only by the local simulated-provider launcher; surfaced in every run.
    simulated: bool = field(default_factory=lambda: _flag("INTEL_SIMULATED", False))

    # credentials — repr=False; never serialised
    virustotal_api_key: str | None = _secret("VIRUSTOTAL_API_KEY")
    abuseipdb_api_key: str | None = _secret("ABUSEIPDB_API_KEY")
    shodan_api_key: str | None = _secret("SHODAN_API_KEY")
    ipinfo_token: str | None = _secret("IPINFO_TOKEN")

    def credential(self, provider: str) -> str | None:
        return {
            "virustotal": self.virustotal_api_key,
            "abuseipdb": self.abuseipdb_api_key,
            "shodan": self.shodan_api_key,
            "ipinfo": self.ipinfo_token,
        }.get(provider)

    def base_url(self, provider: str) -> str:
        return {
            "virustotal": self.vt_base,
            "abuseipdb": self.abuseipdb_base,
            "shodan": self.shodan_base,
            "ipinfo": self.ipinfo_base,
            "tor_exit_list": self.tor_list_url,
        }[provider]

    def configured(self, provider: str) -> bool:
        if provider == "tor_exit_list":
            return True          # public list, no credential
        return self.credential(provider) is not None

    def switched_on(self, provider: str) -> bool:
        return bool(getattr(self, f"enable_{provider}", False))

    def endpoint_ok(self, provider: str) -> bool:
        return endpoint_allowed(self.base_url(provider))

    def enabled(self, provider: str) -> bool:
        return self.switched_on(provider) and self.configured(provider) and self.endpoint_ok(provider)

    def limits(self, provider: str) -> tuple[int, int]:
        short = {"virustotal": "vt", "abuseipdb": "abuseipdb", "shodan": "shodan",
                 "ipinfo": "ipinfo", "tor_exit_list": "tor"}[provider]
        return getattr(self, f"{short}_per_minute"), getattr(self, f"{short}_per_day")

    def status(self) -> dict:
        """Booleans only — safe to return from the API."""
        providers = {
            p: {"label": LABELS[p], "configured": self.configured(p), "enabled": self.enabled(p),
                "requires_credentials": p != "tor_exit_list"}
            for p in PROVIDERS
        }
        for p, note in NOT_CONFIGURED.items():
            providers[p] = {"label": note.split(" — ")[0], "configured": False, "enabled": False,
                            "requires_credentials": True, "note": note}
        return {
            "offline": self.offline,
            "simulated": self.simulated,
            "consent_required": True,
            "consent_default": False,
            "max_iocs_per_analysis": self.max_iocs_per_analysis,
            "informational_only": True,
            "providers": providers,
        }


_CONFIG: IntelConfig | None = None


def get_intel_config() -> IntelConfig:
    global _CONFIG
    if _CONFIG is None:
        _CONFIG = IntelConfig()
    return _CONFIG


def reset_intel_config() -> None:
    global _CONFIG
    _CONFIG = None
