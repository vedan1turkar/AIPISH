"""Infrastructure-intelligence enrichment.

Scope: normalize/validate IOCs from the parsed message (IPs, sender domain,
URL hosts, mail domains) and enrich them with:
- DNS A / AAAA / MX / TXT lookups (always available, offline-testable),
- RDAP registration data for domains (optional, keyless),
- IP geolocation via a keyless HTTP provider (optional),
later adapters implementable behind the same ProviderResult envelope.

Principles:
- credentials ONLY from environment variables; missing credentials yield a
  ``skipped`` status (with reason), never an exception;
- every result carries provider, latency_ms, status, evidence, provenance;
- network timeouts everywhere; results cached in-process per key;
- private/loopback/etc. IPs are NEVER given public geo data;
- geolocation identifies network infrastructure, never a person.
"""
from app.enrichment.engine import (
    EnrichmentConfig,
    EnrichmentResult,
    run_enrichment,
)
from app.enrichment.config import get_enrichment_config
from app.enrichment.iocs import collect_iocs, normalize_domain, normalize_ip

__all__ = [
    "EnrichmentConfig",
    "EnrichmentResult",
    "run_enrichment",
    "get_enrichment_config",
    "collect_iocs",
    "normalize_domain",
    "normalize_ip",
]
