"""Threat-intelligence provider integrations (P5a).

VirusTotal, AbuseIPDB, Shodan, IPinfo and the Tor bulk exit list behind one
``Provider.lookup`` interface with distinct statuses, consent gating, offline
mode, strict indicator validation, DB-backed caching with stale fallback,
per-provider rate limits / daily quotas and credential redaction.
MaxMind GeoIP2 and MISP are out of scope (externally blocked) and are reported
as "not configured". Results are informational only.
"""
from app.intel.config import IntelConfig, get_intel_config, reset_intel_config
from app.intel.service import extract_indicators, run_threat_intel

__all__ = ["IntelConfig", "get_intel_config", "reset_intel_config", "extract_indicators", "run_threat_intel"]
