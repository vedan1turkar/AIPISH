"""Combined risk configuration (P5h). Versioned: change CONFIG_VERSION whenever a value changes.

The ML-index thresholds were derived from the VALIDATION split only (see docs/risk/README.md §3 and
docs/risk/evaluation_v1.md); band edges are fixed.
"""
from __future__ import annotations

from dataclasses import dataclass, field

ENGINE_VERSION = "risk-engine-1.0"
CONFIG_VERSION = "risk-config-1.0"

LEVELS = ("minimal", "low", "medium", "high", "critical")
INDETERMINATE = "indeterminate"


@dataclass(frozen=True)
class RiskConfig:
    # band edges on the 0-100 combined score: level = highest band whose edge <= score
    edge_low: int = 10
    edge_medium: int = 25
    edge_high: int = 60
    edge_critical: int = 85
    # ML threat-index thresholds mapped onto the edges above (validation-derived; t_med <= 0.5 required)
    t_low: float = 0.10
    t_med: float = 0.36
    t_high: float = 0.50
    t_crit: float = 0.90
    ml_side_threshold: float = 0.5        # p >= this => ML on the threat side
    high_confidence_ml: float = 0.80      # ML top-class confidence needed for "high" confidence
    hard_floor: int = 60                  # every hard-evidence floor (= high)
    conflict_floor: int = 25              # medium
    suspicious_floor: int = 10            # low
    missing_primary_floor: int = 10       # low: missing rules or ML never yields minimal
    intel_strong_points: int = 10
    intel_soft_points: int = 5
    intel_strong_floor: int = 25          # medium
    intel_cap: int = 15
    strong_intel_providers: frozenset[str] = frozenset({"virustotal", "abuseipdb"})
    soft_intel_providers: frozenset[str] = frozenset({"tor_exit_list", "ipinfo", "shodan"})
    identity_rules: frozenset[str] = frozenset({"sender_reply_to_mismatch", "lookalike_domain",
                                                "auth_dmarc_misaligned"})
    lure_rules: frozenset[str] = frozenset({"payment_diversion", "credential_request"})
    cue_rules: tuple[str, ...] = ("urgency_language", "credential_request", "payment_diversion",
                                  "all_caps_pressure")
    extra: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {"edges": {"low": self.edge_low, "medium": self.edge_medium, "high": self.edge_high,
                          "critical": self.edge_critical},
                "ml_thresholds": {"t_low": self.t_low, "t_med": self.t_med, "t_high": self.t_high,
                                  "t_crit": self.t_crit}}


_CONFIG = RiskConfig()


def get_config() -> RiskConfig:
    return _CONFIG
