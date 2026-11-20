"""Correlation configuration: link strength per indicator, thresholds, stoplist (P5c).

All values are documented in docs/correlation/README.md and can be overridden by env.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from app.core.config import env

STRONG, MEDIUM, WEAK = "strong", "medium", "weak"
TIER_RANK = {WEAK: 1, MEDIUM: 2, STRONG: 3}

# (entity type, role) → (tier, weight). Weight is a probability-like strength in [0, 1];
# a pair's score combines independent indicators as 1 − Π(1 − w).
LINK_STRENGTH: dict[tuple[str, str], tuple[str, float]] = {
    ("attachment_hash", "attachment_sha256"): (STRONG, 0.90),
    ("public_ip", "origin_candidate_ip"): (MEDIUM, 0.60),        # "medium-strong"
    ("url_host", "url_host"): (MEDIUM, 0.50),
    ("public_ip", "url_host_ip"): (MEDIUM, 0.50),                # URL pointing at a bare public IP
    ("reply_to_domain", "reply_to_domain"): (MEDIUM, 0.50),
    ("return_path_domain", "return_path_domain"): (WEAK, 0.30),
    ("sender_domain", "sender_domain"): (WEAK, 0.30),
    ("message_id_domain", "message_id_domain"): (WEAK, 0.15),
    ("public_ip", "relay_ip"): (WEAK, 0.15),
    ("display_name_alias", "display_name"): (WEAK, 0.10),
}
DOMAIN_TYPES = {"sender_domain", "reply_to_domain", "return_path_domain", "message_id_domain", "url_host"}

STOPLIST_FILE = Path(__file__).with_name("stoplist.txt")


def _int(name: str, default: int) -> int:
    try:
        return max(1, int(env(name, str(default)) or default))
    except ValueError:
        return default


def load_stoplist() -> frozenset[str]:
    path = Path(env("AIPISH_CORR_STOPLIST_FILE") or STOPLIST_FILE)
    items: set[str] = set()
    if path.is_file():
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.split("#", 1)[0].strip().lower().rstrip(".")
            if line:
                items.add(line)
    for extra in (env("AIPISH_CORR_STOPLIST_EXTRA") or "").split(","):
        if extra.strip():
            items.add(extra.strip().lower().rstrip("."))
    return frozenset(items)


@dataclass(frozen=True)
class CorrelationConfig:
    stoplist: frozenset[str] = field(default_factory=load_stoplist)
    # document-frequency damping: an entity seen in more than df_soft analyses loses half its
    # weight and one tier; above df_max it is treated as generic (no link strength at all).
    df_soft: int = field(default_factory=lambda: _int("AIPISH_CORR_DF_SOFT", 10))
    df_max: int = field(default_factory=lambda: _int("AIPISH_CORR_DF_MAX", 25))
    high_threshold: float = 0.85
    medium_threshold: float = 0.60
    max_related: int = 50

    def is_stoplisted(self, domain: str | None) -> bool:
        if not domain:
            return False
        d = domain.lower().rstrip(".")
        return any(d == s or d.endswith("." + s) for s in self.stoplist)

    def confidence_label(self, score: float, has_strong: bool) -> str:
        if has_strong or score >= self.high_threshold:
            return "high"
        return "medium" if score >= self.medium_threshold else "low"


_CONFIG: CorrelationConfig | None = None


def get_correlation_config() -> CorrelationConfig:
    global _CONFIG
    if _CONFIG is None:
        _CONFIG = CorrelationConfig()
    return _CONFIG


def reset_correlation_config() -> None:
    global _CONFIG
    _CONFIG = None
