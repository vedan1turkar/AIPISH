"""Header-forensics configuration — the single place for thresholds + confidence.

Every confidence rule is evidence-based and documented; the numeric values here
are referenced from FORENSICS_NOTES.md so analysts can audit the weights.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class ForensicsConfig:
    # ── Hop-confidence points (0-100, clamped) ─────────────────────────
    # Each rule's rationale lives inline; the table is mirrored in FORENSICS_NOTES.md.
    conf_public_ip: int = 20            # from-IP is publicly routable
    conf_host_ip_consistent: int = 15   # from-host present alongside an IP (pairing)
    conf_tls: int = 10                  # TLS mentioned in the hop
    conf_has_timestamp: int = 10        # parseable timestamp
    conf_trusted_boundary: int = 25     # hop at/after the trusted boundary
    conf_untrusted_penalty: int = 0     # untrusted hops don't gain the boundary bonus; capped instead
    untrusted_cap: int = 40             # hard ceiling for hops before the boundary
    penalty_missing_hosts: int = 15     # both from/by missing
    penalty_binary_garbage: int = 10    # raw value had non-text garbage

    # minimum confidence for a candidate IP to be treated as VERIFIED origin
    verified_origin_min_confidence: int = 60

    # ── Chain sanity ────────────────────────────────────────────────────
    max_expected_hops: int = 10         # > this → excess_hops finding

    # ── Inconsistency severities (fixed by rule, configurable severity) ──
    severity_returnpath_mismatch: str = "medium"
    severity_messageid_mismatch: str = "low"
    severity_replyto_mismatch: str = "medium"
    severity_received_spf: str = "medium"
    severity_excess_hops: str = "low"
    severity_no_received: str = "info"

    # ── Local-MX patterns for trusted-boundary detection ─────────────────
    # A hop is `trusted` if its `by` host matches one of these shapes or belongs
    # to the receiver's own domain. Configure for your actual MX fleet.
    local_mx_patterns: tuple[str, ...] = ("mx.", "mail.", "smtp.", "mx1.", "mx2.")
    receiver_domain: str | None = None  # set at runtime from To/Cc or config


_CONFIG: ForensicsConfig | None = None


def get_forensics_config() -> ForensicsConfig:
    global _CONFIG
    if _CONFIG is None:
        _CONFIG = ForensicsConfig()
    return _CONFIG
