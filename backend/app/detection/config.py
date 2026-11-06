"""Detection configuration — the single place to tune weights and thresholds.

All weights are raw 0-100 points; the engine caps each rule at its max and the
final aggregate at 100. Bands are the only thresholds that decide a verdict.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class DetectionConfig:
    # ── Verdict bands (bounded score 0-100) ─────────────────────────────
    band_minimal_max: int = 24          # 0-24    → minimal
    band_suspicious_min: int = 25       # 25-59   → suspicious
    band_suspicious_max: int = 59
    band_phishing_min: int = 60         # 60-100  → phishing/fraud likely

    # ── Per-rule weights (0-100) and the observed-fact vs heuristic tag ──
    # trust tags: "fact" = provable from message bytes (structural match)
    #             "heuristic" = judgment on noisy evidence (lexicon, similarity)
    weights: dict[str, int] = field(default_factory=lambda: {
        # URL indicators
        "ip_literal_url": 30,               # fact
        "url_obfuscation": 25,              # heuristic (decoy chars/domain-in-text)
        "suspicious_url_structure": 15,     # heuristic (TLD, shortener, creds, punycode)
        # sender indicators
        "lookalike_domain": 35,             # heuristic  (fired only with a reliable reference)
        "sender_reply_to_mismatch": 35,     # fact       (different reply-to domain)
        # content indicators
        "urgency_language": 20,             # heuristic (lexicon)
        "credential_request": 25,           # heuristic (lexicon)
        "payment_diversion": 25,            # heuristic (lexicon)
        "all_caps_pressure": 15,            # heuristic (formatting pressure)
        # attachment indicators
        "risky_attachment_type": 30,        # fact
        # header indicators
        "header_inconsistency": 20,         # fact-based (measured, but interpretation is a judgment)
        # authentication bridging (weak, never alone)
        "auth_failure_support": 10,         # fact
        # header-forensics / authentication bridging (transparent weights)
        "header_inconsistency_forensics": 20,   # fact (measured from forensics module)
        "auth_conflict": 20,                # heuristic — header claims conflict with live results
        "auth_verified_fail": 15,           # fact — locally re-verified fail (not merely claimed)
        "auth_dmarc_misaligned": 20,        # heuristic — alignment check failed
        # enrichment bridging (fires only on corroborating evidence, not on
        # provider availability/skips)
        "ip_url_risky_lookup": 20,          # heuristic — public URL-host IP with no A/PTR DNS shape or non-global
        "domain_no_mx_shortlived": 15,      # heuristic — sender domain with no MX AND very recent RDAP creation
    })

    max_findings: int = 50
    score_cap: int = 100

    # ── Lexicons & lists (data-as-config) ────────────────────────────────
    urgency_terms: tuple[str, ...] = (
        "urgent", "immediately", "act now", "within 24 hours", "asap",
        "final warning", "expires today", "limited time", "last chance",
        "immediate action", "right away",
    )
    credential_terms: tuple[str, ...] = (
        "password", "verify your account", "confirm your identity",
        "login credentials", "enter your password", "update your payment details",
        "confirm your billing", "validate your identity",
    )
    payment_terms: tuple[str, ...] = (
        "wire transfer", "change of bank details", "banking details",
        "update payment", "new account number", "invoice attached",
        "payment diverted", "remit to", "gift card",
    )
    risky_attachment_exts: frozenset[str] = frozenset({
        ".exe", ".scr", ".bat", ".cmd", ".js", ".jse", ".vbs", ".vbe",
        ".ps1", ".psm1", ".hta", ".msi", ".com", ".pif", ".cpl",
        ".docm", ".xlsm", ".pptm", ".jar", ".iso", ".img", ".lnk",
    })
    shortener_hosts: frozenset[str] = frozenset({
        "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
        "rebrand.ly", "shorturl.at", "cutt.ly",
    })
    suspicious_tlds: frozenset[str] = frozenset({
        ".zip", ".top", ".xyz", ".click", ".country", ".kim", ".men", ".work",
        ".loan", ".date", ".racing", ".download", ".stream",
    })
    # Brand-lookalike references (registered-domain dictionary); a lookalike rule
    # only fires when the sender domain differs from a listed brand but is
    # similar: edit-distance ≤2 on ≤7 chars or codestyle substitutions.
    brand_domains: tuple[str, ...] = (
        "paypal.com", "google.com", "microsoft.com", "apple.com",
        "amazon.com", "netflix.com", "linkedin.com", "facebook.com",
        "hsbc.com", "chase.com", "wellsfargo.com", "outlook.com",
    )
    lookalike_max_edit_distance: int = 2
    lookalike_max_brand_len: int = 7      # edit distance only reliable on short names
    lookalike_char_subs: dict[str, str] = field(default_factory=lambda: {
        "1": "l", "0": "o", "5": "s", "3": "e", "8": "b", "$": "s", "@": "a",
    })
    # Header inconsistency knobs
    min_reply_to_domain_len: int = 4     # guard: reply-to domain must be >= 4 chars


_CONFIG: DetectionConfig | None = None


def get_config() -> DetectionConfig:
    """Process-wide config (identical inputs → identical rule sets)."""
    global _CONFIG
    if _CONFIG is None:
        _CONFIG = DetectionConfig()
    return _CONFIG
