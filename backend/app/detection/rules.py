"""Rule implementations — one function per weighted indicator.

Each rule returns ``None`` (observation neutral / not fired) or a Finding with:
- severity, evidence (a quoted excerpt or structural fact), rationale (why it
  matters), contribution (exact points added), knowledge ("fact"/"heuristic").
Rules never see raw attachment bytes and never perform network I/O.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from app.detection.config import DetectionConfig
from app.detection.fs_model import FeatureModel, _levenshtein, _norm_domain

NOTFIRED = None


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str                    # info | low | medium | high | critical
    weight: int                      # rule weight from config
    contribution: int                # points actually added (≤ weight)
    knowledge: str                   # fact | heuristic
    title: str
    evidence: str                    # quoted excerpt or structural fact
    rationale: str                   # why this matters, analyst-facing

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "weight": self.weight,
            "contribution": self.contribution,
            "knowledge": self.knowledge,
            "title": self.title,
            "evidence": self.evidence,
            "rationale": self.rationale,
        }


# ── URL rules ──────────────────────────────────────────────────────────────

def ip_literal_url(f: FeatureModel, cfg: DetectionConfig) -> Finding | None:
    hits = [u for u in f.urls if u.is_ip_literal]
    if not hits:
        return NOTFIRED
    return Finding(
        rule_id="ip_literal_url",
        severity="high",
        weight=cfg.weights["ip_literal_url"],
        contribution=cfg.weights["ip_literal_url"],
        knowledge="fact",
        title="IP-literal URL",
        evidence=f"link target is a raw IP address: {hits[0].host}",
        rationale="Legitimate consumer mail rarely links to bare IPs; "
                  "attackers use them to bypass brand/domain reputation.",
    )


def url_obfuscation(f: FeatureModel, cfg: DetectionConfig) -> Finding | None:
    hits: list[str] = []
    # zero-width/invisible characters in the ORIGINAL URL text (the parser
    # strips them before the URL reaches us; the count is measured upstream)
    if f.obfuscated_url_count > 0:
        hits.append(
            f"{f.obfuscated_url_count} URL(s) contained invisible zero-width characters "
            "in the original message (stripped before analysis)"
        )
    for u in f.urls:
        if u.percent_encoded_ratio > 0.35 and "%" in u.raw:
            hits.append(f"heavy percent-encoding ({int(u.percent_encoded_ratio*100)}%): {u.raw[:60]}")
    if not hits:
        return NOTFIRED
    return Finding(
        rule_id="url_obfuscation",
        severity="medium",
        weight=cfg.weights["url_obfuscation"],
        contribution=cfg.weights["url_obfuscation"],
        knowledge="heuristic",
        title="URL obfuscation",
        evidence=hits[0],
        rationale="Encoding tricks or zero-width characters are used to hide a "
                  "link's true destination from the reader.",
    )


def suspicious_url_structure(f: FeatureModel, cfg: DetectionConfig) -> Finding | None:
    reasons: list[str] = []
    for u in f.urls:
        if u.is_shortener:
            reasons.append(f"link shortener: {u.host}")
        elif u.has_punycode:
            reasons.append(f"punycode host (possible homograph): {u.host}")
        elif u.suspicious_tld:
            reasons.append(f"suspicious TLD {u.suspicious_tld} on {u.host}")
        elif u.has_credentials:
            reasons.append(f"credentials embedded in URL: {u.host}")
    if not reasons:
        return NOTFIRED
    return Finding(
        rule_id="suspicious_url_structure",
        severity="medium",
        weight=cfg.weights["suspicious_url_structure"],
        contribution=cfg.weights["suspicious_url_structure"],
        knowledge="heuristic",
        title="Suspicious URL structure",
        evidence=reasons[0],
        rationale="Shorteners hide destinations; punycode and odd TLDs are "
                  "commonly abused for lookalike link hosts; embedded "
                  "credentials are never legitimate.",
    )


# ── Sender rules ───────────────────────────────────────────────────────────

def lookalike_domain(f: FeatureModel, cfg: DetectionConfig) -> Finding | None:
    """Fires only when a *reliable* comparison is available."""
    sender_domain = f.from_domain
    if not sender_domain:
        return NOTFIRED
    # no reference without a brand in the display name — do not guess
    reference = f.from_display_name_brand
    if not reference:
        return NOTFIRED

    sender_reg = _norm_domain(sender_domain)
    ref_reg = _norm_domain(reference)
    if sender_reg == ref_reg:
        return NOTFIRED

    # registered name without TLD — take the first label so hyphenated
    # attacker hosts (paypa1-secure.com) compare against the brand (paypal).
    s_name = sender_reg.split(".")[0].split("-")[0]
    r_name = ref_reg.split(".")[0]
    distance = _levenshtein(s_name, r_name, cfg.lookalike_max_edit_distance)

    # substitution tricks on the visible name (paypa1 vs paypal)
    s_decoy = "".join(cfg.lookalike_char_subs.get(c, c) for c in s_name)
    r_decoy = "".join(cfg.lookalike_char_subs.get(c, c) for c in r_name)
    decoy_equal = s_decoy == r_decoy

    similar = (
        decoy_equal
        or (distance <= cfg.lookalike_max_edit_distance and len(r_name) <= cfg.lookalike_max_brand_len)
        or (r_name in sender_reg and len(r_name) >= 4)   # brand word embedded anywhere in the domain
    )
    if not similar:
        return NOTFIRED
    return Finding(
        rule_id="lookalike_domain",
        severity="high",
        weight=cfg.weights["lookalike_domain"],
        contribution=cfg.weights["lookalike_domain"],
        knowledge="heuristic",
        title="Lookalike sender domain",
        evidence=f"display name claims brand '{ref_reg.split('.')[0]}' but mail comes from '{sender_reg}'",
        rationale="Display-name impersonation plus a near-miss domain is the "
                  "classic spoofing pattern; the sending domain is not the "
                  "brand it claims in the visible name.",
    )


def sender_reply_to_mismatch(f: FeatureModel, cfg: DetectionConfig) -> Finding | None:
    if not f.sender_and_reply_domains_differ:
        return NOTFIRED
    rt = f.reply_to_domains[0]
    return Finding(
        rule_id="sender_reply_to_mismatch",
        severity="high",
        weight=cfg.weights["sender_reply_to_mismatch"],
        contribution=cfg.weights["sender_reply_to_mismatch"],
        knowledge="fact",
        title="Reply-To differs from sender domain",
        evidence=f"From: {f.from_domain} → Reply-To: {rt}",
        rationale="Replies would be diverted to an unrelated domain — a BEC "
                  "signature when the visible sender looks internal or trusted.",
    )


# ── Content rules ──────────────────────────────────────────────────────────

def _lexicon_hits(text: str, terms: tuple[str, ...]) -> list[str]:
    low = text.lower()
    return [t for t in terms if t in low]


def urgency_language(f: FeatureModel, cfg: DetectionConfig) -> Finding | None:
    hits = _lexicon_hits(f.text, cfg.urgency_terms) + _lexicon_hits(f.subject, cfg.urgency_terms)
    if not hits:
        return NOTFIRED
    return Finding(
        rule_id="urgency_language",
        severity="medium",
        weight=cfg.weights["urgency_language"],
        contribution=cfg.weights["urgency_language"],
        knowledge="heuristic",
        title="Urgency / pressure language",
        evidence=f"matched {len(hits)} phrase(s), e.g. “{hits[0]}”",
        rationale="Manufactured urgency short-circuits careful reading — a "
                  "core social-engineering technique.",
    )


def credential_request(f: FeatureModel, cfg: DetectionConfig) -> Finding | None:
    hits = _lexicon_hits(f.text, cfg.credential_terms)
    if not hits:
        return NOTFIRED
    return Finding(
        rule_id="credential_request",
        severity="high",
        weight=cfg.weights["credential_request"],
        contribution=cfg.weights["credential_request"],
        knowledge="heuristic",
        title="Credential request",
        evidence=f"matched {len(hits)} phrase(s), e.g. “{hits[0]}”",
        rationale="Asks the recipient to surrender credentials or identity "
                  "data — the payload of most phishing and BEC lures.",
    )


def payment_diversion(f: FeatureModel, cfg: DetectionConfig) -> Finding | None:
    hits = _lexicon_hits(f.text, cfg.payment_terms)
    if not hits:
        return NOTFIRED
    return Finding(
        rule_id="payment_diversion",
        severity="high",
        weight=cfg.weights["payment_diversion"],
        contribution=cfg.weights["payment_diversion"],
        knowledge="heuristic",
        title="Payment-diversion / BEC language",
        evidence=f"matched {len(hits)} phrase(s), e.g. “{hits[0]}”",
        rationale="Bank-detail changes, wire instructions, or gift-card asks "
                  "are the monetisation step of BEC fraud.",
    )


def all_caps_pressure(f: FeatureModel, cfg: DetectionConfig) -> Finding | None:
    words = re.findall(r"\b[A-Z]{4,}\b", f.subject) if f.subject else []
    if len(words) < 1:
        return NOTFIRED
    return Finding(
        rule_id="all_caps_pressure",
        severity="low",
        weight=cfg.weights["all_caps_pressure"],
        contribution=cfg.weights["all_caps_pressure"],
        knowledge="heuristic",
        title="Shouty ALL-CAPS subject",
        evidence=f"caps words in subject: {', '.join(words[:3])}",
        rationale="All-caps emphasis is a cheap attention-forcing device "
                  "common in bulk fraud mail.",
    )


# ── Attachment rules ───────────────────────────────────────────────────────

def risky_attachment_type(f: FeatureModel, cfg: DetectionConfig) -> Finding | None:
    if not f.risky_attachment_names:
        return NOTFIRED
    return Finding(
        rule_id="risky_attachment_type",
        severity="high",
        weight=cfg.weights["risky_attachment_type"],
        contribution=cfg.weights["risky_attachment_type"],
        knowledge="fact",
        title="Risky attachment type",
        evidence=f"attachment(s): {', '.join(f.risky_attachment_names[:3])}",
        rationale="Executable / macro-enabled / container formats are the "
                  "dominant malware-delivery vector and never needed for "
                  "ordinary correspondence.",
    )


# ── Header rules ───────────────────────────────────────────────────────────

def header_inconsistency(f: FeatureModel, cfg: DetectionConfig) -> Finding | None:
    """Measured, byte-provable inconsistencies. Each has a bounded cap."""
    issues: list[str] = []
    # multiple Reply-To with different domains invites diversion confusion
    if len(set(f.reply_to_domains)) > 1:
        issues.append(f"multiple Reply-To domains: {sorted(set(f.reply_to_domains))[:2]}")
    # double From headers (header_counts carries 'from')
    if f.header_counts.get("from", 0) > 1:
        issues.append(f"{f.header_counts['from']} From headers present")
    # many Received headers without any can indicate insertion
    if f.header_counts.get("received", 0) >= 12:
        issues.append(f"unusually many Received headers ({f.header_counts['received']})")
    if not issues:
        return NOTFIRED
    return Finding(
        rule_id="header_inconsistency",
        severity="medium",
        weight=cfg.weights["header_inconsistency"],
        contribution=cfg.weights["header_inconsistency"],
        knowledge="fact",
        title="Header inconsistency",
        evidence=issues[0],
        rationale="Conflicting or excessive routing headers are used to "
                  "confuse relay forensics or defeat spoofing checks.",
    )


def auth_failure_support(f: FeatureModel, cfg: DetectionConfig) -> Finding | None:
    """Bridged, low-weight signal from Authentication-Results headers.

    Never fires alone as 'the email is bad'; adds 10 points max, and only when
    a fail result is *reported by the message's own Authentication-Results
    header* — evidence that something upstream already flunked a check.
    """
    fails: list[str] = []
    for raw in f.raw_authentication_results:
        low = raw.lower()
        for token in ("spf=fail", "dmarc=fail", "dkim=fail"):
            if token in low:
                fails.append(token)
    if not fails:
        return NOTFIRED
    return Finding(
        rule_id="auth_failure_support",
        severity="low",
        weight=cfg.weights["auth_failure_support"],
        contribution=cfg.weights["auth_failure_support"],
        knowledge="fact",
        title="Authentication-Results reports failure",
        evidence=", ".join(sorted(set(fails))),
        rationale="An upstream receiver already saw the mail fail SPF/DKIM/"
                  "DMARC. Weak support signal: the header itself can be "
                  "forged, so this contributes little on its own.",
    )


# ── Header-forensics / auth bridging rules ────────────────────────────────
# These consume precomputed forensic/auth results carried in the FeatureModel.

def header_inconsistency_forensics(f: FeatureModel, cfg: DetectionConfig) -> Finding | None:
    n = len(f.forensic_inconsistencies)
    if n == 0:
        return NOTFIRED
    return Finding(
        rule_id="header_inconsistency_forensics",
        severity="medium",
        weight=cfg.weights["header_inconsistency_forensics"],
        contribution=cfg.weights["header_inconsistency_forensics"],
        knowledge="fact",
        title="Header forensics found inconsistencies",
        evidence=f"{n} inconsistency(ies): " + ", ".join(f.forensic_inconsistencies[:3]),
        rationale="Measured disagreement among Return-Path / Message-ID / Reply-To "
                  "and relay traces — each is byte-provable in the raw message.",
    )


def auth_conflict(f: FeatureModel, cfg: DetectionConfig) -> Finding | None:
    if not f.auth_has_conflict:
        return NOTFIRED
    return Finding(
        rule_id="auth_conflict",
        severity="medium",
        weight=cfg.weights["auth_conflict"],
        contribution=cfg.weights["auth_conflict"],
        knowledge="heuristic",
        title="Authentication results conflict",
        evidence=f.auth_auth_conflict_detail or "header claims disagree with locally verified results",
        rationale="When a header claim and a locally re-verified result disagree, "
                  "one of the two sources is unreliable — a spoofing indicator.",
    )


def auth_verified_fail(f: FeatureModel, cfg: DetectionConfig) -> Finding | None:
    if not f.auth_verified_fail_protocols:
        return NOTFIRED
    protos = f.auth_verified_fail_protocols
    return Finding(
        rule_id="auth_verified_fail",
        severity="high",
        weight=cfg.weights["auth_verified_fail"],
        contribution=cfg.weights["auth_verified_fail"],
        knowledge="fact",
        title="Authentication locally re-verified as FAILED",
        evidence=f"locally verified failures: {', '.join(protos)}",
        rationale="This system re-ran the DNS checks itself and they failed — "
                  "stronger than a header claim. Still bounded: a single "
                  "verified failure alone cannot make an email malicious.",
    )


def ip_url_risky_lookup(f: FeatureModel, cfg: DetectionConfig) -> Finding | None:
    """Provider-backed corroboration only — skips/unavailability add nothing."""
    if not f.enrichment_url_ip_not_global:
        return NOTFIRED
    return Finding(
        rule_id="ip_url_risky_lookup",
        severity="medium",
        weight=cfg.weights["ip_url_risky_lookup"],
        contribution=cfg.weights["ip_url_risky_lookup"],
        knowledge="heuristic",
        title="URL-host IP is not a global address",
        evidence=f"URL-host IPs not global: {', '.join(f.enrichment_url_ip_not_global[:2])}",
        rationale="A link pointing at a non-routable or reserved address is a "
                  "malformed/malicious lure; global-public URLs are normal.",
    )


def domain_no_mx_shortlived(f: FeatureModel, cfg: DetectionConfig) -> Finding | None:
    if not f.enrichment_domain_no_mx_and_new:
        return NOTFIRED
    return Finding(
        rule_id="domain_no_mx_shortlived",
        severity="medium",
        weight=cfg.weights["domain_no_mx_shortlived"],
        contribution=cfg.weights["domain_no_mx_shortlived"],
        knowledge="heuristic",
        title="Sender domain has no MX and is newly registered",
        evidence="; ".join(f.enrichment_domain_no_mx_and_new[:2]),
        rationale="A sending domain that cannot receive mail and was registered "
                  "recently is typical of throwaway fraud infrastructure.",
    )


def auth_dmarc_misaligned(f: FeatureModel, cfg: DetectionConfig) -> Finding | None:
    misaligned = [k for k, v in (f.auth_alignment or {}).items() if v == "misaligned"]
    if not misaligned:
        return NOTFIRED
    return Finding(
        rule_id="auth_dmarc_misaligned",
        severity="medium",
        weight=cfg.weights["auth_dmarc_misaligned"],
        contribution=cfg.weights["auth_dmarc_misaligned"],
        knowledge="heuristic",
        title="Domain alignment failure",
        evidence=f"misaligned: {', '.join(misaligned)}",
        rationale="The sending infrastructure's domain does not match the "
                  "visible From domain (relaxed org-domain match) — central "
                  "to DMARC-style spoofing assessment.",
    )


def all_caps_pressure(f: FeatureModel, cfg: DetectionConfig) -> Finding | None:
    words = re.findall(r"\b[A-Z]{4,}\b", f.subject) if f.subject else []
    if len(words) < 1:
        return NOTFIRED
    return Finding(
        rule_id="all_caps_pressure",
        severity="low",
        weight=cfg.weights["all_caps_pressure"],
        contribution=cfg.weights["all_caps_pressure"],
        knowledge="heuristic",
        title="Shouty ALL-CAPS subject",
        evidence=f"caps words in subject: {', '.join(words[:3])}",
        rationale="All-caps emphasis is a cheap attention-forcing device "
                  "common in bulk fraud mail.",
    )


ALL_RULES = (
    ip_literal_url,
    url_obfuscation,
    suspicious_url_structure,
    lookalike_domain,
    sender_reply_to_mismatch,
    urgency_language,
    credential_request,
    payment_diversion,
    all_caps_pressure,
    risky_attachment_type,
    header_inconsistency,
    auth_failure_support,
    header_inconsistency_forensics,
    auth_conflict,
    auth_verified_fail,
    auth_dmarc_misaligned,
    ip_url_risky_lookup,
    domain_no_mx_shortlived,
)
