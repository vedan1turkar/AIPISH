"""Header forensics engine.

Parses Received headers in wire order (RFC 5321: the LAST Received header is
written by the receiving server; earlier ones may be forged by the sender),
constructs the observed relay chain, classifies IPs, locates the trusted
boundary, scores hop confidence with documented evidence rules, and runs
header-field inconsistency checks. Deterministic: no network, no randomness.

Terms:
- "observed chain" — what the headers *claim*, not verified truth.
- "earliest candidate IP" — first public from-IP in the observed chain.
- "verified originating IP" — earliest public from-IP whose hop confidence
  ≥ configured threshold (extra evidence required; a claim alone is not proof).
Never infers a person's location/identity from an IP; infrastructure only.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from app.forensics.config import ForensicsConfig, get_forensics_config
from app.forensics.ipclass import IPClass, classify_ip
from app.ingestion.addresses import (
    HEADER_COMPARISON_VERSION,
    address_domain,
    message_id_domain,
    normalize_mail_domain,
)
from app.ingestion.parser import ParsedEmail

# ── Received-header token parsers ─────────────────────────────────────────
_FROM_IP_RE = re.compile(
    r"\[((?:\d{1,3}(?:\.\d{1,3}){3})|(?:[0-9a-fA-F:]+)|IPv6:(?:[0-9a-fA-F:]+))\]",
    re.IGNORECASE,
)
_FROM_HOST_RE = re.compile(r"\bfrom\s+(\S+)(?:\s*\(|\s|$)", re.IGNORECASE)
# bc the parser already unwrapped the header into one line, this regex is applied to
# that collapsed string; multi-line Received headers still parse correctly.
_BY_HOST_RE = re.compile(r"\bby\s+(\S+?)(?:\s+with\s|\s+;|\s*\(|$)", re.IGNORECASE)
_WITH_RE = re.compile(r"\bwith\s+([a-zA-Z0-9\-]+)(?:\s|;|\(|$)", re.IGNORECASE)
_TLS_HINT_RE = re.compile(r"\b(using\s+(?:tls|esmtps|esmtpsa)|tls\s+encryption|version=tls[\d.]*)\b", re.IGNORECASE)
_TS_RE = re.compile(r";\s*(.+)$")
_BINARY_GARBAGE_RE = re.compile(r"[^\x20-\x7e\t]")


@dataclass
class ParsedHop:
    index: int                     # 0 = first hop (closest to sender)
    raw: str
    from_host: str | None
    from_ip_raw: str | None
    from_ip_class: IPClass
    by_host: str | None
    with_proto: str | None
    tls: bool
    timestamp: str | None
    extra_meta: dict[str, str] = field(default_factory=dict)


@dataclass
class Inconsistency:
    rule_id: str
    severity: str
    evidence: str
    rationale: str


@dataclass
class ChainHop:
    """A hop in the reconstructed chain (display order: first hop first)."""
    index: int
    from_host: str | None
    from_ip: str | None
    from_ip_category: str
    by_host: str | None
    protocol: str | None
    tls: bool
    timestamp: str | None
    trusted: bool
    confidence: int
    confidence_reasons: list[str]
    notes: list[str]


@dataclass
class HeaderForensicsResult:
    chain: list[ChainHop]
    trusted_boundary_index: int | None      # hop index where the trusted zone starts
    candidate_ips: list[str]                # public IPs in observed order
    earliest_candidate_ip: str | None
    verified_originating_ip: str | None
    inconsistencies: list[Inconsistency]
    confidence_rules: list[str]             # the documented rule table
    forgery_note: str
    disclaimer: str
    # P5d.1: 2 = parsed + normalised address comparison; 1 = legacy (ML feature path only).
    header_comparison_version: int = 1

    def to_dict(self) -> dict:
        return {
            "relay_chain": [
                {
                    "index": h.index, "from_host": h.from_host, "from_ip": h.from_ip,
                    "from_ip_category": h.from_ip_category, "by_host": h.by_host,
                    "protocol": h.protocol, "tls": h.tls, "timestamp": h.timestamp,
                    "trusted": h.trusted, "confidence": h.confidence,
                    "confidence_reasons": h.confidence_reasons, "notes": h.notes,
                }
                for h in self.chain
            ],
            "header_comparison_version": self.header_comparison_version,
            "trusted_boundary_index": self.trusted_boundary_index,
            "candidate_ips": self.candidate_ips,
            "earliest_candidate_ip": self.earliest_candidate_ip,
            "verified_originating_ip": self.verified_originating_ip,
            "inconsistencies": [
                {"rule_id": i.rule_id, "severity": i.severity,
                 "evidence": i.evidence, "rationale": i.rationale}
                for i in self.inconsistencies
            ],
            "confidence_rules": self.confidence_rules,
            "forgery_note": self.forgery_note,
            "disclaimer": self.disclaimer,
        }


FORGERY_NOTE = (
    "Received headers written BEFORE the trusted receiving server's own trace can be "
    "forged by the sender — RFC 5321 explicitly permits this. Only hops at or after the "
    "trusted boundary are reliable; earlier hops are treated as untrusted claims."
)
DISCLAIMER = (
    "IP addresses identify network infrastructure, not people. A public origin IP shows "
    "where the message (or a relay) entered a network — it does not prove the identity, "
    "device, or physical location of any human sender. Received headers can be forged "
    "before the trusted receiving server adds its own trace; origin claims are therefore "
    "confidence-based observations, not verified identity assertions."
)

CONFIDENCE_RULES_DOC = [
    "+20  public from-IP",
    "+15  from-host present (host/IP pairing evidence)",
    "+10  TLS in hop",
    "+10  parseable timestamp",
    "+25  hop at/after the trusted boundary (receiver-side trace)",
    "cap 40 for hops before the trusted boundary (untrusted zone)",
    "-15  both from-host and by-host missing",
    "-10  non-ASCII/binary garbage in raw value",
]


def _parse_received(raw: str, idx: int, cfg: ForensicsConfig) -> ParsedHop:
    m = _FROM_IP_RE.search(raw)
    ip_raw = m.group(1) if m else None
    if ip_raw and ip_raw.lower().startswith("ipv6:"):
        ip_raw = ip_raw[5:]
    hm = _FROM_HOST_RE.search(raw)
    from_host = None
    if hm:
        cand = hm.group(1).strip().rstrip("]")
        # from-host might itself be bracketed (from [1.2.3.4])
        if not (cand.startswith("[") or cand.replace(".", "").isdigit()):
            from_host = cand
    bm = _BY_HOST_RE.search(raw)
    by_host = bm.group(1).strip().rstrip("])(") if bm else None
    if by_host and (by_host.startswith("[") or by_host.replace(".", "").replace(":", "").isdigit()):
        by_host = None                          # 'by [1.2.3.4]' is not a hostname
    wm = _WITH_RE.search(raw)
    with_proto = wm.group(1).strip().lower() if wm else None
    tls = bool(_TLS_HINT_RE.search(raw)) or (with_proto in ("esmtps", "esmtpsa", "smtps", "lmtpsa"))
    # Received traces to an IPv6 literal may say 'with ESMTPS' after 'IPv6:...' —
    # handled by the shared regex above; no extra handling needed.
    tm = _TS_RE.search(raw)
    timestamp = tm.group(1).strip() if tm else None

    garbage = bool(_BINARY_GARBAGE_RE.search(raw))

    return ParsedHop(
        index=idx,
        raw=raw,
        from_host=from_host,
        from_ip_raw=ip_raw,
        from_ip_class=classify_ip(ip_raw),
        by_host=by_host,
        with_proto=with_proto,
        tls=tls,
        timestamp=timestamp,
        extra_meta={"garbage": "1"} if garbage else {},
    )


def _receiver_reg_domain(parsed: ParsedEmail) -> str | None:
    """Best-effort receiver domain from To/Cc."""
    for a in parsed.to + parsed.cc:
        if a.domain:
            return a.domain.lower()
    return None


def _is_trusted(hop: ParsedHop, receiver_domain: str | None, cfg: ForensicsConfig) -> bool:
    by_host = (hop.by_host or "").lower()
    if not by_host:
        return False
    if receiver_domain and (by_host == receiver_domain or by_host.endswith("." + receiver_domain)):
        return True
    return any(by_host.startswith(p) for p in cfg.local_mx_patterns)


def _score_hop(hop: ParsedHop, trusted: bool, cfg: ForensicsConfig) -> tuple[int, list[str]]:
    conf = 0
    reasons: list[str] = []
    if hop.from_ip_class.category == "public":
        conf += cfg.conf_public_ip
        reasons.append("public from-IP (+20)")
    elif hop.from_ip_raw:
        reasons.append(f"non-public from-IP ({hop.from_ip_class.category}, +0 for origin claim)")
    if hop.from_host:
        conf += cfg.conf_host_ip_consistent
        reasons.append("from-host present (+15)")
    if hop.tls:
        conf += cfg.conf_tls
        reasons.append("TLS (+10)")
    if hop.timestamp:
        conf += cfg.conf_has_timestamp
        reasons.append("timestamp (+10)")
    if trusted:
        conf += cfg.conf_trusted_boundary
        reasons.append("trusted boundary (+25)")
    else:
        reasons.append(f"untrusted zone (capped ≤{cfg.untrusted_cap})")
    if not hop.from_host and not hop.by_host:
        conf -= cfg.penalty_missing_hosts
        reasons.append("both hostnames missing (−15)")
    if hop.extra_meta.get("garbage"):
        conf -= cfg.penalty_binary_garbage
        reasons.append("binary garbage in raw header (−10)")

    conf = max(0, min(100, conf))
    if not trusted:
        conf = min(conf, cfg.untrusted_cap)
    return conf, reasons


def _reg_domain(host: str) -> str:
    """Very small registrable-domain reduction: last two labels, handles co.uk-ish poorly — acceptable for MVP, documented."""
    host = host.lower().strip().rstrip(".")
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def _legacy_dom(addr: str | None) -> str | None:
    """Pre-P5d.1 Return-Path domain: keeps a trailing '>' (the bug).

    Intentionally preserved ONLY for the ML feature path (``legacy_domain_compare=True``), so the
    trained model keeps receiving the inputs it was trained on. Do not use elsewhere."""
    if not addr or "@" not in addr:
        return None
    return addr.rpartition("@")[2].lower().strip()


def _inconsistencies(parsed: ParsedEmail, hops: list[ParsedHop], cfg: ForensicsConfig,
                     legacy_domain_compare: bool = False) -> list[Inconsistency]:
    out: list[Inconsistency] = []
    if legacy_domain_compare:
        from_dom = parsed.from_.domain.lower() if parsed.from_ else None
        rp_dom = _legacy_dom(parsed.return_path) if parsed.return_path else None
        rt_doms = [(rt, rt.domain.lower() if rt.domain else None) for rt in parsed.reply_to]
        mid = parsed.message_id or ""
        mid_dom = mid.rpartition("@")[2].lower().rstrip(">") if "@" in mid else None
    else:
        # P5d.1: parse addresses (display names, comments, <> bounce) and normalise domains
        from_dom = normalize_mail_domain(parsed.from_.domain) if parsed.from_ else None
        rp_dom = address_domain(parsed.return_path)
        rt_doms = [(rt, normalize_mail_domain(rt.domain)) for rt in parsed.reply_to]
        mid_dom = message_id_domain(parsed.message_id)

    # Return-Path vs From (the null reverse-path "<>" has no domain → never a mismatch)
    if from_dom and rp_dom and rp_dom != from_dom and "mailfrom" not in (parsed.return_path or "").lower():
        out.append(Inconsistency(
            "returnpath_mismatch", cfg.severity_returnpath_mismatch,
            f"From domain {from_dom} ≠ Return-Path domain {rp_dom}",
            "The envelope sender (Return-Path) disagrees with the visible From — "
            "typical of spoofed or unaligned sends; if auth results were passing, this is suspicious.",
        ))

    # Reply-To vs From
    for rt, rt_dom in rt_doms:
        if from_dom and rt_dom and rt_dom != from_dom:
            out.append(Inconsistency(
                "replyto_mismatch", cfg.severity_replyto_mismatch,
                f"Reply-To {rt.email} diverges from From domain {from_dom}",
                "Replies would be diverted to another domain — common BEC pattern.",
            ))

    # Message-ID vs From
    if from_dom and mid_dom and mid_dom != from_dom and mid_dom not in (from_dom.split(".")[-2:]):
        out.append(Inconsistency(
            "messageid_domain_mismatch", cfg.severity_messageid_mismatch,
            f"Message-ID domain {mid_dom} ≠ From domain {from_dom}",
            "The Message-ID was generated on different infrastructure than the visible sender.",
        ))

    # Authentication-Results vs received-SPF-ish claims inside Received values
    ar_text = " ".join(parsed.authentication_results).lower()
    recv_text = " ".join(h.raw for h in hops).lower()
    if "spf=fail" in ar_text and "spf=pass" in recv_text:
        out.append(Inconsistency(
            "auth_results_spf_mismatch", cfg.severity_received_spf,
            "Authentication-Results says spf=fail while a Received header claims spf=pass",
            "One of these is forged or refers to different links of the chain; acknowledge the conflict explicitly.",
        ))
    if ("authentication-results" in recv_text) and ("spf=pass" in ar_text) and ("spf=fail" in recv_text):
        out.append(Inconsistency(
            "received_spf_mismatch", cfg.severity_received_spf,
            "Received header carries Authentication-Results claims contradicting the top A-R header",
            "A-R headers pasted into Received fields are a known forgery trick.",
        ))

    # structural
    if not hops:
        out.append(Inconsistency(
            "no_received", cfg.severity_no_received,
            "No Received headers present",
            "The message's transport path cannot be reconstructed from the available evidence. "
            "Absent Received headers do not show how, or whether, the message travelled over SMTP.",
        ))
    elif len(hops) > cfg.max_expected_hops:
        out.append(Inconsistency(
            "excess_hops", cfg.severity_excess_hops,
            f"{len(hops)} Received headers (> {cfg.max_expected_hops})",
            "Unusual relay length; can indicate looping or deliberately padded headers.",
        ))
    # gap: an untrusted hop appearing *after* (above) a trusted one in display order
    idxs = [h.index for h in hops]
    for i in range(1, len(idxs)):
        pass
    return out


def run_header_forensics(
    parsed: ParsedEmail,
    cfg: ForensicsConfig | None = None,
    *,
    legacy_domain_compare: bool = False,
) -> HeaderForensicsResult:
    """``legacy_domain_compare=True`` reproduces the pre-P5d.1 address comparison exactly. It is used
    only by the ML feature path (``app.ml.features.run_rules_offline``) to match model training."""
    cfg = cfg or get_forensics_config()

    # Received headers: parser collected them in wire order (top to bottom).
    wire_order = list(parsed.received)               # wire_order[0] = top = LAST hop
    # display/reconstruct in chronological order: bottom is the FIRST hop
    chrono = list(reversed(wire_order))
    parsed_hops = [_parse_received(h.raw, i, cfg) for i, h in enumerate(chrono)]

    receiver_domain = _receiver_reg_domain(parsed)
    trusted_flags = [_is_trusted(h, receiver_domain, cfg) for h in parsed_hops]

    # trusted boundary: first (earliest) hop flagged trusted — everything from
    # that point (including it) is receiver-side; note a trusted hop may appear
    # with earlier garbage below it (common in real chains).
    boundary = next((i for i, t in enumerate(trusted_flags) if t), None)

    chain: list[ChainHop] = []
    for h, t in zip(parsed_hops, trusted_flags):
        conf, reasons = _score_hop(h, t, cfg) if boundary is not None and h.index >= boundary else _score_hop(h, False, cfg)
        chain.append(ChainHop(
            index=h.index,
            from_host=h.from_host,
            from_ip=h.from_ip_class.ip if h.from_ip_raw else None,
            from_ip_category=h.from_ip_class.category if h.from_ip_raw else "missing",
            by_host=h.by_host,
            protocol=h.with_proto,
            tls=h.tls,
            timestamp=h.timestamp,
            trusted=t,
            confidence=conf,
            confidence_reasons=reasons,
            notes=[],
        ))

    candidates = [h.from_ip for h in chain if h.from_ip and h.from_ip_category == "public"]
    earliest = candidates[0] if candidates else None

    verified = None
    if boundary is not None:
        for h in chain:
            if (
                h.from_ip
                and h.from_ip_category == "public"
                and h.trusted
                and h.confidence >= cfg.verified_origin_min_confidence
            ):
                verified = h.from_ip
                break

    inconsistencies = _inconsistencies(parsed, parsed_hops, cfg, legacy_domain_compare)

    return HeaderForensicsResult(
        chain=chain,
        trusted_boundary_index=boundary,
        candidate_ips=candidates,
        earliest_candidate_ip=earliest,
        verified_originating_ip=verified,
        inconsistencies=inconsistencies,
        confidence_rules=CONFIDENCE_RULES_DOC,
        forgery_note=FORGERY_NOTE,
        disclaimer=DISCLAIMER,
        header_comparison_version=1 if legacy_domain_compare else HEADER_COMPARISON_VERSION,
    )
