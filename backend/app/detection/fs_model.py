"""Feature model — pure, cached extraction of detection inputs from a ParsedEmail.

No rule logic here. Every field is derived deterministically from the parsed
message so identical .eml bytes always produce identical features.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from app.detection.config import DetectionConfig, get_config
from app.ingestion.parser import ParsedEmail
from app.ingestion.addresses import normalize_mail_domain

_URL_TOKEN_RE = re.compile(r"https?://\S+|www\.\S+", re.IGNORECASE)
# invisible / zero-width characters used to break up visible words or URLs
_INVISIBLE_RE = re.compile(r"[\u200b\u200c\u200d\u2060\ufeff]")


def _levenshtein(a: str, b: str, cap: int) -> int:
    """Bounded Levenshtein distance (returns > cap once exceeded)."""
    if abs(len(a) - len(b)) > cap:
        return cap + 1
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
        if min(prev) > cap:
            return cap + 1
    return prev[-1]


@dataclass
class UrlFeature:
    raw: str
    host: str
    scheme: str
    is_ip_literal: bool
    is_shortener: bool
    has_credentials: bool
    has_punycode: bool
    suspicious_tld: str | None
    # obfuscation: host written with zero-width chars, or brand-like host that
    # appears in visible link text as a different domain, or heavy percent-encode
    has_invisible_chars: bool
    percent_encoded_ratio: float


@dataclass
class FeatureModel:
    from_domain: str | None
    reply_to_domains: list[str]
    from_display_name_brand: str | None       # brand word inside display name, if any
    urls: list[UrlFeature]
    text: str
    subject: str
    attachment_names: list[str]
    risky_attachment_names: list[str]
    header_counts: dict[str, int]
    received_count: int
    raw_authentication_results: list[str]
    obfuscated_url_count: int

    sender_and_reply_domains_differ: bool

    # bridged forensics / auth / enrichment evidence (None → rules treat as unknown)
    forensic_inconsistencies: list[str] = field(default_factory=list)
    auth_verified_fail_protocols: list[str] = field(default_factory=list)
    auth_has_conflict: bool = False
    auth_auth_conflict_detail: str = ""
    auth_alignment: dict[str, str] = field(default_factory=dict)

    # enrichment bridged evidence (never fabricated — only provider-backed facts)
    enrichment_url_ip_not_global: list[str] = field(default_factory=list)   # URL-host IPs that are not global
    enrichment_domain_no_mx_and_new: list[str] = field(default_factory=list)  # sender-domain DNS+RDAP corroboration


def _legacy_norm_domain(d: str) -> str:
    """Pre-P5d.1 domain normalisation (no trailing-dot / IDNA handling).

    Intentionally preserved ONLY for the ML feature path (``legacy_domain_compare=True``), so the
    trained model keeps receiving the inputs it was trained on. Do not use elsewhere."""
    d = _INVISIBLE_RE.sub("", d).strip().lower()
    return d[4:] if d.startswith("www.") else d


_norm_domain = _legacy_norm_domain      # URL-host handling (unchanged; not an address comparison)


def _addr_domain(d: str | None) -> str:
    """P5d.1 address-domain normalisation for sender/Reply-To comparisons (www. handling kept)."""
    n = normalize_mail_domain(d) or ""
    return n[4:] if n.startswith("www.") else n


def _classify_url(url: str, cfg: DetectionConfig) -> UrlFeature:
    raw = _INVISIBLE_RE.sub("", url)
    try:
        parts = urlsplit(raw)
    except ValueError:
        parts = urlsplit("http://invalid.invalid")
    host = (parts.hostname or "").lower()
    is_ip_literal = bool(re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host)) or host.startswith("[")
    tld = None
    if "." in host:
        candidate = "." + host.rsplit(".", 1)[-1]
        if candidate in cfg.suspicious_tlds:
            tld = candidate
    raw_for_enc = raw.split("://", 1)[-1]
    pct = raw_for_enc.count("%") / max(len(raw_for_enc), 1)
    return UrlFeature(
        raw=raw,
        host=host,
        scheme=parts.scheme or "",
        is_ip_literal=is_ip_literal,
        is_shortener=host in cfg.shortener_hosts,
        has_credentials=bool(parts.username),
        has_punycode="xn--" in host,
        suspicious_tld=tld,
        has_invisible_chars=bool(_INVISIBLE_RE.search(url)),   # original, pre-strip
        percent_encoded_ratio=round(pct, 3),
    )


def build_features(parsed: ParsedEmail, cfg: DetectionConfig | None = None, *,
                   legacy_domain_compare: bool = False) -> FeatureModel:
    """``legacy_domain_compare=True`` reproduces the pre-P5d.1 sender/Reply-To comparison exactly;
    it is used only by the ML feature path to match model training."""
    cfg = cfg or get_config()

    from_domain = parsed.from_.domain if parsed.from_ else None
    norm = _legacy_norm_domain if legacy_domain_compare else _addr_domain
    reply_domains: list[str] = []
    for a in parsed.reply_to:
        d = norm(a.domain or (a.email.rpartition("@")[2] if "@" in a.email else ""))
        if d and len(d) >= cfg.min_reply_to_domain_len:
            reply_domains.append(d)
    # domain used for comparisons (the displayed from_domain field is unchanged)
    cmp_from = (from_domain if legacy_domain_compare else (normalize_mail_domain(from_domain) or from_domain)) \
        if from_domain else None

    text = "\n".join(filter(None, [parsed.body_text]))
    subject = parsed.subject or ""

    urls = [_classify_url(u.url, cfg) for u in parsed.urls]

    names = [a.filename for a in parsed.attachments]
    risky = [n for n in names if any(n.lower().endswith(ext) for ext in cfg.risky_attachment_exts)]

    # display-name brand reference: only reliable if the name really contains a
    # known brand token and the sender domain differs from that brand.
    display_name = (parsed.from_.display_name or "").lower() if parsed.from_ else ""
    brand_in_name: str | None = None
    if display_name and from_domain:
        for brand in cfg.brand_domains:
            brand_name = brand.split(".")[0]
            if brand_name in display_name and cmp_from != brand:
                brand_in_name = brand
                break

    auth_raw = list(parsed.authentication_results or [])

    return FeatureModel(
        from_domain=_norm_domain(from_domain) if from_domain else None,
        reply_to_domains=reply_domains,
        from_display_name_brand=brand_in_name,
        urls=urls,
        text=text,
        subject=subject,
        attachment_names=names,
        risky_attachment_names=risky,
        header_counts=dict(parsed.header_counts or {}),
        received_count=parsed.received_count,
        raw_authentication_results=auth_raw,
        obfuscated_url_count=getattr(parsed, "obfuscated_url_count", 0),
        sender_and_reply_domains_differ=bool(from_domain) and bool(reply_domains) and all(d != norm(from_domain) for d in reply_domains),
    )
