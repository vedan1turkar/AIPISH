"""Normalisation and indicator extraction from a stored analysis (P5c).

Rules:
- IPs: only addresses accepted by the P5a validation helper (public, non-reserved).
- Origin candidates come from the forensics engine's own decision (verified / earliest /
  candidate IPs). Relay IPs come only from *untrusted* hops. From-IPs of trusted hops that
  the forensics engine did not select as candidates are our own receiving relays and are
  never entities.
- Hops whose host belongs to a stop-listed provider (e.g. *.google.com, *.amazonses.com)
  are provider infrastructure and are not recorded as IP entities.
- Domains: lower-case, IDNA (punycode), trailing dot stripped, at least two labels, not an IP.
- Each observation carries ``source_field``: the exact field of the stored analysis it came
  from (e.g. ``forensics.relay_chain[3].from_ip``), which is the evidence reference.
"""
from __future__ import annotations

import ipaddress
import re
import unicodedata
from dataclasses import dataclass

from app.correlation.config import CorrelationConfig
from app.intel.validate import validate_hash, validate_ip

_LABEL_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")


@dataclass(frozen=True)
class Extracted:
    type: str
    value: str
    role: str
    source_field: str


def normalize_domain(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    d = value.strip().strip("<>").lower().rstrip(".")
    if "@" in d:
        d = d.rpartition("@")[2].strip().strip(">").rstrip(".")
    if d.startswith("[") or not d or len(d) > 253 or any(c in d for c in "/:?#[] \t\r\n\\"):
        return None
    try:
        ipaddress.ip_address(d)
        return None
    except ValueError:
        pass
    try:
        d = d.encode("idna").decode("ascii")
    except (UnicodeError, ValueError):
        return None
    labels = d.split(".")
    if len(labels) < 2 or d == "localhost" or re.fullmatch(r"[0-9.]+", d):
        return None
    if not all(_LABEL_RE.match(lbl) for lbl in labels) or not re.fullmatch(r"(xn--)?[a-z][a-z0-9-]*", labels[-1]):
        return None
    return d


def normalize_public_ip(value: object) -> str | None:
    ip, _reason = validate_ip(value)
    return ip


def normalize_hash(value: object) -> str | None:
    h, _reason = validate_hash(value)
    return h


def normalize_display_name(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    s = unicodedata.normalize("NFKC", value).casefold()
    s = re.sub(r"[^\w\s]", " ", s)
    s = re.sub(r"\s+", " ", s).strip()
    return s[:120] if len(s) >= 3 else None


def _domain_of_address(addr: object) -> str | None:
    if not isinstance(addr, str) or "@" not in addr:
        return None
    return normalize_domain(addr.rpartition("@")[2])


def extract(rec, cfg: CorrelationConfig) -> list[Extracted]:
    """All correlation observations for one stored Analysis row, deterministic order."""
    out: list[Extracted] = []
    seen: set[tuple[str, str, str, str]] = set()

    def add(etype: str, value: str | None, role: str, field: str) -> None:
        if not value:
            return
        key = (etype, value, role, field)
        if key not in seen:
            seen.add(key)
            out.append(Extracted(etype, value, role, field))

    fx = rec.forensics_json or {}
    chain = fx.get("relay_chain") or []

    provider_ips: set[str] = set()
    trusted_ips: set[str] = set()
    for hop in chain:
        hop = hop or {}
        ip = normalize_public_ip(hop.get("from_ip"))
        if not ip:
            continue
        host = normalize_domain(hop.get("from_host") or "")
        if host and cfg.is_stoplisted(host):
            provider_ips.add(ip)
        if hop.get("trusted"):
            trusted_ips.add(ip)

    candidates: list[tuple[str, str]] = []
    if fx.get("verified_originating_ip"):
        candidates.append((fx["verified_originating_ip"], "forensics.verified_originating_ip"))
    if fx.get("earliest_candidate_ip"):
        candidates.append((fx["earliest_candidate_ip"], "forensics.earliest_candidate_ip"))
    for i, ip in enumerate(fx.get("candidate_ips") or []):
        candidates.append((ip, f"forensics.candidate_ips[{i}]"))
    candidate_set: set[str] = set()
    for raw, field in candidates:
        ip = normalize_public_ip(raw)
        if ip and ip not in provider_ips:
            candidate_set.add(ip)
            add("public_ip", ip, "origin_candidate_ip", field)

    for hop in chain:
        hop = hop or {}
        ip = normalize_public_ip(hop.get("from_ip"))
        if not ip or ip in candidate_set or ip in provider_ips or hop.get("trusted") or ip in trusted_ips:
            continue                                    # trusted relays never become entities
        add("public_ip", ip, "relay_ip", f"forensics.relay_chain[{hop.get('index')}].from_ip")

    add("sender_domain", normalize_domain(rec.from_domain or ""), "sender_domain", "from.domain")
    for i, addr in enumerate(rec.reply_to_emails or []):
        add("reply_to_domain", _domain_of_address(addr), "reply_to_domain", f"reply_to[{i}]")
    rp = (rec.return_path or "").strip().strip("<>")
    add("return_path_domain", _domain_of_address(rp), "return_path_domain", "return_path")
    mid = (rec.message_id or "").strip().strip("<>")
    if "@" in mid:
        add("message_id_domain", normalize_domain(mid.rpartition("@")[2]), "message_id_domain", "message_id")
    for i, u in enumerate(rec.urls or []):
        host = normalize_domain(str((u or {}).get("host") or ""))
        if host:
            add("url_host", host, "url_host", f"urls[{i}].host")
        else:
            ip = normalize_public_ip(str((u or {}).get("host") or "").strip("[]"))
            if ip:
                add("public_ip", ip, "url_host_ip", f"urls[{i}].host")
    for i, a in enumerate(rec.attachments or []):
        add("attachment_hash", normalize_hash((a or {}).get("sha256")), "attachment_sha256",
            f"attachments[{i}].sha256")
    add("display_name_alias", normalize_display_name(rec.from_display_name), "display_name", "from.display_name")
    return out
