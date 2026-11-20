"""Indicator collection and validation.

Sources (from the parser): attachment-irrelevant IPs are collected from
Authentication-Results, Received headers (via forensics candidates), URL
hosts, plus sender/return-path/reply-to/mail domains and URL hostnames.
Everything is validated/normalized before use; invalid entries are dropped
with a note.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from app.ingestion.parser import ParsedEmail
from app.ingestion.addresses import address_domain

_DOMAIN_RE = re.compile(r"^(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)*[a-z]{2,63}$")


@dataclass
class Ioc:
    kind: str           # ip | domain | hostname
    value: str          # normalized value
    origin: str         # where it came from (message evidence)
    ip_category: str | None = None   # for IPs: public/private/loopback/…
    notes: list[str] = field(default_factory=list)


def normalize_domain(value: str | None) -> str | None:
    if not value:
        return None
    d = value.strip().lower().strip(".")
    d = d[4:] if d.startswith("www.") else d
    # strip brackets / ports
    d = d.strip("[]")
    if ":" in d and _DOMAIN_RE.match(d.split(":")[0]):
        d = d.split(":")[0]
    if len(d) > 253:
        return None
    if not _DOMAIN_RE.match(d):
        return None
    return d


def normalize_ip(value: str | None) -> str | None:
    if not value:
        return None
    txt = value.strip().strip("[]")
    if txt.count(":") == 1 and txt.count(".") == 3:
        txt = txt.split(":", 1)[0]
    try:
        return str(ipaddress.ip_address(txt))
    except ValueError:
        return None


def is_private_ip(ip: str) -> bool:
    a = ipaddress.ip_address(ip)
    return not a.is_global


def is_global_ip(ip: str | None) -> bool:
    """True for globally-routable (public) addresses; never raises."""
    if not ip:
        return False
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def collect_iocs(parsed: ParsedEmail, forensic_ips: list[str]) -> list[Ioc]:
    iocs: dict[tuple[str, str], Ioc] = {}

    def add(kind: str, value: str | None, origin: str) -> None:
        if not value:
            return
        key = (kind, value)
        if key in iocs:
            if origin not in iocs[key].origin:
                iocs[key].origin += f", {origin}"
            return
        iocs[key] = Ioc(kind=kind, value=value, origin=origin)

    # IPs: forensics candidates + auth-received literals + URL hosts that are IPs
    for ip in forensic_ips:
        norm = normalize_ip(ip)
        if norm:
            add("ip", norm, "received-chain candidate")

    for u in parsed.urls:
        host_raw = urlsplit(u.url).hostname or ""
        norm_ip = normalize_ip(host_raw)
        if norm_ip:
            add("ip", norm_ip, "url host")
        else:
            d = normalize_domain(host_raw)
            if d:
                add("hostname", d, "url host")

    # mail domains
    if parsed.from_ and parsed.from_.domain:
        add("domain", normalize_domain(parsed.from_.domain), "From header")
    rp_dom = address_domain(parsed.return_path)       # P5d.1: parsed, "<>" bounce → none
    if rp_dom:
        add("domain", normalize_domain(rp_dom), "Return-Path")
    for rt in parsed.reply_to:
        add("domain", normalize_domain(rt.domain), "Reply-To")

    out = list(iocs.values())
    return out
