"""Indicator validation — runs before ANY threat-intel network call.

Only bare, public, well-formed indicators are eligible:
- IPs: valid IPv4/IPv6 that are globally routable. Private, loopback,
  link-local, multicast, reserved, unspecified, CGNAT/shared, documentation
  ranges and IPv4-mapped IPv6 addresses that point at any of them are refused.
- Domains: syntactically valid (IDNA-encoded) multi-label public names. IPs
  written as domains, localhost, single labels and internal / reserved
  suffixes (.local, .internal, .lan, .example, ...) are refused.
- Hashes: MD5 / SHA-1 / SHA-256 hex only.

Every function returns ``(normalised_value, None)`` or ``(None, reason_code)``
and never raises.
"""
from __future__ import annotations

import ipaddress
import re

IP, DOMAIN, HASH = "ip", "domain", "hash"
INDICATOR_TYPES = (IP, DOMAIN, HASH)

_DOC_NETS = [ipaddress.ip_network(n) for n in (
    "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32", "3fff::/20")]
_SHARED_NET = ipaddress.ip_network("100.64.0.0/10")
_BENCH_NET = ipaddress.ip_network("198.18.0.0/15")

_LABEL_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
_TLD_RE = re.compile(r"^(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$")
# Internal, special-use and documentation names that must never leave the host.
_BLOCKED_SUFFIXES = (
    "local", "internal", "lan", "localhost", "localdomain", "home", "corp", "intranet",
    "private", "home.arpa", "test", "example", "invalid", "onion", "arpa",
)
_DOC_DOMAINS = ("example.com", "example.net", "example.org")
_HASH_LENGTHS = {32: "md5", 40: "sha1", 64: "sha256"}
_HEX_RE = re.compile(r"^[0-9a-f]+$")


def _ip_reason(a: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str | None:
    if a.is_unspecified:
        return "unspecified"
    if a.is_loopback:
        return "loopback"
    if a.is_link_local:
        return "link_local"
    if a.is_multicast:
        return "multicast"
    if any(a in n for n in _DOC_NETS if n.version == a.version):
        return "documentation"
    if a.version == 4 and (a in _SHARED_NET):
        return "shared_cgnat"
    if a.version == 4 and (a in _BENCH_NET):
        return "reserved"
    if a.is_reserved:
        return "reserved"
    if a.is_private:
        return "private"
    if not a.is_global:
        return "not_global"
    return None


def validate_ip(value: object) -> tuple[str | None, str | None]:
    if not isinstance(value, str):
        return None, "invalid_ip"
    text = value.strip()
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1]
    if not text or "%" in text or "/" in text or len(text) > 45:
        return None, "invalid_ip"
    try:
        a = ipaddress.ip_address(text)
    except ValueError:
        return None, "invalid_ip"
    if a.version == 6:
        mapped = a.ipv4_mapped or a.sixtofour or (a.teredo[1] if a.teredo else None)
        if mapped is not None:
            reason = _ip_reason(mapped)
            if reason:
                return None, f"ipv4_mapped_{reason}"
            if a.ipv4_mapped is not None:
                return str(a.ipv4_mapped), None   # canonical IPv4 form of a public address
    reason = _ip_reason(a)
    if reason:
        return None, reason
    return str(a), None


def validate_domain(value: object) -> tuple[str | None, str | None]:
    if not isinstance(value, str):
        return None, "invalid_domain"
    d = value.strip().lower().rstrip(".")
    if not d or len(d) > 253 or any(c in d for c in "/:@?#[] \t\r\n\\"):
        return None, "invalid_domain"
    try:
        ipaddress.ip_address(d)
        return None, "ip_as_domain"
    except ValueError:
        pass
    if re.fullmatch(r"[0-9.]+", d):
        return None, "ip_as_domain"
    if any(len(label) > 63 for label in d.split(".")):
        return None, "label_too_long"
    try:
        d = d.encode("idna").decode("ascii")
    except (UnicodeError, ValueError):
        return None, "invalid_idna"
    if len(d) > 253:
        return None, "too_long"
    labels = d.split(".")
    if len(labels) < 2:
        return None, "localhost" if d == "localhost" else "single_label"
    for label in labels:
        if len(label) > 63:
            return None, "label_too_long"
        if not _LABEL_RE.match(label):
            return None, "invalid_label"
    if not _TLD_RE.match(labels[-1]):
        return None, "invalid_tld"
    for suffix in _BLOCKED_SUFFIXES:
        if d == suffix or d.endswith("." + suffix):
            return None, "localhost" if suffix == "localhost" else "internal_or_reserved_suffix"
    if d in _DOC_DOMAINS or any(d.endswith("." + x) for x in _DOC_DOMAINS):
        return None, "documentation_domain"
    return d, None


def validate_hash(value: object) -> tuple[str | None, str | None]:
    if not isinstance(value, str):
        return None, "invalid_hash"
    h = value.strip().lower()
    if len(h) not in _HASH_LENGTHS or not _HEX_RE.match(h):
        return None, "invalid_hash"
    return h, None


def hash_kind(h: str) -> str | None:
    return _HASH_LENGTHS.get(len(h))


_VALIDATORS = {IP: validate_ip, DOMAIN: validate_domain, HASH: validate_hash}


def validate(value: object, indicator_type: str | None = None) -> tuple[str | None, str | None, str | None]:
    """Returns ``(type, normalised, reason)``. Infers the type when not given."""
    if indicator_type is not None:
        fn = _VALIDATORS.get(indicator_type)
        if fn is None:
            return indicator_type, None, "unsupported_indicator_type"
        norm, reason = fn(value)
        return indicator_type, norm, reason
    for t in (IP, HASH, DOMAIN):
        norm, reason = _VALIDATORS[t](value)
        if norm is not None:
            return t, norm, None
    # report the most specific rejection
    _, ip_reason = validate_ip(value)
    if ip_reason != "invalid_ip":
        return IP, None, ip_reason
    _, d_reason = validate_domain(value)
    return DOMAIN, None, d_reason


REASON_TEXT = {
    "invalid_ip": "not a valid IP address",
    "private": "private (RFC 1918 / ULA) address",
    "loopback": "loopback address",
    "link_local": "link-local address",
    "multicast": "multicast address",
    "reserved": "reserved address range",
    "unspecified": "unspecified address",
    "shared_cgnat": "shared / carrier-grade NAT range (100.64.0.0/10)",
    "documentation": "documentation range",
    "not_global": "not a globally routable address",
    "ipv4_mapped": "IPv4-mapped IPv6 form (the IPv4 address is used instead)",
    "invalid_domain": "not a valid domain name",
    "ip_as_domain": "an IP address written as a domain",
    "invalid_idna": "invalid internationalised domain name",
    "too_long": "domain name too long",
    "label_too_long": "domain label longer than 63 characters",
    "invalid_label": "invalid domain label",
    "invalid_tld": "invalid top-level domain",
    "single_label": "single-label name (not a public domain)",
    "localhost": "localhost",
    "internal_or_reserved_suffix": "internal or reserved suffix (e.g. .local, .internal, .lan, .example)",
    "documentation_domain": "documentation domain (example.com/.net/.org)",
    "invalid_hash": "not an MD5 / SHA-1 / SHA-256 hex hash",
    "unsupported_indicator_type": "unsupported indicator type",
}


def reason_text(code: str | None) -> str:
    if not code:
        return ""
    if code.startswith("ipv4_mapped_"):
        return "IPv4-mapped/embedded IPv6 pointing at a " + REASON_TEXT.get(code[12:], code[12:])
    return REASON_TEXT.get(code, code)
