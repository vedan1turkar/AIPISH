"""IP classification for origin claims.

Distinct categories matter: only PUBLIC addresses may support a public-origin
claim. Private / loopback / link-local / documentation / reserved addresses are
recorded but EXCLUDED. Never raises on bad input.

IPv4 special ranges (RFC 5737 documentation, RFC 3927 link-local, RFC 6598
shared, RFC 3171 multicast, RFC 919 broadcast):
- 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 → documentation
- 169.254.0.0/16 → link_local
- 100.64.0.0/10 → shared/reserved
- 224.0.0.0/4 → multicast; 240.0.0.0/4 → reserved
IPv6: 2001:db8::/32 documentation, fe80::/10 link-local, ::1 loopback,
fc00::/7 unique-local (private), ff00::/8 multicast.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass


@dataclass(frozen=True)
class IPClass:
    ip: str
    category: str        # public | private | loopback | link_local | documentation | reserved | shared | multicast | invalid
    version: int         # 4 | 6 | 0


def classify_ip(raw: str | None) -> IPClass:
    if not raw:
        return IPClass(ip="", category="invalid", version=0)
    txt = raw.strip().strip("[]").strip()
    # plain host:port decoration on an IPv4 address
    if txt.count(":") == 1 and txt.count(".") == 3:
        txt = txt.split(":", 1)[0]

    try:
        addr = ipaddress.ip_address(txt)
    except ValueError:
        return IPClass(ip=raw, category="invalid", version=0)

    if addr.version == 4:
        n = int(addr)  # 32-bit int for explicit range checks
        if addr.is_loopback:
            cat = "loopback"
        elif addr.is_multicast:
            cat = "multicast"
        elif addr in ipaddress.ip_network("192.0.2.0/24") or addr in ipaddress.ip_network("198.51.100.0/24") or addr in ipaddress.ip_network("203.0.113.0/24"):
            cat = "documentation"
        elif addr.is_link_local:
            cat = "link_local"
        elif addr in ipaddress.ip_network("100.64.0.0/10"):
            cat = "shared"
        elif addr in ipaddress.ip_network("10.0.0.0/8") or addr in ipaddress.ip_network("172.16.0.0/12") or addr in ipaddress.ip_network("192.168.0.0/16"):
            cat = "private"
        elif addr.is_reserved and n >= 0xF0000000:  # 240.0.0.0/4 block, excluding 255.255.255.255 broadcast
            cat = "reserved"
        else:
            cat = "public"
    elif addr.version == 6:
        if addr.is_loopback:
            cat = "loopback"
        elif addr in ipaddress.ip_network("2001:db8::/32"):
            cat = "documentation"
        elif addr.is_link_local:
            cat = "link_local"
        elif addr.is_multicast:
            cat = "multicast"
        elif addr in ipaddress.ip_network("fc00::/7"):
            cat = "private"
        elif addr.is_private or addr.is_reserved:
            cat = "reserved"
        else:
            cat = "public"
    else:
        cat = "invalid"

    return IPClass(ip=str(addr), category=cat, version=addr.version)
