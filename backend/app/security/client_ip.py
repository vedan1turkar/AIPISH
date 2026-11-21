"""Client IP for throttling and audit, safe behind a reverse proxy (P5i).

``X-Forwarded-For`` is honoured ONLY when the TCP peer is a configured trusted proxy
(``AIPISH_TRUSTED_PROXIES``: comma-separated IPs or CIDRs, empty by default). The header is then read
right to left and the first address that is not itself a trusted proxy is the client. A client that
talks to the backend directly, or that sends its own ``X-Forwarded-For`` through the proxy, cannot
choose its throttling identity: the proxy overwrites/appends, and only the hop the trusted proxy saw
is used.
"""
from __future__ import annotations

import ipaddress
from functools import lru_cache

from starlette.requests import Request

from app.core.config import env

Network = ipaddress.IPv4Network | ipaddress.IPv6Network


@lru_cache
def _trusted(spec: str) -> tuple[Network, ...]:
    nets: list[Network] = []
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            nets.append(ipaddress.ip_network(part, strict=False))
        except ValueError:
            continue          # an invalid entry trusts nothing (fail closed)
    return tuple(nets)


def trusted_proxies() -> tuple[Network, ...]:
    return _trusted(env("AIPISH_TRUSTED_PROXIES", "") or "")


def _parse(addr: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(addr.strip())
    except ValueError:
        return None


def _is_trusted(ip, nets: tuple[Network, ...]) -> bool:
    return ip is not None and any(ip in n for n in nets)


def client_ip(request: Request) -> str:
    peer = request.client.host if request.client else ""
    nets = trusted_proxies()
    peer_ip = _parse(peer)
    if not nets or not _is_trusted(peer_ip, nets):
        return peer or "unknown"
    hops = [h for h in ",".join(request.headers.getlist("x-forwarded-for")).split(",") if h.strip()]
    for hop in reversed(hops):
        ip = _parse(hop)
        if ip is None:
            return peer or "unknown"      # malformed chain: fall back to the proxy itself
        if not _is_trusted(ip, nets):
            return str(ip)
    return peer or "unknown"
