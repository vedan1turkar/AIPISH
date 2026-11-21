"""Per-request actor, so audit writes can record who acted without threading it through every call."""
from __future__ import annotations

from contextvars import ContextVar

_actor: ContextVar[str | None] = ContextVar("aipish_actor_user_id", default=None)


def set_actor(user_id: str | None) -> None:
    _actor.set(user_id)


def current_actor_id() -> str | None:
    return _actor.get()


# P5e: client IP for audit events (trusted-proxy aware; see app/security/client_ip.py)
_client_ip: ContextVar[str | None] = ContextVar("aipish_client_ip", default=None)


def set_client_ip(ip: str | None) -> None:
    _client_ip.set(ip)


def current_client_ip() -> str | None:
    return _client_ip.get()
