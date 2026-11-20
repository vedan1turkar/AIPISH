"""Per-request actor, so audit writes can record who acted without threading it through every call."""
from __future__ import annotations

from contextvars import ContextVar

_actor: ContextVar[str | None] = ContextVar("aipish_actor_user_id", default=None)


def set_actor(user_id: str | None) -> None:
    _actor.set(user_id)


def current_actor_id() -> str | None:
    return _actor.get()
