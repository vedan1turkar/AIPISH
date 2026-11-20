"""Bounded in-memory failed-login throttling (per username and per source IP).

Limitation (documented): state is per process and resets on restart. Per-user
lockout is additionally mirrored to ``app_user.locked_until`` for known users,
so that part survives a restart.
"""
from __future__ import annotations

import threading
import time
from collections import OrderedDict, deque
from typing import Callable

from app.core.config import env


def _int_env(name: str, default: int) -> int:
    try:
        return max(1, int(env(name, str(default)) or default))
    except ValueError:
        return default


class FailureLimiter:
    """After ``max_failures`` failures within ``window`` seconds, a key is locked for ``lockout`` seconds."""

    def __init__(self, max_failures: int, window: int, lockout: int, max_keys: int = 10_000,
                 clock: Callable[[], float] = time.monotonic):
        self.max_failures, self.window, self.lockout, self.max_keys = max_failures, window, lockout, max_keys
        self.clock = clock
        self._fails: OrderedDict[str, deque[float]] = OrderedDict()
        self._locked: OrderedDict[str, float] = OrderedDict()
        self._lock = threading.Lock()

    def _trim(self, store: OrderedDict) -> None:
        while len(store) > self.max_keys:        # bounded: evict the least recently touched keys
            store.popitem(last=False)

    def retry_after(self, key: str) -> int:
        """Seconds until the key may try again (0 = allowed)."""
        with self._lock:
            until = self._locked.get(key)
            if until is None:
                return 0
            left = until - self.clock()
            if left <= 0:
                del self._locked[key]
                return 0
            return int(left) + 1

    def fail(self, key: str) -> bool:
        """Record a failure. Returns True when this failure triggered a lockout."""
        now = self.clock()
        with self._lock:
            q = self._fails.setdefault(key, deque())
            self._fails.move_to_end(key)
            q.append(now)
            while q and now - q[0] > self.window:
                q.popleft()
            locked = len(q) >= self.max_failures
            if locked:
                self._locked[key] = now + self.lockout
                self._locked.move_to_end(key)
                q.clear()
            self._trim(self._fails)
            self._trim(self._locked)
            return locked

    def reset(self, key: str) -> None:
        with self._lock:
            self._fails.pop(key, None)
            self._locked.pop(key, None)

    def clear(self) -> None:
        with self._lock:
            self._fails.clear()
            self._locked.clear()

    def __len__(self) -> int:
        return len(self._fails)


def _build() -> tuple[FailureLimiter, FailureLimiter]:
    window = _int_env("AIPISH_LOGIN_WINDOW_SECONDS", 900)
    lockout = _int_env("AIPISH_LOGIN_LOCKOUT_SECONDS", 900)
    return (FailureLimiter(_int_env("AIPISH_LOGIN_MAX_FAILURES_USER", 5), window, lockout),
            FailureLimiter(_int_env("AIPISH_LOGIN_MAX_FAILURES_IP", 20), window, lockout))


USER_LIMITER, IP_LIMITER = _build()


def reset_all() -> None:
    USER_LIMITER.clear()
    IP_LIMITER.clear()
