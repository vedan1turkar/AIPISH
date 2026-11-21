"""AIPISH_AUDIT_KEY handling (P5e).

- production / demo: the key must be set and strong, else start-up refuses (fail closed);
- dev / offline (local): a random key is generated once and appended to the gitignored env file
  (``<repo>/.env`` or APP_ENV_FILE) with mode 0600 — never printed;
- test: a random per-process key (tests never depend on a persisted key).
The key never appears in responses, logs or audit details.
"""
from __future__ import annotations

import os
import secrets
from functools import lru_cache

from app.core.config import ENV_FILE, env, get_settings, reload_env_file

MIN_LEN = 32
_TEST_KEY = secrets.token_urlsafe(48)
GENERATE_ENVS = {"dev", "offline"}


class AuditKeyError(RuntimeError):
    """Refusing to start: the audit key is missing or weak."""


def key_problem(key: str | None) -> str | None:
    if not key or not key.strip():
        return "AIPISH_AUDIT_KEY is not set"
    k = key.strip()
    low = k.lower()
    if len(k) < MIN_LEN:
        return f"AIPISH_AUDIT_KEY is shorter than {MIN_LEN} characters"
    if "change" in low or "placeholder" in low or "example" in low or len(set(k)) < 10:
        return "AIPISH_AUDIT_KEY looks like a placeholder"
    return None


def _generate_into_env_file() -> str | None:
    if ENV_FILE is None:
        return None
    key = secrets.token_urlsafe(48)
    try:
        existed = ENV_FILE.is_file()
        fd = os.open(ENV_FILE, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        try:
            prefix = b"\n" if existed and ENV_FILE.stat().st_size and not ENV_FILE.read_bytes().endswith(b"\n") else b""
            os.write(fd, prefix + b"# P5e: audit hash-chain key, generated locally. Keep secret; never commit.\n"
                     + f"AIPISH_AUDIT_KEY={key}\n".encode())
        finally:
            os.close(fd)
    except OSError:
        return None
    os.environ["AIPISH_AUDIT_KEY"] = key
    reload_env_file()
    return key


@lru_cache
def audit_key() -> bytes:
    app_env = (get_settings().env or "").lower()
    key = env("AIPISH_AUDIT_KEY")
    problem = key_problem(key)
    if problem is None:
        return key.strip().encode()
    if app_env == "test":
        return _TEST_KEY.encode()
    if app_env in GENERATE_ENVS and not (key or "").strip():
        generated = _generate_into_env_file()
        if generated:
            return generated.encode()
    raise AuditKeyError(
        f"Refusing to start: {problem}. Set a random value of at least {MIN_LEN} characters "
        "(python -c 'import secrets; print(secrets.token_urlsafe(48))') in the environment or env file.")


def reset_audit_key_cache() -> None:
    audit_key.cache_clear()
