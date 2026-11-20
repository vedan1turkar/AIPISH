"""HS256 access tokens (PyJWT) and fail-closed secret handling.

Secret: ``AIPISH_JWT_SECRET`` (process env, then the repo-root ``.env``).
Outside ``APP_ENV=test`` the app refuses to start when the secret is missing,
shorter than 32 characters, low-variety or a known placeholder. Under
``APP_ENV=test`` an invalid/missing secret is replaced by a random
per-process secret (tokens are still fully signed and verified — there is no
bypass).

Claims: sub (user id), role, jti, iat, exp, tv (token_version), iss, aud.
Only HS256 is accepted on decode, so ``alg=none`` and algorithm-confusion
tokens are rejected; exp/iat/iss/aud/sub/jti are required.
"""
from __future__ import annotations

import secrets
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

import jwt

from app.core.config import env, get_settings

ALGORITHM = "HS256"
ISSUER = "aipish"
AUDIENCE = "aipish-api"
MIN_SECRET_LEN = 32
_PLACEHOLDER_HINTS = ("change", "replace", "placeholder", "example", "your", "secret", "default",
                      "xxxx", "todo", "dummy", "insecure", "password")


class AuthConfigError(RuntimeError):
    """Raised at startup when auth cannot be configured safely. Never contains the secret."""


@dataclass(frozen=True)
class AuthConfig:
    secret: str = field(repr=False)
    ttl_minutes: int
    issuer: str = ISSUER
    audience: str = AUDIENCE
    ephemeral: bool = False


def secret_problem(secret: str | None) -> str | None:
    """Why a secret is unacceptable (never echoes it), or None."""
    if not secret or not secret.strip():
        return "AIPISH_JWT_SECRET is not set"
    s = secret.strip()
    if len(s) < MIN_SECRET_LEN:
        return f"AIPISH_JWT_SECRET is shorter than {MIN_SECRET_LEN} characters"
    if len(set(s)) < 10:
        return "AIPISH_JWT_SECRET has too little variety"
    low = s.lower()
    if any(h in low for h in _PLACEHOLDER_HINTS):
        return "AIPISH_JWT_SECRET looks like a placeholder"
    return None


def _ttl() -> int:
    try:
        v = int(env("AIPISH_JWT_TTL_MINUTES", "60") or "60")
    except ValueError:
        v = 60
    return max(1, min(v, 24 * 60))


_EPHEMERAL_TEST_SECRET = secrets.token_urlsafe(48)     # one per process, test env only


def load_auth_config(app_env: str | None = None) -> AuthConfig:
    app_env = (app_env or get_settings().env or "").lower()
    secret = env("AIPISH_JWT_SECRET")
    problem = secret_problem(secret)
    if problem is None:
        return AuthConfig(secret=secret.strip(), ttl_minutes=_ttl())
    if app_env == "test":
        return AuthConfig(secret=_EPHEMERAL_TEST_SECRET, ttl_minutes=_ttl(), ephemeral=True)
    raise AuthConfigError(
        f"Refusing to start: {problem}. Set a random value of at least {MIN_SECRET_LEN} characters "
        "(e.g. python -c 'import secrets; print(secrets.token_urlsafe(48))') in the environment or .env.")


_CONFIG: AuthConfig | None = None


def get_auth_config() -> AuthConfig:
    global _CONFIG
    if _CONFIG is None:
        _CONFIG = load_auth_config()
    return _CONFIG


def set_auth_config(cfg: AuthConfig | None) -> None:
    global _CONFIG
    _CONFIG = cfg


class TokenError(Exception):
    """Invalid token. The message is generic and safe to return."""


def create_access_token(user, *, cfg: AuthConfig | None = None, now: datetime | None = None,
                        ttl_minutes: int | None = None) -> tuple[str, datetime]:
    cfg = cfg or get_auth_config()
    now = now or datetime.now(timezone.utc)
    exp = now + timedelta(minutes=ttl_minutes if ttl_minutes is not None else cfg.ttl_minutes)
    claims = {
        "sub": user.id, "role": user.role, "tv": int(user.token_version or 0),
        "jti": uuid.uuid4().hex, "iat": int(now.timestamp()), "exp": int(exp.timestamp()),
        "iss": cfg.issuer, "aud": cfg.audience,
    }
    return jwt.encode(claims, cfg.secret, algorithm=ALGORITHM), exp


def decode_access_token(token: str, *, cfg: AuthConfig | None = None) -> dict:
    cfg = cfg or get_auth_config()
    try:
        header = jwt.get_unverified_header(token)
        if header.get("alg") != ALGORITHM:
            raise TokenError("invalid token")
        claims = jwt.decode(
            token, cfg.secret, algorithms=[ALGORITHM], audience=cfg.audience, issuer=cfg.issuer,
            options={"require": ["exp", "iat", "sub", "jti", "iss", "aud"]},
        )
    except jwt.ExpiredSignatureError:
        raise TokenError("token expired") from None
    except TokenError:
        raise
    except Exception:
        raise TokenError("invalid token") from None
    if not isinstance(claims.get("sub"), str) or not isinstance(claims.get("tv"), int) \
            or not isinstance(claims.get("role"), str):
        raise TokenError("invalid token")
    return claims
