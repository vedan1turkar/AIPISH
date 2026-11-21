"""Production-mode guard rails (P5i). ``APP_ENV=production`` fails closed on weak configuration.

Checked at app start-up (``create_app``), so a container with a bad configuration exits with a clear
message instead of serving. The JWT secret is checked separately by ``load_auth_config`` (all
non-test environments). Messages never include secret values.
"""
from __future__ import annotations

from app.core.config import env

PRODUCTION = "production"
MIN_DB_PASSWORD_LEN = 16
_WEAK = {"postgres", "password", "changeme", "change-me", "admin", "aipish", "secret", "example"}


class ProductionConfigError(RuntimeError):
    """Refusing to start in production with this configuration."""


def is_production(app_env: str | None) -> bool:
    return (app_env or "").strip().lower() == PRODUCTION


def db_password_problem(password: str | None) -> str | None:
    if not password:
        return "the database password is missing"
    p = password.strip()
    low = p.lower()
    if len(p) < MIN_DB_PASSWORD_LEN:
        return f"the database password is shorter than {MIN_DB_PASSWORD_LEN} characters"
    if low in _WEAK or "change" in low or "placeholder" in low or len(set(p)) < 6:
        return "the database password is a placeholder or too simple"
    return None


def check_production(app_env: str | None) -> None:
    """Raise ProductionConfigError when production mode is misconfigured; no-op elsewhere."""
    if not is_production(app_env):
        return
    from app.core.db import engine
    if engine.dialect.name != "postgresql":
        raise ProductionConfigError(
            "Refusing to start: APP_ENV=production requires DATABASE_URL to point at PostgreSQL.")
    problem = db_password_problem(engine.url.password)
    if problem:
        raise ProductionConfigError(
            f"Refusing to start: {problem}. Set a random POSTGRES_PASSWORD of at least "
            f"{MIN_DB_PASSWORD_LEN} characters (e.g. python -c 'import secrets; print(secrets.token_urlsafe(32))').")
    from app.audit.keys import key_problem
    audit_problem = key_problem(env("AIPISH_AUDIT_KEY"))
    if audit_problem:
        raise ProductionConfigError(
            f"Refusing to start: {audit_problem}. Production requires a random audit hash-chain key of at "
            "least 32 characters (python -c 'import secrets; print(secrets.token_urlsafe(48))').")


def allowed_origins(app_env: str | None, configured: list[str]) -> list[str]:
    """Strict CORS: in production only origins set explicitly in APP_ALLOWED_ORIGINS (none by default —
    the SPA is served same-origin through Nginx); elsewhere the configured/dev defaults."""
    if is_production(app_env) and not (env("APP_ALLOWED_ORIGINS") or "").strip():
        return []
    return [o for o in configured if o and o != "*"]
