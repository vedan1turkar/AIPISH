from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path

from dotenv import dotenv_values
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


# ── Environment strategy (single source of truth) ────────────────────────
# Precedence, highest first:
#   1. Real process environment (shell exports, Docker Compose `environment:`)
#   2. The env file: $APP_ENV_FILE if set, else <repo root>/.env
#   3. Code defaults
# The env file is optional: a missing file is silently skipped, so Docker
# deployments can inject variables without any .env on disk.

def _resolve_env_file() -> Path | None:
    override = os.environ.get("APP_ENV_FILE")
    if override:
        return Path(override)
    parents = Path(__file__).resolve().parents  # core, app, backend, <repo root>
    return parents[3] / ".env" if len(parents) > 3 else None


ENV_FILE: Path | None = _resolve_env_file()


@lru_cache
def _env_file_values() -> dict[str, str]:
    if ENV_FILE is None or not ENV_FILE.is_file():
        return {}
    return {k: v for k, v in dotenv_values(ENV_FILE).items() if v is not None}


def env(name: str, default: str | None = None) -> str | None:
    """Read one setting: process env first, then the env file, then default."""
    value = os.environ.get(name)
    if value is not None:
        return value
    return _env_file_values().get(name, default)


def reload_env_file() -> None:
    """Drop the cached env-file contents (tests / config reload)."""
    _env_file_values.cache_clear()


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="APP_",
        env_file=ENV_FILE,
        env_file_encoding="utf-8",
        env_ignore_empty=True,
        extra="ignore",
        populate_by_name=True,
    )

    env: str = "dev"
    bind_host: str = "127.0.0.1"
    port: int = 8000
    allowed_origins: list[str] = Field(default_factory=lambda: ["http://localhost:5173"])
    db_path: str = "db/app.sqlite"
    upload_max_mb: int = 10
    request_timeout_seconds: int = 60
    log_level: str = "INFO"

    def public_dict(self) -> dict[str, object]:
        """Safe-to-serialize settings (no secrets exist yet, but keep the seam)."""
        return self.model_dump()


@lru_cache
def get_settings() -> Settings:
    return Settings()
