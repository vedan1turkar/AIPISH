from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="APP_",
        env_file=Path(__file__).resolve().parents[3] / ".env",
        env_file_encoding="utf-8",
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
