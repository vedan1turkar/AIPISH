"""Database engine and session factory.

Backend selection (P5i):
- ``DATABASE_URL`` set → that database (PostgreSQL via psycopg 3 in deployments). ``postgres://`` and
  ``postgresql://`` URLs are normalised to the ``postgresql+psycopg://`` driver.
- otherwise → SQLite at ``APP_DB_PATH`` (default ``backend/db/app.sqlite``), the dev/test default.

The engine is module-level and read-only after import. Sessions always see timezone-aware UTC
timestamps on PostgreSQL (the connection time zone is pinned to UTC); SQLite drops tzinfo, which the
code already normalises with ``_aware`` helpers.
"""
from __future__ import annotations

from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.engine import URL, make_url
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from app.core.config import env, get_settings

_BACKEND_ROOT = Path(__file__).resolve().parents[2]  # backend/


def database_url() -> URL:
    """The configured database URL (DATABASE_URL, else the SQLite file at APP_DB_PATH)."""
    raw = (env("DATABASE_URL") or "").strip()
    if raw:
        url = make_url(raw)
        if url.drivername in ("postgres", "postgresql"):
            url = url.set(drivername="postgresql+psycopg")
        return url
    db_file = Path(get_settings().db_path)
    if not db_file.is_absolute():
        db_file = _BACKEND_ROOT / db_file
    db_file.parent.mkdir(parents=True, exist_ok=True)
    return make_url(f"sqlite:///{db_file}")


def redacted_url(url: URL | None = None) -> str:
    """URL safe for logs and errors: the password is never shown."""
    return (url or engine.url).render_as_string(hide_password=True)


def _make_engine(url: URL):
    if url.get_backend_name() == "sqlite":
        # FastAPI can serve from a thread pool
        return create_engine(url, connect_args={"check_same_thread": False}, echo=False)
    connect_args = {"options": "-c timezone=UTC"} if url.get_backend_name() == "postgresql" else {}
    return create_engine(url, pool_pre_ping=True, pool_size=5, max_overflow=5, connect_args=connect_args,
                         echo=False)


engine = _make_engine(database_url())
DIALECT = engine.dialect.name          # "sqlite" | "postgresql"

SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


class Base(DeclarativeBase):
    pass


def get_db():
    """FastAPI dependency yielding a scoped DB session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
