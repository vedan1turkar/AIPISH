from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from app.core.config import get_settings

# Derive the SQLite path from settings so it is configurable; keep the engine
# module-level and read-only after import. The path is resolved relative to the
# backend/ directory so it is independent of the process working directory.
_settings = get_settings()
_db_file = Path(_settings.db_path)
_backend_root = Path(__file__).resolve().parents[2]  # backend/
if not _db_file.is_absolute():
    _db_file = _backend_root / _db_file
_db_file.parent.mkdir(parents=True, exist_ok=True)

engine = create_engine(
    f"sqlite:///{_db_file}",
    connect_args={"check_same_thread": False},  # FastAPI can serve from a thread pool
    echo=False,
)

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
