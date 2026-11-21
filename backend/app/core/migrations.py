"""Versioned, idempotent schema migrations for SQLite and PostgreSQL (P5i).

Why not Alembic: the schema has only a few additive steps, every one already idempotent, and the
project needs them to run from app start-up *and* every CLI command (the P5b lesson). A small
``schema_migrations`` table with ordered steps covers that with no extra dependency.

How it works (``upgrade(engine)``):
1. Take a lock (PostgreSQL: ``pg_advisory_lock``; SQLite: single-process dev, no lock needed).
2. ``Base.metadata.create_all`` — creates any missing table/index from the models. Safe to repeat.
3. Run each step in ``STEPS`` whose version is not recorded in ``schema_migrations``, in order, and
   record it. Every step must itself be idempotent (check before change), so a step interrupted
   before it is recorded is simply run again next time.

Adding a migration: append ``(next_version, "short_name", function(engine))`` to ``STEPS``. Use only
SQL that both dialects accept (``ALTER TABLE … ADD COLUMN``, ``CREATE INDEX IF NOT EXISTS``), check
the current schema with ``sqlalchemy.inspect`` first, never edit or reorder an existing step, and add
a test that runs ``upgrade`` twice. Destructive changes (drop/rename) need a documented backup first.
"""
from __future__ import annotations

from collections.abc import Callable
from contextlib import contextmanager

from sqlalchemy import inspect, text
from sqlalchemy.engine import Engine

from app.core.db import Base

# arbitrary constant: one advisory lock id for "schema migration in progress"
_PG_LOCK_ID = 7_340_501


def _baseline(engine: Engine) -> None:
    """v1: every table and model-declared index (create_all already ran; recorded for history)."""


def _audit_actor(engine: Engine) -> None:
    from app.core.models import migrate_audit_actor
    migrate_audit_actor(engine)


def _analysis_search_indexes(engine: Engine) -> None:
    from app.core.models import migrate_correlation_indexes
    migrate_correlation_indexes(engine)


STEPS: list[tuple[int, str, Callable[[Engine], None]]] = [
    (1, "baseline_tables", _baseline),
    (2, "audit_event_actor_user_id", _audit_actor),
    (3, "analysis_search_indexes", _analysis_search_indexes),
    (4, "geo_observation_table", _baseline),       # P5g: new table, created by create_all
]


@contextmanager
def _migration_lock(engine: Engine):
    if engine.dialect.name != "postgresql":
        yield
        return
    with engine.connect() as conn:
        conn.execute(text("SELECT pg_advisory_lock(:k)"), {"k": _PG_LOCK_ID})
        conn.commit()
        try:
            yield
        finally:
            conn.execute(text("SELECT pg_advisory_unlock(:k)"), {"k": _PG_LOCK_ID})
            conn.commit()


def applied_versions(engine: Engine) -> set[int]:
    if not inspect(engine).has_table("schema_migrations"):
        return set()
    with engine.connect() as conn:
        return {int(r[0]) for r in conn.execute(text("SELECT version FROM schema_migrations"))}


def upgrade(engine: Engine) -> list[str]:
    """Bring the schema up to date. Idempotent; returns the names of steps applied now."""
    import app.core.models  # noqa: F401  (register every model on Base.metadata)
    from app.core.models import SchemaMigration, utcnow

    applied_now: list[str] = []
    with _migration_lock(engine):
        Base.metadata.create_all(bind=engine)
        done = applied_versions(engine)
        for version, name, step in STEPS:
            if version in done:
                continue
            step(engine)
            with engine.begin() as conn:
                conn.execute(SchemaMigration.__table__.insert().values(
                    version=version, name=name, applied_at=utcnow()))
            applied_now.append(name)
    return applied_now


def current_version(engine: Engine) -> int:
    done = applied_versions(engine)
    return max(done) if done else 0
