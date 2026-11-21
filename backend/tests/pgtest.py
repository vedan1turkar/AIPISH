"""Opt-in PostgreSQL test database (P5i).

``TEST_DATABASE_URL=postgresql://user:pass@127.0.0.1:55432/aipish_test pytest --allow-hosts=127.0.0.1``

The suite then runs against a dedicated database that is dropped and re-created at session start and
dropped at the end (``AIPISH_KEEP_TEST_DB=1`` keeps it). The database name must look like a test
database, so a typo can never wipe an application database.
"""
from __future__ import annotations

import re

from sqlalchemy.engine import make_url

_TEST_NAME = re.compile(r"(^|[_-])test([_-]|$)|^test", re.IGNORECASE)


class UnsafeTestDatabase(RuntimeError):
    pass


def _admin_conninfo(url) -> dict:
    return {"host": url.host or "127.0.0.1", "port": url.port or 5432, "user": url.username,
            "password": url.password, "dbname": "postgres", "autocommit": True}


def check_name(name: str | None) -> str:
    if not name or not _TEST_NAME.search(name):
        raise UnsafeTestDatabase(
            f"refusing to run tests against database {name!r}: TEST_DATABASE_URL must name a dedicated "
            "test database (e.g. aipish_test); it is dropped and re-created.")
    return name


def prepare_test_database(raw_url: str) -> str:
    """Drop + create the test database; return the SQLAlchemy URL (psycopg driver) to use."""
    import psycopg
    url = make_url(raw_url)
    if url.get_backend_name() != "postgresql":
        raise UnsafeTestDatabase("TEST_DATABASE_URL must be a postgresql:// URL")
    name = check_name(url.database)
    with psycopg.connect(**_admin_conninfo(url)) as conn:
        conn.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')
        conn.execute(f'CREATE DATABASE "{name}"')
    return url.set(drivername="postgresql+psycopg").render_as_string(hide_password=False)


def drop_test_database(raw_url: str) -> None:
    import psycopg
    url = make_url(raw_url)
    name = check_name(url.database)
    with psycopg.connect(**_admin_conninfo(url)) as conn:
        conn.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')
