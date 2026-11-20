"""Test helpers: real users and real signed JWTs per role (no auth bypass exists in app code)."""
from __future__ import annotations

import secrets

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.core.db import SessionLocal, get_db
from app.core.models import User
from app.security.tokens import create_access_token
from app.security.users import create_user

_CACHE: dict[tuple[int, str], str] = {}     # (id(bind), role) → user id


def _session_for(app: FastAPI | None):
    override = app.dependency_overrides.get(get_db) if app is not None else None
    if override is None:
        return SessionLocal(), True
    db = override()
    if hasattr(db, "__next__"):
        db = next(db)
    return db, False


def strong_password() -> str:
    return "Tst-" + secrets.token_urlsafe(18)


def make_user(db, role: str = "analyst", username: str | None = None, password: str | None = None,
              **fields) -> tuple[User, str]:
    password = password or strong_password()
    u = create_user(db, username or f"t-{role}-{secrets.token_hex(4)}", password, role, audit_source="test")
    for k, v in fields.items():
        setattr(u, k, v)
    if fields:
        db.commit()
    return u, password


def user_for(app: FastAPI | None, role: str) -> User:
    db, own = _session_for(app)
    try:
        key = (id(db.get_bind()), role)
        u = db.get(User, _CACHE[key]) if key in _CACHE else None
        if u is None or not u.is_active or u.role != role or u.must_change_password:
            u, _ = make_user(db, role)
            _CACHE[key] = u.id
        db.expunge(u) if own else None
        return u
    finally:
        if own:
            db.close()


def token_for(user: User) -> str:
    return create_access_token(user)[0]


def auth_headers(user: User) -> dict[str, str]:
    return {"Authorization": f"Bearer {token_for(user)}"}


def authed_client(app: FastAPI | None = None, role: str = "admin", **kw) -> TestClient:
    """TestClient whose requests carry a real bearer token for a user of ``role``."""
    if app is None:
        from app.main import create_app
        app = create_app()
    client = TestClient(app, **kw)
    client.headers.update(auth_headers(user_for(app, role)))
    return client
