"""App-wide access enforcement.

``enforce_access`` is installed as a FastAPI *application-level* dependency,
so it runs for every API route, including routes added later. It resolves the
matched route to its entry in ``ROUTE_PERMISSIONS``; a route without an entry
is denied (deny by default). Handlers that need the caller use
``current_user(request)``.
"""
from __future__ import annotations

import logging

from fastapi import Depends, HTTPException, Request
from fastapi.routing import iter_route_contexts
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool

from app.core.db import get_db
from app.core.models import User
from app.security.context import set_actor
from app.security.permissions import PUBLIC, ROUTE_PERMISSIONS, SELF, role_allows
from app.security.tokens import TokenError, decode_access_token

logger = logging.getLogger(__name__)

_BEARER = {"WWW-Authenticate": "Bearer"}


def _unauthorized(code: str, message: str, error: str | None = None) -> HTTPException:
    hdr = {"WWW-Authenticate": f'Bearer error="{error}"'} if error else dict(_BEARER)
    return HTTPException(status_code=401, detail={"code": code, "message": message}, headers=hdr)


def _forbidden(code: str, message: str) -> HTTPException:
    return HTTPException(status_code=403, detail={"code": code, "message": message})


def route_index(app) -> dict[tuple[str, object], tuple[str, str | None]]:
    """(method, endpoint) → (path template, permission or None). Cached on app.state."""
    idx = getattr(app.state, "route_permission_index", None)
    if idx is not None:
        return idx
    idx = {}
    for rc in iter_route_contexts(app.routes):
        path = getattr(rc, "path_format", None) or getattr(rc, "path", "")
        for m in (getattr(rc, "methods", None) or set()):
            m = m.upper()
            perm = ROUTE_PERMISSIONS.get(("GET" if m == "HEAD" else m, path))
            idx[(m, rc.endpoint)] = (path, perm)
    app.state.route_permission_index = idx
    return idx


def _endpoint(request: Request):
    route = request.scope.get("route")
    return getattr(route, "endpoint", None) or request.scope.get("endpoint")


def _bearer_token(request: Request) -> str | None:
    header = request.headers.get("authorization") or ""
    scheme, _, token = header.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        return None
    return token.strip()


def _load_user(db: Session, claims: dict) -> User | None:
    user = db.get(User, claims["sub"])
    if user is None or not user.is_active or int(user.token_version or 0) != claims["tv"]:
        return None
    return user


async def enforce_access(request: Request, db: Session = Depends(get_db)) -> None:
    set_actor(None)
    from app.security.client_ip import client_ip
    from app.security.context import set_client_ip
    set_client_ip(client_ip(request))
    request.state.user = None
    request.state.user_role = None
    path, perm = route_index(request.app).get((request.method.upper(), _endpoint(request)), (None, None))
    if perm == PUBLIC:
        return

    token = _bearer_token(request)
    if token is None:
        raise _unauthorized("NOT_AUTHENTICATED", "Sign in to continue.")
    try:
        claims = decode_access_token(token)
    except TokenError as exc:
        expired = str(exc) == "token expired"
        raise _unauthorized("TOKEN_EXPIRED" if expired else "INVALID_TOKEN",
                            "Your session has expired. Sign in again." if expired
                            else "Invalid session. Sign in again.", "invalid_token") from None
    user = await run_in_threadpool(_load_user, db, claims)
    if user is None:
        raise _unauthorized("SESSION_REVOKED", "Your session is no longer valid. Sign in again.", "invalid_token")

    request.state.user = user
    request.state.user_role = user.role          # plain strings: safe to read after the session closes
    request.state.user_id = user.id
    set_actor(user.id)
    if perm is None:
        logger.warning("denied request to unmapped route %s %s", request.method, path or "?")
        raise _forbidden("ROUTE_NOT_PERMITTED", "This endpoint is not available to any role.")
    if user.must_change_password and perm != SELF:
        raise _forbidden("PASSWORD_CHANGE_REQUIRED", "Change your temporary password before continuing.")
    if not role_allows(user.role, perm):
        raise _forbidden("FORBIDDEN", "Your role does not allow this action.")


def current_user(request: Request) -> User:
    user = getattr(request.state, "user", None)
    if user is None:          # defensive: enforce_access always sets it on non-public routes
        raise _unauthorized("NOT_AUTHENTICATED", "Sign in to continue.")
    return user
