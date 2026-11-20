"""Authentication endpoints (P5b): JSON login, current user, logout, password change.

Login takes a JSON body ``{"username", "password"}`` (not the OAuth2 form) and
returns a bearer access token. There are no refresh tokens: when the token
expires (default 60 min) the user signs in again.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.security import users as svc
from app.security.deps import current_user
from app.security.tokens import create_access_token

router = APIRouter(prefix="/auth", tags=["auth"])


class LoginRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=256)
    password: str = Field(..., min_length=1, max_length=svc.MAX_PASSWORD_INPUT)


class ChangePasswordRequest(BaseModel):
    current_password: str = Field(..., min_length=1, max_length=svc.MAX_PASSWORD_INPUT)
    new_password: str = Field(..., min_length=1, max_length=svc.MAX_PASSWORD_INPUT)


def token_response(user) -> dict:
    token, exp = create_access_token(user)
    return {"access_token": token, "token_type": "bearer", "expires_at": exp.isoformat(),
            "user": svc.user_dict(user)}


def throttled(exc: svc.Throttled) -> HTTPException:
    return HTTPException(status_code=429, headers={"Retry-After": str(exc.retry_after)}, detail={
        "code": "TOO_MANY_ATTEMPTS",
        "message": f"Too many failed attempts. Try again in {exc.retry_after} seconds."})


def user_error(exc: svc.UserError) -> HTTPException:
    detail = {"code": exc.code, "message": exc.message}
    if exc.problems:
        detail["message"] = f"{exc.message} {' '.join(exc.problems)}"
    return HTTPException(status_code=exc.status, detail=detail)


@router.post("/login")
def login(body: LoginRequest, request: Request, db: Session = Depends(get_db)) -> dict:
    ip = request.client.host if request.client else "unknown"
    try:
        user = svc.authenticate(db, body.username, body.password, ip)
    except svc.Throttled as exc:
        raise throttled(exc) from None
    except svc.AuthError:
        raise HTTPException(status_code=401, headers={"WWW-Authenticate": "Bearer"},
                            detail={"code": "INVALID_CREDENTIALS", "message": "invalid credentials"}) from None
    return token_response(user)


@router.get("/me")
def me(request: Request) -> dict:
    user = current_user(request)
    from app.security.permissions import ROLE_PERMISSIONS
    return {**svc.user_dict(user), "permissions": sorted(ROLE_PERMISSIONS.get(user.role, ()))}


@router.post("/logout")
def logout(request: Request, db: Session = Depends(get_db)) -> dict:
    svc.logout(db, current_user(request))
    return {"status": "logged_out", "scope": "all_sessions"}


@router.post("/change-password")
def change_password(body: ChangePasswordRequest, request: Request, db: Session = Depends(get_db)) -> dict:
    try:
        user = svc.change_password(db, current_user(request), body.current_password, body.new_password)
    except svc.Throttled as exc:
        raise throttled(exc) from None
    except svc.UserError as exc:
        raise user_error(exc) from None
    return token_response(user)      # old tokens are revoked; continue with a fresh one
