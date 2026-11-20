"""User administration (P5b, admin only via the central permission map)."""
from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.api.auth_router import user_error
from app.core.db import get_db
from app.core.models import User
from app.security import users as svc
from app.security.deps import current_user
from app.security.passwords import generate_password

router = APIRouter(prefix="/admin", tags=["admin"])

Role = Literal["viewer", "analyst", "admin"]


class CreateUserRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=64)
    role: Role


class UpdateUserRequest(BaseModel):
    role: Role | None = None
    is_active: bool | None = None


def _target(db: Session, user_id: str) -> User:
    u = db.get(User, user_id)
    if u is None:
        raise HTTPException(status_code=404, detail={"code": "USER_NOT_FOUND", "message": "User not found."})
    return u


@router.get("/users")
def list_users(db: Session = Depends(get_db)) -> list[dict]:
    return [svc.user_dict(u) for u in db.query(User).order_by(User.username).all()]


@router.post("/users", status_code=201)
def create_user(body: CreateUserRequest, request: Request, db: Session = Depends(get_db)) -> dict:
    """Creates the user with a random temporary password, returned once here and never stored in clear."""
    temp = generate_password()
    try:
        u = svc.create_user(db, body.username, temp, body.role, must_change_password=True,
                            actor_user_id=current_user(request).id)
    except svc.UserError as exc:
        raise user_error(exc) from None
    return {"user": svc.user_dict(u), "temporary_password": temp,
            "note": "Shown once. The user must change it at first sign-in."}


@router.patch("/users/{user_id}")
def update_user(user_id: str, body: UpdateUserRequest, request: Request, db: Session = Depends(get_db)) -> dict:
    try:
        u = svc.update_user(db, current_user(request), _target(db, user_id), role=body.role,
                            is_active=body.is_active)
    except svc.UserError as exc:
        raise user_error(exc) from None
    return svc.user_dict(u)


@router.post("/users/{user_id}/reset-password")
def reset_password(user_id: str, request: Request, db: Session = Depends(get_db)) -> dict:
    target = _target(db, user_id)
    temp = svc.reset_password(db, current_user(request), target)
    return {"user": svc.user_dict(target), "temporary_password": temp,
            "note": "Shown once. Existing sessions were revoked; the user must change it at next sign-in."}
