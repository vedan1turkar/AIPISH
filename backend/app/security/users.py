"""User accounts: creation, login with throttling/lockout, password change, admin operations.

Every security-relevant action writes an audit event. Passwords, hashes and
tokens never appear in audit details, logs, exceptions or API responses.
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from app.core.models import User, utcnow
from app.security import throttle
from app.security.passwords import (
    dummy_verify,
    generate_password,
    hash_password,
    password_problems,
    verify_password,
)
from app.security.permissions import ADMIN, ROLES

USERNAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{2,63}$")
MAX_PASSWORD_INPUT = 1024          # bounds hashing cost for oversized inputs


class AuthError(Exception):
    """Generic login failure. Message is always 'invalid credentials'."""


class Throttled(Exception):
    def __init__(self, retry_after: int):
        super().__init__("too many attempts")
        self.retry_after = max(1, int(retry_after))


class UserError(Exception):
    def __init__(self, status: int, code: str, message: str, problems: list[str] | None = None):
        super().__init__(message)
        self.status, self.code, self.message, self.problems = status, code, message, problems or []


def normalize_username(name: str | None) -> str:
    return (name or "").strip().lower()


def _audit(db: Session, event: str, detail: dict, actor: str | None = None) -> None:
    from app.cases.service import record_audit
    record_audit(db, event, detail=detail, actor_user_id=actor)


def _aware(dt: datetime | None) -> datetime | None:
    if dt is not None and dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)      # SQLite drops tzinfo; stored values are UTC
    return dt


def user_dict(u: User) -> dict:
    """Public representation. Never includes the password hash."""
    locked_until = _aware(u.locked_until)
    return {
        "id": u.id, "username": u.username, "role": u.role, "is_active": bool(u.is_active),
        "must_change_password": bool(u.must_change_password),
        "created_at": _aware(u.created_at).isoformat() if u.created_at else None,
        "last_login_at": _aware(u.last_login_at).isoformat() if u.last_login_at else None,
        "locked": bool(locked_until and locked_until > utcnow()),
    }


def get_by_username(db: Session, username: str) -> User | None:
    return db.query(User).filter(User.username == normalize_username(username)).one_or_none()


def active_admin_count(db: Session) -> int:
    return db.query(User).filter(User.role == ADMIN, User.is_active.is_(True)).count()


def validate_new_user(username: str, role: str) -> str:
    norm = normalize_username(username)
    if not USERNAME_RE.match(norm):
        raise UserError(400, "INVALID_USERNAME",
                        "Username must be 3–64 characters: letters, digits, '.', '_' or '-'.")
    if role not in ROLES:
        raise UserError(400, "INVALID_ROLE", f"Role must be one of: {', '.join(ROLES)}.")
    return norm


def create_user(db: Session, username: str, password: str, role: str, *, must_change_password: bool = False,
                actor_user_id: str | None = None, audit_source: str = "admin") -> User:
    norm = validate_new_user(username, role)
    problems = password_problems(password, norm)
    if problems:
        raise UserError(400, "WEAK_PASSWORD", "Password does not meet the policy.", problems)
    if get_by_username(db, norm) is not None:
        raise UserError(409, "USERNAME_TAKEN", "That username already exists.")
    u = User(username=norm, password_hash=hash_password(password), role=role, is_active=True,
             token_version=0, must_change_password=must_change_password, failed_login_count=0,
             password_changed_at=utcnow())
    db.add(u)
    db.flush()
    _audit(db, "user_created", {"user_id": u.id, "username": norm, "role": role, "source": audit_source},
           actor=actor_user_id)
    db.commit()
    return u


def authenticate(db: Session, username: str, password: str, source_ip: str) -> User:
    """Verify credentials with per-username and per-IP throttling.

    Unknown user, wrong password and disabled user all raise the same AuthError.
    While throttled/locked the password is not evaluated (a dummy hash still
    runs), so the response cannot reveal whether it was right.
    """
    norm = normalize_username(username)[:64]
    password = (password or "")[:MAX_PASSWORD_INPUT]
    ip = (source_ip or "unknown")[:64]
    user = get_by_username(db, norm) if norm else None

    wait = max(throttle.USER_LIMITER.retry_after(norm), throttle.IP_LIMITER.retry_after(ip))
    if user is not None and _aware(user.locked_until) and _aware(user.locked_until) > utcnow():
        wait = max(wait, int((_aware(user.locked_until) - utcnow()).total_seconds()) + 1)
    if wait > 0:
        dummy_verify(password)
        _audit(db, "login_throttled", {"username_attempted": norm, "source_ip": ip, "retry_after": wait})
        db.commit()
        raise Throttled(wait)

    if user is None:
        dummy_verify(password)
        ok, reason = False, "unknown_user"
    else:
        ok = verify_password(password, user.password_hash)
        reason = "bad_password" if not ok else None
        if ok and not user.is_active:
            ok, reason = False, "disabled"

    if not ok:
        user_locked = throttle.USER_LIMITER.fail(norm)
        ip_locked = throttle.IP_LIMITER.fail(ip)
        if user is not None:
            user.failed_login_count = int(user.failed_login_count or 0) + 1
            if user_locked:
                user.locked_until = utcnow() + timedelta(seconds=throttle.USER_LIMITER.lockout)
        _audit(db, "login_failed", {"username_attempted": norm, "source_ip": ip, "reason": reason,
                                    "user_id": user.id if user else None})
        if user_locked or ip_locked:
            _audit(db, "login_lockout", {"username_attempted": norm, "source_ip": ip,
                                         "scope": "username" if user_locked else "ip",
                                         "lockout_seconds": throttle.USER_LIMITER.lockout})
        db.commit()
        raise AuthError("invalid credentials")

    throttle.USER_LIMITER.reset(norm)
    user.failed_login_count = 0
    user.locked_until = None
    user.last_login_at = utcnow()
    _audit(db, "login_success", {"user_id": user.id, "username": user.username, "source_ip": ip},
           actor=user.id)
    db.commit()
    return user


def change_password(db: Session, user: User, current: str, new: str) -> User:
    key = user.username
    wait = throttle.USER_LIMITER.retry_after(key)
    if wait > 0:
        raise Throttled(wait)
    if not verify_password((current or "")[:MAX_PASSWORD_INPUT], user.password_hash):
        locked = throttle.USER_LIMITER.fail(key)
        _audit(db, "password_change_failed", {"user_id": user.id, "reason": "wrong_current_password",
                                              "locked": locked}, actor=user.id)
        db.commit()
        raise UserError(400, "INVALID_CURRENT_PASSWORD", "The current password is not correct.")
    if new == current:
        raise UserError(400, "PASSWORD_UNCHANGED", "Choose a password different from the current one.")
    problems = password_problems(new, user.username)
    if problems:
        raise UserError(400, "WEAK_PASSWORD", "Password does not meet the policy.", problems)
    user.password_hash = hash_password(new)
    user.token_version = int(user.token_version or 0) + 1
    user.must_change_password = False
    user.password_changed_at = utcnow()
    _audit(db, "password_changed", {"user_id": user.id}, actor=user.id)
    db.commit()
    return user


def logout(db: Session, user: User) -> None:
    """Revoke every token of this user (bumps token_version)."""
    user.token_version = int(user.token_version or 0) + 1
    _audit(db, "logout", {"user_id": user.id, "scope": "all_sessions"}, actor=user.id)
    db.commit()


def update_user(db: Session, actor: User, target: User, *, role: str | None = None,
                is_active: bool | None = None) -> User:
    if role is not None and role not in ROLES:
        raise UserError(400, "INVALID_ROLE", f"Role must be one of: {', '.join(ROLES)}.")
    new_role = role if role is not None else target.role
    new_active = is_active if is_active is not None else bool(target.is_active)
    loses_admin = target.role == ADMIN and target.is_active and (new_role != ADMIN or not new_active)
    if loses_admin and active_admin_count(db) <= 1:
        raise UserError(409, "LAST_ADMIN",
                        "This is the last active admin. Create or enable another admin first.")
    changes = {}
    if new_role != target.role:
        changes["role"] = {"from": target.role, "to": new_role}
        target.role = new_role
    if new_active != bool(target.is_active):
        changes["is_active"] = {"from": bool(target.is_active), "to": new_active}
        target.is_active = new_active
    if not changes:
        return target
    target.token_version = int(target.token_version or 0) + 1      # revoke existing tokens
    if "role" in changes:
        _audit(db, "user_role_changed", {"user_id": target.id, "username": target.username, **changes["role"]},
               actor=actor.id)
    if "is_active" in changes:
        _audit(db, "user_enabled" if new_active else "user_disabled",
               {"user_id": target.id, "username": target.username}, actor=actor.id)
    db.commit()
    return target


def reset_password(db: Session, actor: User, target: User) -> str:
    """Set a random temporary password (returned once to the caller, never stored in clear or logged)."""
    temp = generate_password()
    target.password_hash = hash_password(temp)
    target.token_version = int(target.token_version or 0) + 1
    target.must_change_password = True
    target.failed_login_count = 0
    target.locked_until = None
    target.password_changed_at = utcnow()
    throttle.USER_LIMITER.reset(target.username)
    _audit(db, "user_password_reset", {"user_id": target.id, "username": target.username}, actor=actor.id)
    db.commit()
    return temp
