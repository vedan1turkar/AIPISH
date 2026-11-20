"""Management commands (P5b).

    python -m app.cli create-user --username alice --role analyst [--must-change-password]
        Password from $AIPISH_NEW_USER_PASSWORD, else prompted twice with getpass.
        Passwords are never accepted on the command line (argv is visible in `ps`/shell history).

    python -m app.cli seed-dev-users
        LOCAL DEV ONLY (APP_ENV=dev). (Re)creates demo-admin / demo-analyst / demo-viewer with
        random strong passwords written to backend/.dev_credentials (mode 0600, gitignored).
        Prints only the file path, never a password.
"""
from __future__ import annotations

import argparse
import getpass
import os
import sys
from pathlib import Path

DEV_CREDENTIALS = Path(__file__).resolve().parents[1] / ".dev_credentials"
DEMO_USERS = (("demo-admin", "admin"), ("demo-analyst", "analyst"), ("demo-viewer", "viewer"))


def _session():
    from app.core.db import Base, SessionLocal, engine
    from app.core.models import migrate_audit_actor
    Base.metadata.create_all(bind=engine)
    migrate_audit_actor(engine)          # same additive upgrade the app runs at startup
    return SessionLocal()


def _read_password() -> str:
    pw = os.environ.get("AIPISH_NEW_USER_PASSWORD")
    if pw:
        return pw
    if not sys.stdin.isatty():
        raise SystemExit("No TTY: set AIPISH_NEW_USER_PASSWORD in the environment instead.")
    first = getpass.getpass("New password: ")
    if first != getpass.getpass("Repeat password: "):
        raise SystemExit("Passwords do not match.")
    return first


def create_user_cmd(args) -> int:
    from app.security.users import UserError, create_user
    password = _read_password()
    with _session() as db:
        try:
            u = create_user(db, args.username, password, args.role,
                            must_change_password=args.must_change_password, audit_source="cli")
        except UserError as exc:
            print(f"error: {exc.message} {' '.join(exc.problems)}".strip(), file=sys.stderr)
            return 2
        print(f"created user {u.username} ({u.role})")
    return 0


def _write_private(path: Path, text: str) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, text.encode("utf-8"))
    finally:
        os.close(fd)
    os.chmod(path, 0o600)


def seed_dev_users_cmd(args) -> int:
    from app.core.config import get_settings
    if (get_settings().env or "").lower() != "dev":
        print("refusing: seed-dev-users runs only with APP_ENV=dev", file=sys.stderr)
        return 2
    from app.core.models import utcnow
    from app.security.passwords import generate_password, hash_password
    from app.security.users import create_user, get_by_username
    lines = ["# AIPISH LOCAL DEV demo accounts. Gitignored, mode 0600. Never use in any shared environment.",
             "# Regenerate with: python -m app.cli seed-dev-users"]
    with _session() as db:
        for username, role in DEMO_USERS:
            pw = generate_password()
            u = get_by_username(db, username)
            if u is None:
                create_user(db, username, pw, role, audit_source="dev_seed")
            else:
                u.password_hash, u.role, u.is_active = hash_password(pw), role, True
                u.must_change_password, u.failed_login_count, u.locked_until = False, 0, None
                u.token_version = int(u.token_version or 0) + 1
                u.password_changed_at = utcnow()
                db.commit()
            lines.append(f"{username}\t{role}\t{pw}")
    _write_private(DEV_CREDENTIALS, "\n".join(lines) + "\n")
    print(f"dev credentials written to {DEV_CREDENTIALS}")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="python -m app.cli")
    sub = p.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("create-user", help="create a user (password via env or getpass, never argv)")
    c.add_argument("--username", required=True)
    c.add_argument("--role", required=True, choices=["viewer", "analyst", "admin"])
    c.add_argument("--must-change-password", action="store_true")
    c.set_defaults(func=create_user_cmd)
    s = sub.add_parser("seed-dev-users", help="LOCAL DEV ONLY: demo users with random passwords")
    s.set_defaults(func=seed_dev_users_cmd)
    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
