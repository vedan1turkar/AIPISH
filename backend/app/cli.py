"""Management commands (P5b).

    python -m app.cli create-user --username alice --role analyst [--must-change-password]
        Password from $AIPISH_NEW_USER_PASSWORD, else prompted twice with getpass.
        Passwords are never accepted on the command line (argv is visible in `ps`/shell history).

    python -m app.cli disable-user --username alice
        Disable an account locally (revokes its tokens; refuses the last active admin; audited).

    python -m app.cli backfill-attack
        Compute ATT&CK mappings for every stored analysis (latest intel run and ML assessment).
        Idempotent: a version is appended only when the results change.

    python -m app.cli rebuild-correlation
        Backfill correlation observations for every stored analysis and recompute candidate
        campaigns. Idempotent and deterministic: running it twice gives the same result.

    python -m app.cli seed-demo-campaign
        LOCAL DEV ONLY. Runs the SYNTHETIC emails in tests/fixtures/demo/campaign through the real
        analysis pipeline (external lookups off) and creates a case marked SYNTHETIC. Skips emails
        already ingested (same SHA-256), so re-running adds nothing.

    python -m app.cli migrate
        Create/upgrade the schema (versioned, idempotent; SQLite or PostgreSQL via DATABASE_URL) and
        print the schema version. Every command below runs the same upgrade first.

    python -m app.cli init-demo [--no-assessment]
        DEMO ONLY (refused when APP_ENV=production). On the configured (fresh) database: migrate,
        create demo-admin / demo-analyst / demo-viewer with random passwords written to
        $AIPISH_DEMO_CREDENTIALS_FILE (default backend/.demo_credentials, mode 0600; only the path is
        printed), seed the SYNTHETIC campaign, and analyse the synthetic BEC sample (with the ML/SHAP/LLM
        assessment when models are present). Idempotent: existing users and emails are kept.

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
    from app.core.db import SessionLocal, engine
    from app.core.models import run_additive_migrations
    run_additive_migrations(engine)      # exactly the additive upgrade the app runs at startup
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


def disable_user_cmd(args) -> int:
    from app.security.users import UserError, get_by_username, update_user
    with _session() as db:
        u = get_by_username(db, args.username)
        if u is None:
            print("error: no such user", file=sys.stderr)
            return 2
        try:
            update_user(db, u, u, is_active=False)      # actor = the account itself (local CLI operator)
        except UserError as exc:
            print(f"error: {exc.message}", file=sys.stderr)
            return 2
        print(f"disabled user {u.username}")
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


DEMO_DIR = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "demo" / "campaign"
BEC_SAMPLE = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "demo" / "bec_wire_change.eml"
DEMO_EXTRA_FIXTURE = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "demo" / "attack" / "synthetic_tor_origin.eml"
DEMO_CREDENTIALS = Path(__file__).resolve().parents[1] / ".demo_credentials"
SEED_ENVS = {"dev", "demo"}          # synthetic seeding is never allowed in production


def _preflight() -> int:
    """Fail closed before touching the database: production config + JWT secret (same checks as the app)."""
    from app.core.config import get_settings
    from app.core.production import ProductionConfigError, check_production
    from app.security.tokens import AuthConfigError, load_auth_config
    env_name = get_settings().env
    try:
        check_production(env_name)
        load_auth_config(env_name)
    except (ProductionConfigError, AuthConfigError) as exc:
        print(str(exc), file=sys.stderr)
        return 3
    return 0


def migrate_cmd(args) -> int:
    rc = _preflight()
    if rc:
        return rc
    from app.core.db import engine       # never print the URL (host/user); the dialect is enough
    from app.core.migrations import current_version, upgrade
    applied = upgrade(engine)
    print(f"database: {engine.dialect.name}")
    print(f"applied now: {', '.join(applied) if applied else 'none (already up to date)'}")
    print(f"schema version: {current_version(engine)}")
    return 0


def _demo_credentials_path() -> Path:
    from app.core.config import env
    p = env("AIPISH_DEMO_CREDENTIALS_FILE")
    return Path(p) if p else DEMO_CREDENTIALS


def init_demo_cmd(args) -> int:
    import hashlib
    import io
    from app.core.config import get_settings
    from app.core.production import is_production
    settings = get_settings()
    if is_production(settings.env):
        print("refusing: init-demo never runs with APP_ENV=production", file=sys.stderr)
        return 2
    if (settings.env or "").lower() not in SEED_ENVS:
        print("refusing: init-demo runs only with APP_ENV=dev or demo", file=sys.stderr)
        return 2
    from app.core.models import Analysis
    from app.security.passwords import generate_password
    from app.security.users import create_user, get_by_username
    path = _demo_credentials_path()
    with _session() as db:
        missing = [(u, r) for u, r in DEMO_USERS if get_by_username(db, u) is None]
        if missing or not path.is_file():
            # (re)issue every demo password so the file always matches the database
            from app.core.models import utcnow
            from app.security.passwords import hash_password
            lines = ["# AIPISH DEMO accounts (SYNTHETIC demo data only). Mode 0600, never commit.",
                     "# username\trole\tpassword"]
            for username, role in DEMO_USERS:
                pw = generate_password()
                u = get_by_username(db, username)
                if u is None:
                    create_user(db, username, pw, role, audit_source="demo_seed")
                else:
                    u.password_hash, u.role, u.is_active = hash_password(pw), role, True
                    u.must_change_password, u.failed_login_count, u.locked_until = False, 0, None
                    u.token_version = int(u.token_version or 0) + 1
                    u.password_changed_at = utcnow()
                    db.commit()
                lines.append(f"{username}\t{role}\t{pw}")
            path.parent.mkdir(parents=True, exist_ok=True)
            _write_private(path, "\n".join(lines) + "\n")
            print("demo users: created/reset")
        else:
            print("demo users: already present (credentials file kept)")
    print(f"demo credentials written to {path}")

    rc = seed_demo_campaign_cmd(args)
    if rc:
        return rc

    # P5g: one more synthetic sample with a distinct (Tor-listed in the SIMULATED data) origin, so the demo map
    # and analytics show several locations. Offline; skipped when already ingested.
    extra = DEMO_EXTRA_FIXTURE.read_bytes()
    with _session() as db:
        if db.query(Analysis).filter_by(raw_sha256=hashlib.sha256(extra).hexdigest()).first() is None:
            from starlette.datastructures import UploadFile
            from app.api.router import upload_eml
            original_env = settings.env
            settings.env = "offline"
            try:
                upload_eml(UploadFile(file=io.BytesIO(extra), filename=DEMO_EXTRA_FIXTURE.name), db)
            finally:
                settings.env = original_env
        from app.geo.demo import seed_simulated_geo
        print(f"SIMULATED geo observations added: {seed_simulated_geo(db)}")

    raw = BEC_SAMPLE.read_bytes()
    with _session() as db:
        if db.query(Analysis).filter_by(raw_sha256=hashlib.sha256(raw).hexdigest()).first() is not None:
            print("BEC sample: already analysed")
            return 0
    from starlette.datastructures import UploadFile
    original_env = settings.env
    settings.env = "offline"          # synthetic sample: no live DNS / enrichment lookups
    try:
        with _session() as db:
            upload = UploadFile(file=io.BytesIO(raw), filename=BEC_SAMPLE.name)
            from app.ml.inference import model_dir
            if getattr(args, "no_assessment", False) or not model_dir().is_dir():
                from app.api.router import upload_eml
                upload_eml(upload, db)
                print("BEC sample: analysed (rules only; models not mounted or --no-assessment)")
            else:
                from app.api.llm_router import summary_from_upload
                res = summary_from_upload(upload, db)
                ml = (res.get("ml") or {})
                llm = ((res.get("forensic_summary") or {}).get("status")) or "see dashboard"
                print(f"BEC sample: analysed with assessment (ml {ml.get('status')}, llm {llm})")
    finally:
        settings.env = original_env
    return 0


def backfill_attack_cmd(args) -> int:
    from app.attack.service import backfill
    from app.cases.service import record_audit
    with _session() as db:
        result = backfill(db)
        record_audit(db, "attack_backfilled", detail={**result, "source": "cli"})
        db.commit()
    for k, v in result.items():
        print(f"{k}: {v}")
    return 0


def rebuild_correlation_cmd(args) -> int:
    from app.correlation.engine import rebuild_all
    from app.cases.service import record_audit
    with _session() as db:
        result = rebuild_all(db)
        record_audit(db, "correlation_rebuilt", detail={**result, "source": "cli"})
        db.commit()
    for k, v in result.items():
        print(f"{k}: {v}")
    return 0


def seed_demo_campaign_cmd(args) -> int:
    import hashlib
    import io
    from app.core.config import get_settings
    settings = get_settings()
    if (settings.env or "").lower() not in SEED_ENVS:
        print("refusing: seed-demo-campaign runs only with APP_ENV=dev or demo", file=sys.stderr)
        return 2
    from starlette.datastructures import UploadFile
    from app.api.router import upload_eml
    from app.cases.service import create_investigation_from_analysis
    from app.core.models import Analysis, Case
    from app.correlation.views import campaigns_for
    files = sorted(DEMO_DIR.glob("*.eml"))
    created, skipped, ids = 0, 0, {}
    original_env = settings.env
    settings.env = "offline"          # synthetic data: no live DNS / enrichment lookups
    try:
        with _session() as db:
            for f in files:
                raw = f.read_bytes()
                existing = db.query(Analysis).filter_by(raw_sha256=hashlib.sha256(raw).hexdigest()).first()
                if existing is not None:
                    ids[f.name] = existing.id
                    skipped += 1
                    continue
                detail = upload_eml(UploadFile(file=io.BytesIO(raw), filename=f.name), db)
                ids[f.name] = detail.id
                created += 1
            first = ids.get("campaign_member_1.eml")
            title = "SYNTHETIC DEMO - candidate campaign walkthrough (fictional data)"
            case = db.query(Case).filter_by(title=title).first()
            if case is None and first:
                case = create_investigation_from_analysis(db, first)
                case.title = title
                db.commit()
            camps = campaigns_for(db, first) if first else []
            case_number = case.case_number if case else "-"
            from app.geo.demo import seed_simulated_geo
            geo_rows = seed_simulated_geo(db)      # P5g: SIMULATED, offline, synthetic fixtures only
    finally:
        settings.env = original_env
    print(f"synthetic emails ingested: {created}, already present: {skipped}")
    print(f"synthetic case: {case_number}")
    print(f"SIMULATED geo observations added: {geo_rows}")
    print("campaign of campaign_member_1: " + (", ".join(f"{c['label']} ({c['member_count']} members, "
                                                         f"{c['confidence']})" for c in camps) or "none"))
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="python -m app.cli")
    sub = p.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("create-user", help="create a user (password via env or getpass, never argv)")
    c.add_argument("--username", required=True)
    c.add_argument("--role", required=True, choices=["viewer", "analyst", "admin"])
    c.add_argument("--must-change-password", action="store_true")
    c.set_defaults(func=create_user_cmd)
    du = sub.add_parser("disable-user", help="disable an account and revoke its tokens")
    du.add_argument("--username", required=True)
    du.set_defaults(func=disable_user_cmd)
    ba = sub.add_parser("backfill-attack", help="compute ATT&CK mappings for all analyses (idempotent)")
    ba.set_defaults(func=backfill_attack_cmd)
    r = sub.add_parser("rebuild-correlation", help="backfill observations and recompute campaigns")
    r.set_defaults(func=rebuild_correlation_cmd)
    d = sub.add_parser("seed-demo-campaign", help="LOCAL DEV ONLY: synthetic campaign demo data")
    d.set_defaults(func=seed_demo_campaign_cmd)
    m = sub.add_parser("migrate", help="create/upgrade the schema (idempotent) and print its version")
    m.set_defaults(func=migrate_cmd)
    i = sub.add_parser("init-demo", help="DEMO ONLY: demo users, synthetic campaign and BEC sample")
    i.add_argument("--no-assessment", action="store_true", help="skip the ML/SHAP/LLM assessment of the BEC sample")
    i.set_defaults(func=init_demo_cmd)
    s = sub.add_parser("seed-dev-users", help="LOCAL DEV ONLY: demo users with random passwords")
    s.set_defaults(func=seed_dev_users_cmd)
    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
