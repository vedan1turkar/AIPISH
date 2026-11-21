"""HMAC-SHA256 hash chain over ``audit_event`` (P5e). Tamper-EVIDENT, not tamper-PROOF.

event_hash(n) = HMAC-SHA256(AIPISH_AUDIT_KEY, canonical(event n) + "|" + prev_hash), prev_hash(1) = "0"*64.

canonical(event) is compact, key-sorted JSON of: seq, id, event_type, created_at (UTC, microseconds),
actor_user_id, analysis_id, case_id, target_type, target_id, outcome, source_ip, detail.

Appends are serialised by the single ``audit_chain_head`` row: each append first runs
``UPDATE audit_chain_head SET seq = seq + 1 … RETURNING`` inside the caller's transaction. That takes a
row lock on PostgreSQL and the database write lock on SQLite, so concurrent writers queue and the chain
stays linear; a rollback rolls back the head too.

``verify`` recomputes every HMAC, checks seq continuity and prev links, and compares the tail with the
head row (so a deleted last event is detected). Database triggers (``ensure_triggers``) reject UPDATE,
DELETE (and TRUNCATE on PostgreSQL) on audit rows; a database superuser can still bypass them.
"""
from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime, timezone

from sqlalchemy import select, text, update
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from app.audit.keys import audit_key

GENESIS_PREV = "0" * 64
TRIGGER_MESSAGE = "audit_event is append-only (P5e)"


def _ts(dt: datetime | None) -> str:
    if dt is None:
        return ""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def canonical(ev) -> bytes:
    body = {
        "seq": ev.seq, "id": ev.id, "event_type": ev.event_type, "created_at": _ts(ev.created_at),
        "actor_user_id": ev.actor_user_id, "analysis_id": ev.analysis_id, "case_id": ev.case_id,
        "target_type": ev.target_type, "target_id": ev.target_id, "outcome": ev.outcome,
        "source_ip": ev.source_ip, "detail": ev.detail or {},
    }
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str).encode()


def compute_hash(ev, prev_hash: str, key: bytes | None = None) -> str:
    return hmac.new(key or audit_key(), canonical(ev) + b"|" + prev_hash.encode(), hashlib.sha256).hexdigest()


def _head_table():
    from app.core.models import AuditChainHead
    return AuditChainHead.__table__


def ensure_head(db_or_conn) -> None:
    head = _head_table()
    if db_or_conn.execute(select(head.c.id).where(head.c.id == 1)).first() is None:
        db_or_conn.execute(head.insert().values(id=1, seq=0, last_hash=GENESIS_PREV))


def append(db: Session, ev) -> None:
    """Assign seq/prev_hash/event_hash to a new AuditEvent and add it (inside the caller's transaction)."""
    from app.core.models import utcnow
    head = _head_table()
    if ev.created_at is None:
        ev.created_at = utcnow()
    row = db.execute(update(head).where(head.c.id == 1).values(seq=head.c.seq + 1)
                     .returning(head.c.seq, head.c.last_hash)).first()
    if row is None:                       # first event of a database whose head was never created
        ensure_head(db)
        row = db.execute(update(head).where(head.c.id == 1).values(seq=head.c.seq + 1)
                         .returning(head.c.seq, head.c.last_hash)).first()
    ev.seq, ev.prev_hash = int(row[0]), row[1]
    ev.event_hash = compute_hash(ev, ev.prev_hash)
    db.add(ev)
    db.execute(update(head).where(head.c.id == 1).values(last_hash=ev.event_hash))
    db.flush()


def verify(db: Session, key: bytes | None = None) -> dict:
    """Walk the chain. Returns {"ok", "checked", "last_seq", "last_hash", "first_broken_seq", "reason"}."""
    from app.core.models import AuditEvent
    key = key or audit_key()
    unchained = db.query(AuditEvent).filter(AuditEvent.seq.is_(None)).count()
    expected_seq, prev = 1, GENESIS_PREV
    checked = 0
    for ev in db.query(AuditEvent).filter(AuditEvent.seq.isnot(None)).order_by(AuditEvent.seq).yield_per(500):
        if ev.seq != expected_seq:
            reason = (f"seq {expected_seq} is missing (deleted or never written)" if ev.seq > expected_seq
                      else f"duplicate seq {ev.seq}")
            return _result(False, checked, expected_seq, reason, prev, unchained)
        if ev.prev_hash != prev:
            return _result(False, checked, ev.seq, "prev_hash does not link to the previous event "
                                                   "(re-ordered, inserted or deleted)", prev, unchained)
        if not hmac.compare_digest(compute_hash(ev, prev, key), ev.event_hash or ""):
            return _result(False, checked, ev.seq, "event_hash mismatch: the event content was changed", prev,
                           unchained)
        prev = ev.event_hash
        expected_seq += 1
        checked += 1
    head = db.execute(select(_head_table())).first()
    if head is not None and (int(head.seq) != checked or head.last_hash != prev):
        return _result(False, checked, checked + 1 if int(head.seq) > checked else int(head.seq),
                       "chain head mismatch: events after the last verified one are missing", prev, unchained)
    if unchained:
        return _result(False, checked, None, f"{unchained} event(s) have no chain fields (written outside the "
                                             "audit writer)", prev, unchained)
    return _result(True, checked, None, None, prev, unchained)


def _result(ok: bool, checked: int, broken: int | None, reason: str | None, last_hash: str, unchained: int) -> dict:
    return {"ok": ok, "checked": checked, "last_seq": checked, "last_hash": last_hash,
            "first_broken_seq": broken, "reason": reason, "unchained_events": unchained}


# ── migration helpers ────────────────────────────────────────────────────────
def genesis_backfill(engine: Engine) -> int:
    """Chain pre-existing (legacy) events once, in (created_at, id) order, then append a chain_genesis marker.

    Only the chain columns of legacy rows are set (content is never rewritten). Idempotent: does nothing
    when any event already has a seq. Must run before the append-only triggers exist.
    """
    from app.core.models import AuditEvent, new_id, utcnow
    from sqlalchemy.orm import Session as S
    with S(bind=engine) as db:
        if db.query(AuditEvent).filter(AuditEvent.seq.isnot(None)).first() is not None:
            return 0
        ensure_head(db)
        legacy = db.query(AuditEvent).order_by(AuditEvent.created_at, AuditEvent.id).all()
        prev, seq = GENESIS_PREV, 0
        for ev in legacy:
            seq += 1
            ev.seq, ev.prev_hash = seq, prev
            ev.event_hash = compute_hash(ev, prev)
            prev = ev.event_hash
        head = _head_table()
        db.execute(update(head).where(head.c.id == 1).values(seq=seq, last_hash=prev))
        db.flush()
        append(db, AuditEvent(
            id=new_id(), event_type="chain_genesis", created_at=utcnow(), target_type="audit",
            outcome="success", detail={
                "legacy_events": len(legacy),
                "note": (f"Events with seq 1..{seq} pre-date the hash chain: they were chained once at "
                         "migration without changing their content, so they prove order and integrity only "
                         "from this point on." if legacy else "Hash chain started on an empty audit log.")}))
        db.commit()
        return len(legacy)


def ensure_triggers(engine: Engine) -> None:
    """Idempotently create triggers that reject UPDATE/DELETE (and TRUNCATE on PostgreSQL) on audit_event."""
    with engine.begin() as conn:
        if engine.dialect.name == "postgresql":
            conn.execute(text(f"""
                CREATE OR REPLACE FUNCTION aipish_audit_append_only() RETURNS trigger AS $$
                BEGIN RAISE EXCEPTION '{TRIGGER_MESSAGE}'; END $$ LANGUAGE plpgsql"""))
            conn.execute(text("DROP TRIGGER IF EXISTS audit_event_no_update_delete ON audit_event"))
            conn.execute(text("CREATE TRIGGER audit_event_no_update_delete BEFORE UPDATE OR DELETE ON audit_event "
                              "FOR EACH ROW EXECUTE FUNCTION aipish_audit_append_only()"))
            conn.execute(text("DROP TRIGGER IF EXISTS audit_event_no_truncate ON audit_event"))
            conn.execute(text("CREATE TRIGGER audit_event_no_truncate BEFORE TRUNCATE ON audit_event "
                              "FOR EACH STATEMENT EXECUTE FUNCTION aipish_audit_append_only()"))
        else:
            for op in ("UPDATE", "DELETE"):
                conn.execute(text(f"CREATE TRIGGER IF NOT EXISTS audit_event_no_{op.lower()} BEFORE {op} ON audit_event "
                                  f"BEGIN SELECT RAISE(ABORT, '{TRIGGER_MESSAGE}'); END"))


def checkpoint(db: Session) -> dict:
    """Record the current chain tip as an audit event and return it for external recording."""
    from app.cases.service import record_audit
    v = verify(db)
    tip = {"seq": v["last_seq"], "event_hash": v["last_hash"], "chain_ok": v["ok"],
           "created_at": datetime.now(timezone.utc).isoformat()}
    record_audit(db, "audit_checkpoint", target_type="audit", detail=tip)
    db.commit()
    return tip
