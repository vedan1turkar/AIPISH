"""Audit log, custody timeline, retention, legal holds and erasure endpoints (P5e).

Every route is in the central permission map (app/security/permissions.py). Audit and retention are
admin-only; the per-analysis custody timeline is analyst+.
"""
from __future__ import annotations

import csv
import io
import json
from datetime import date, datetime, time, timezone
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import Response
from pydantic import BaseModel, Field
from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.audit import GUARANTEE, INTEGRITY_NOTE
from app.audit.chain import checkpoint, verify
from app.cases.service import record_audit
from app.core.db import get_db
from app.core.models import Analysis, AuditEvent, User
from app.retention import service as retention
from app.security.deps import current_user

router = APIRouter(tags=["audit"])
MAX_PAGE = 100
EXPORT_CAP = 10_000


def _iso(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    return (dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)).isoformat()


def _usernames(db: Session, ids: set[str]) -> dict[str, str]:
    ids = {i for i in ids if i}
    if not ids:
        return {}
    return {u.id: u.username for u in db.query(User).filter(User.id.in_(sorted(ids))).all()}


def event_dict(e: AuditEvent, names: dict[str, str], with_chain: bool = True) -> dict:
    out = {"seq": e.seq, "id": e.id, "at": _iso(e.created_at), "action": e.event_type,
           "actor_id": e.actor_user_id, "actor": names.get(e.actor_user_id or "", None),
           "target_type": e.target_type, "target_id": e.target_id, "analysis_id": e.analysis_id,
           "case_id": e.case_id, "outcome": e.outcome, "source_ip": e.source_ip, "detail": e.detail or {}}
    if with_chain:
        out["hash_prefix"] = (e.event_hash or "")[:12]
    return out


def _filtered(db: Session, actor: str | None, action: str | None, target_type: str | None,
              target_id: str | None, outcome: str | None, date_from: date | None, date_to: date | None):
    q = db.query(AuditEvent)
    if actor:
        user = db.query(User).filter(User.username == actor.strip().lower()).first()
        q = q.filter(AuditEvent.actor_user_id == (user.id if user else actor.strip()))
    if action:
        q = q.filter(AuditEvent.event_type == action)
    if target_type:
        q = q.filter(AuditEvent.target_type == target_type)
    if target_id:
        q = q.filter(or_(AuditEvent.target_id == target_id, AuditEvent.analysis_id == target_id,
                         AuditEvent.case_id == target_id))
    if outcome:
        q = q.filter(AuditEvent.outcome == outcome)
    if date_from:
        q = q.filter(AuditEvent.created_at >= datetime.combine(date_from, time.min, tzinfo=timezone.utc))
    if date_to:
        q = q.filter(AuditEvent.created_at <= datetime.combine(date_to, time.max, tzinfo=timezone.utc))
    return q


@router.get("/audit/events")
def audit_events(actor: str | None = None, action: str | None = None, target_type: str | None = None,
                 target_id: str | None = None, outcome: str | None = None, date_from: date | None = None,
                 date_to: date | None = None, page: int = Query(1, ge=1, le=100_000),
                 page_size: int = Query(50, ge=1, le=MAX_PAGE), db: Session = Depends(get_db)) -> dict:
    q = _filtered(db, actor, action, target_type, target_id, outcome, date_from, date_to)
    total = q.count()
    rows = q.order_by(AuditEvent.seq.desc().nulls_last(), AuditEvent.created_at.desc()) \
        .offset((page - 1) * page_size).limit(page_size).all()
    names = _usernames(db, {r.actor_user_id for r in rows})
    actions = [a for (a,) in db.query(AuditEvent.event_type).distinct().order_by(AuditEvent.event_type).all()]
    return {"items": [event_dict(r, names) for r in rows], "total": total, "page": page, "page_size": page_size,
            "actions": actions, "guarantee": GUARANTEE}


@router.get("/audit/export")
def audit_export(format: Literal["csv", "json"] = "json", actor: str | None = None, action: str | None = None,
                 target_type: str | None = None, target_id: str | None = None, outcome: str | None = None,
                 date_from: date | None = None, date_to: date | None = None,
                 db: Session = Depends(get_db)) -> Response:
    q = _filtered(db, actor, action, target_type, target_id, outcome, date_from, date_to)
    total = q.count()
    rows = q.order_by(AuditEvent.seq.asc().nulls_first()).limit(EXPORT_CAP).all()
    names = _usernames(db, {r.actor_user_id for r in rows})
    items = [event_dict(r, names) for r in rows]
    for it, r in zip(items, rows):
        it["prev_hash"], it["event_hash"] = r.prev_hash, r.event_hash
    record_audit(db, "audit_exported", target_type="audit", detail={
        "format": format, "rows": len(items), "capped": total > EXPORT_CAP,
        "filters": {k: v for k, v in {"actor": actor, "action": action, "target_type": target_type,
                                      "target_id": target_id, "outcome": outcome,
                                      "date_from": str(date_from or ""), "date_to": str(date_to or "")}.items() if v}})
    db.commit()
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    if format == "json":
        body = json.dumps({"guarantee": GUARANTEE, "total": total, "exported": len(items), "capped": total > EXPORT_CAP,
                           "events": items}, ensure_ascii=False, indent=1)
        return Response(body, media_type="application/json",
                        headers={"Content-Disposition": f'attachment; filename="aipish-audit-{stamp}.json"'})
    buf = io.StringIO()
    cols = ["seq", "at", "action", "actor", "actor_id", "target_type", "target_id", "analysis_id", "case_id",
            "outcome", "source_ip", "prev_hash", "event_hash", "detail"]
    w = csv.writer(buf)
    w.writerow(cols)
    for it in items:
        w.writerow([json.dumps(it[c], ensure_ascii=False, sort_keys=True) if c == "detail" else (it.get(c) or "")
                    for c in cols])
    return Response(buf.getvalue(), media_type="text/csv",
                    headers={"Content-Disposition": f'attachment; filename="aipish-audit-{stamp}.csv"'})


VERIFY_DEDUPE_MINUTES = 5


@router.get("/audit/verify")
def audit_verify(request: Request, db: Session = Depends(get_db)) -> dict:
    """Verify the chain. A successful result is recorded at most once per admin per 5 minutes (the Audit
    page verifies on every load); a failed verification is always recorded."""
    result = verify(db)
    if result["ok"]:
        from datetime import timedelta
        since = datetime.now(timezone.utc) - timedelta(minutes=VERIFY_DEDUPE_MINUTES)
        recent = (db.query(AuditEvent.id).filter(AuditEvent.event_type == "audit_verified",
                                                 AuditEvent.outcome == "success",
                                                 AuditEvent.actor_user_id == getattr(request.state, "user_id", None),
                                                 AuditEvent.created_at >= since).first())
        if recent is not None:
            return {**result, "guarantee": GUARANTEE, "recorded": False}
    record_audit(db, "audit_verified", target_type="audit", outcome="success" if result["ok"] else "failure",
                 detail={k: result[k] for k in ("ok", "checked", "first_broken_seq", "reason")})
    db.commit()
    return {**result, "guarantee": GUARANTEE, "recorded": True}


def _last_checkpoint(db: Session) -> dict | None:
    e = (db.query(AuditEvent).filter(AuditEvent.event_type == "audit_checkpoint")
         .order_by(AuditEvent.seq.desc()).first())
    if e is None:
        return None
    names = _usernames(db, {e.actor_user_id})
    return {"seq": (e.detail or {}).get("seq"), "event_hash": (e.detail or {}).get("event_hash"),
            "created_at": _iso(e.created_at), "by": names.get(e.actor_user_id or "", None),
            "checkpoint_event_seq": e.seq}


@router.get("/audit/checkpoint")
def audit_checkpoint_latest(db: Session = Depends(get_db)) -> dict:
    return {"latest": _last_checkpoint(db), "guarantee": GUARANTEE,
            "advice": "Record the seq and hash outside this system (ticket, signed e-mail, notebook). "
                      "A later verification against that external copy reveals a re-forged chain."}


@router.post("/audit/checkpoint")
def audit_checkpoint_create(db: Session = Depends(get_db)) -> dict:
    tip = checkpoint(db)
    return {"checkpoint": tip, "latest": _last_checkpoint(db), "guarantee": GUARANTEE}


# ── custody timeline (analyst+) ──────────────────────────────────────────────
_SAFE_DETAIL = {"report_id", "assessment_version", "intel_run_version", "attack_version", "result", "case_number",
                "mode", "masked", "outcome", "providers", "consent", "version", "source", "dry_run",
                "evidence_store_policy", "hold_id"}


@router.get("/analyses/{analysis_id}/custody")
def custody(analysis_id: str, db: Session = Depends(get_db)) -> dict:
    rec = db.get(Analysis, analysis_id)
    if rec is None:
        raise HTTPException(status_code=404, detail={"code": "NOT_FOUND", "message": "Analysis not found."})
    rows = (db.query(AuditEvent).filter(or_(AuditEvent.analysis_id == analysis_id,
                                            AuditEvent.target_id == analysis_id))
            .order_by(AuditEvent.seq.asc().nulls_first(), AuditEvent.created_at.asc()).limit(1000).all())
    names = _usernames(db, {r.actor_user_id for r in rows})
    timeline = [{"at": _iso(r.created_at), "action": r.event_type, "actor": names.get(r.actor_user_id or "", None),
                 "outcome": r.outcome, "case_id": r.case_id,
                 "detail": {k: v for k, v in (r.detail or {}).items() if k in _SAFE_DETAIL}} for r in rows]
    held = analysis_id in retention.held_analysis_ids(db)
    return {"analysis_id": analysis_id, "sha256": rec.raw_sha256, "size_bytes": rec.raw_size_bytes,
            "evidence_bytes_stored": rec.evidence_blob is not None, "retention_state": rec.retention_state,
            "redacted_at": _iso(rec.redacted_at), "legal_hold": held, "timeline": timeline,
            "integrity_note": INTEGRITY_NOTE, "audit_guarantee": GUARANTEE}


# ── retention, holds, erasure (admin) ────────────────────────────────────────
class RunBody(BaseModel):
    dry_run: bool = True


class HoldBody(BaseModel):
    target_type: Literal["analysis", "case"]
    target_id: str = Field(min_length=1, max_length=64)
    reason: str = Field(min_length=3, max_length=500)


class ReasonBody(BaseModel):
    reason: str = Field(min_length=3, max_length=500)


def _raise(exc: retention.RetentionError):
    raise HTTPException(status_code=exc.status, detail={"code": exc.code, "message": exc.message})


@router.get("/admin/retention/status")
def retention_status(db: Session = Depends(get_db)) -> dict:
    return retention.status(db)


@router.post("/admin/retention/run")
def retention_run(body: RunBody | None = None, db: Session = Depends(get_db)) -> dict:
    res = retention.run(db, apply=not (body.dry_run if body else True), source="api")
    keep = ("dry_run", "mode", "eligible_analyses", "eligible_evidence_only", "held_skipped", "redacted", "deleted",
            "evidence_purged", "errors", "policy")
    return {k: res[k] for k in keep}


@router.get("/admin/holds")
def list_holds(include_cleared: bool = False, db: Session = Depends(get_db)) -> dict:
    from app.core.models import LegalHold
    q = db.query(LegalHold)
    if not include_cleared:
        q = q.filter(LegalHold.cleared_at.is_(None))
    return {"items": [retention.hold_dict(h) for h in q.order_by(LegalHold.created_at.desc()).limit(500).all()]}


@router.post("/admin/holds", status_code=201)
def create_hold(body: HoldBody, request: Request, db: Session = Depends(get_db)) -> dict:
    try:
        return retention.hold_dict(retention.set_hold(db, body.target_type, body.target_id, body.reason,
                                                      current_user(request).id))
    except retention.RetentionError as exc:
        _raise(exc)


@router.post("/admin/holds/{hold_id}/clear")
def clear_hold(hold_id: str, body: ReasonBody, request: Request, db: Session = Depends(get_db)) -> dict:
    try:
        return retention.hold_dict(retention.clear_hold(db, hold_id, body.reason, current_user(request).id))
    except retention.RetentionError as exc:
        _raise(exc)


@router.delete("/admin/analyses/{analysis_id}")
def erase(analysis_id: str, body: ReasonBody, request: Request, db: Session = Depends(get_db)) -> dict:
    try:
        return retention.erase_analysis(db, analysis_id, body.reason, current_user(request).id)
    except retention.RetentionError as exc:
        _raise(exc)
