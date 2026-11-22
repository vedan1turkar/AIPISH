"""Alert inbox endpoints (P5f). Every route is in the central permission map; anonymous requests get 401.
Alerts are raised when an analysis is processed — this system does not monitor mailboxes in real time."""
from __future__ import annotations

from datetime import date, datetime, time, timezone
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.alerts import service
from app.alerts.config import get_alert_config
from app.core.db import get_db
from app.core.models import Alert, AlertEvent, Analysis, User

router = APIRouter(tags=["alerts"])
MAX_PAGE = 100
HONESTY = "Alerts are raised when an analysis is processed; this system does not monitor mailboxes in real time."


def _iso(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    return (dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt).isoformat()


def _names(db: Session, ids: set[str | None]) -> dict[str, str]:
    ids = {i for i in ids if i}
    if not ids:
        return {}
    return {u.id: u.username for u in db.query(User).filter(User.id.in_(ids)).all()}


def alert_dict(a: Alert, names: dict[str, str], redacted: set[str]) -> dict:
    return {
        "id": a.id, "type": a.type, "type_label": service.TYPE_LABEL.get(a.type, a.type), "severity": a.severity,
        "status": a.status, "title": a.title, "analysis_id": a.analysis_id, "campaign_id": a.campaign_id,
        "risk_id": a.risk_id, "summary": a.summary_json or {}, "occurrence_count": a.occurrence_count,
        "created_at": _iso(a.created_at), "updated_at": _iso(a.updated_at), "last_seen_at": _iso(a.last_seen_at),
        "acknowledged_by": names.get(a.acknowledged_by or ""), "acknowledged_at": _iso(a.acknowledged_at),
        "resolved_by": names.get(a.resolved_by or ""), "resolved_at": _iso(a.resolved_at),
        "resolution_note": a.resolution_note, "delivery": a.delivery_json or {}, "version": a.version,
        "analysis_redacted": bool(a.analysis_id and a.analysis_id in redacted),
    }


def _redacted(db: Session, ids: set[str | None]) -> set[str]:
    ids = {i for i in ids if i}
    if not ids:
        return set()
    return {i for (i,) in db.query(Analysis.id).filter(Analysis.id.in_(ids), Analysis.retention_state == "redacted")}


@router.get("/alerts")
def list_alerts(status: Literal["new", "acknowledged", "resolved", "open"] | None = None,
                severity: Literal["low", "medium", "high", "critical"] | None = None,
                type: Literal[service.TYPES] | None = None,  # type: ignore[valid-type]
                analysis_id: str | None = Query(None, max_length=32), campaign_id: str | None = Query(None, max_length=32),
                date_from: date | None = None, date_to: date | None = None,
                page: int = Query(1, ge=1, le=10_000), page_size: int = Query(25, ge=1, le=MAX_PAGE),
                db: Session = Depends(get_db)) -> dict:
    q = db.query(Alert)
    if status == "open":
        q = q.filter(Alert.status.in_(service.ACTIVE))
    elif status:
        q = q.filter(Alert.status == status)
    if severity:
        q = q.filter(Alert.severity == severity)
    if type:
        q = q.filter(Alert.type == type)
    if analysis_id:
        q = q.filter(Alert.analysis_id == analysis_id)
    if campaign_id:
        q = q.filter(Alert.campaign_id == campaign_id)
    if date_from:
        q = q.filter(Alert.created_at >= datetime.combine(date_from, time.min, tzinfo=timezone.utc))
    if date_to:
        q = q.filter(Alert.created_at <= datetime.combine(date_to, time.max, tzinfo=timezone.utc))
    total = q.count()
    rows = q.order_by(Alert.created_at.desc(), Alert.id.desc()).offset((page - 1) * page_size).limit(page_size).all()
    names = _names(db, {r.acknowledged_by for r in rows} | {r.resolved_by for r in rows})
    red = _redacted(db, {r.analysis_id for r in rows})
    return {"items": [alert_dict(r, names, red) for r in rows], "total": total, "page": page,
            "page_size": page_size, "note": HONESTY}


@router.get("/alerts/summary")
def alerts_summary(db: Session = Depends(get_db)) -> dict:
    by_status = {s: n for s, n in db.query(Alert.status, func.count(Alert.id)).group_by(Alert.status).all()}
    open_sev = {s: n for s, n in db.query(Alert.severity, func.count(Alert.id))
                .filter(Alert.status.in_(service.ACTIVE)).group_by(Alert.severity).all()}
    new_sev = {s: n for s, n in db.query(Alert.severity, func.count(Alert.id))
               .filter(Alert.status == "new").group_by(Alert.severity).all()}
    sev = ("critical", "high", "medium", "low")
    return {"by_status": {s: by_status.get(s, 0) for s in ("new", "acknowledged", "resolved")},
            "open_by_severity": {s: open_sev.get(s, 0) for s in sev},
            "new_by_severity": {s: new_sev.get(s, 0) for s in sev},
            "new": by_status.get("new", 0), "open": sum(by_status.get(s, 0) for s in service.ACTIVE),
            "enabled": get_alert_config().enabled, "note": HONESTY}


@router.get("/alerts/{alert_id}")
def get_alert(alert_id: str, db: Session = Depends(get_db)) -> dict:
    a = db.get(Alert, alert_id)
    if a is None:
        raise HTTPException(status_code=404, detail={"code": "NOT_FOUND", "message": "Alert not found."})
    events = (db.query(AlertEvent).filter_by(alert_id=a.id)
              .order_by(AlertEvent.created_at.asc(), AlertEvent.id.asc()).limit(500).all())
    names = _names(db, {a.acknowledged_by, a.resolved_by} | {e.actor_user_id for e in events})
    return {**alert_dict(a, names, _redacted(db, {a.analysis_id})),
            "history": [{"id": e.id, "action": e.action, "actor": names.get(e.actor_user_id or ""),
                         "note": e.note, "from_state": e.from_state, "to_state": e.to_state,
                         "detail": e.detail_json or {}, "at": _iso(e.created_at)} for e in events],
            "note": HONESTY}


class TransitionBody(BaseModel):
    note: str | None = Field(None, max_length=service.NOTE_MAX)
    version: int | None = Field(None, ge=1)


def _transition(action: str, alert_id: str, body: TransitionBody | None, request: Request, db: Session) -> dict:
    body = body or TransitionBody()
    actor = getattr(request.state, "user_id", None)
    try:
        service.transition(db, alert_id, action, actor, body.note, body.version)
    except service.TransitionError as exc:
        raise HTTPException(status_code=exc.status, detail={"code": exc.code, "message": exc.message}) from exc
    return get_alert(alert_id, db)


@router.post("/alerts/{alert_id}/acknowledge")
def acknowledge(alert_id: str, request: Request, body: TransitionBody | None = None, db: Session = Depends(get_db)) -> dict:
    return _transition("acknowledge", alert_id, body, request, db)


@router.post("/alerts/{alert_id}/resolve")
def resolve(alert_id: str, request: Request, body: TransitionBody | None = None, db: Session = Depends(get_db)) -> dict:
    return _transition("resolve", alert_id, body, request, db)


@router.post("/alerts/{alert_id}/reopen")
def reopen(alert_id: str, request: Request, body: TransitionBody | None = None, db: Session = Depends(get_db)) -> dict:
    return _transition("reopen", alert_id, body, request, db)


@router.get("/admin/alerts/config")
def alert_config() -> dict:
    return get_alert_config().public_dict()
