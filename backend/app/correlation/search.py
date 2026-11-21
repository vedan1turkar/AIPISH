"""Search across analyses, cases, entities and campaigns (P5c).

Indexed SQL only (LIKE / prefix on indexed columns), always through bound parameters; LIKE
wildcards in user input are escaped. Results are capped and paginated. Email bodies are never
searched or returned.
"""
from __future__ import annotations

from datetime import date, datetime, time, timezone

from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.core.models import Analysis, Campaign, Case, Entity, Observation
from app.correlation.views import analysis_brief, campaign_brief

KINDS = ("analysis", "case", "entity", "campaign")
MAX_LIMIT = 50


def _like(q: str) -> str:
    esc = q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{esc}%"


def _prefix(q: str) -> str:
    esc = q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"{esc}%"


def _bounds(d_from: date | None, d_to: date | None) -> tuple[datetime | None, datetime | None]:
    lo = datetime.combine(d_from, time.min, tzinfo=timezone.utc) if d_from else None
    hi = datetime.combine(d_to, time.max, tzinfo=timezone.utc) if d_to else None
    return lo, hi


def search(db: Session, q: str = "", kind: str = "all", *, verdict: str | None = None,
           entity_type: str | None = None, date_from: date | None = None, date_to: date | None = None,
           limit: int = 20, offset: int = 0) -> dict:
    q = (q or "").strip()[:200]
    ql = q.lower()
    limit = max(1, min(int(limit), MAX_LIMIT))
    offset = max(0, min(int(offset), 10_000))
    lo, hi = _bounds(date_from, date_to)
    kinds = KINDS if kind == "all" else (kind,)
    out: dict = {"query": q, "type": kind, "limit": limit, "offset": offset, "results": {}}

    if "analysis" in kinds:
        qa = db.query(Analysis)
        if q:
            ent_ids = db.query(Entity.id).filter(Entity.normalized_value.ilike(_like(ql), escape="\\"))
            via_entity = db.query(Observation.analysis_id).filter(Observation.entity_id.in_(ent_ids))
            qa = qa.filter(or_(
                Analysis.id.ilike(_prefix(ql), escape="\\"),
                Analysis.raw_sha256.ilike(_prefix(ql), escape="\\"),
                Analysis.from_domain.ilike(_like(ql), escape="\\"),
                Analysis.from_email.ilike(_like(ql), escape="\\"),
                Analysis.subject.ilike(_like(q), escape="\\"),
                Analysis.detection_verdict.ilike(_like(ql), escape="\\"),
                Analysis.id.in_(via_entity),
            ))
        if verdict:
            qa = qa.filter(Analysis.detection_verdict == verdict)
        if lo:
            qa = qa.filter(Analysis.created_at >= lo)
        if hi:
            qa = qa.filter(Analysis.created_at <= hi)
        total = qa.count()
        rows = qa.order_by(Analysis.created_at.desc(), Analysis.id).offset(offset).limit(limit).all()
        out["results"]["analysis"] = {"total": total, "items": [analysis_brief(r) for r in rows]}

    if "case" in kinds:
        qc = db.query(Case)
        if q:
            qc = qc.filter(or_(Case.id.ilike(_prefix(ql), escape="\\"),
                               Case.case_number.ilike(_like(q.upper()), escape="\\"),
                               Case.title.ilike(_like(q), escape="\\")))
        if lo:
            qc = qc.filter(Case.created_at >= lo)
        if hi:
            qc = qc.filter(Case.created_at <= hi)
        total = qc.count()
        rows = qc.order_by(Case.created_at.desc(), Case.id).offset(offset).limit(limit).all()
        out["results"]["case"] = {"total": total, "items": [
            {"id": c.id, "case_number": c.case_number, "title": c.title, "status": c.status,
             "created_at": c.created_at.isoformat() if c.created_at else None} for c in rows]}

    if "entity" in kinds:
        qe = db.query(Entity)
        if q:
            qe = qe.filter(Entity.normalized_value.ilike(_like(ql), escape="\\"))
        if entity_type:
            qe = qe.filter(Entity.type == entity_type)
        total = qe.count()
        rows = qe.order_by(Entity.type, Entity.normalized_value).offset(offset).limit(limit).all()
        items = []
        for e in rows:
            df = db.query(Observation.analysis_id).filter_by(entity_id=e.id).distinct().count()
            items.append({"id": e.id, "type": e.type, "value": e.normalized_value, "analyses": df})
        out["results"]["entity"] = {"total": total, "items": items}

    if "campaign" in kinds:
        qk = db.query(Campaign).filter(Campaign.status == "candidate")
        if q:
            qk = qk.filter(or_(Campaign.id.ilike(_prefix(ql), escape="\\"),
                               Campaign.label.ilike(_like(q), escape="\\")))
        total = qk.count()
        rows = qk.order_by(Campaign.number).offset(offset).limit(limit).all()
        out["results"]["campaign"] = {"total": total, "items": [campaign_brief(db, c) for c in rows]}
    return out
