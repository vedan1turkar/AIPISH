"""Cross-case correlation, campaigns, entity graph and search endpoints (P5c).

Every route is listed in the central permission map (app/security/permissions.py).
"""
from __future__ import annotations

from datetime import date
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.core.models import Analysis, Campaign
from app.correlation import views
from app.correlation.engine import rebuild_all
from app.correlation.search import KINDS, search

router = APIRouter(tags=["correlation"])


def _not_found(code: str, message: str) -> HTTPException:
    return HTTPException(status_code=404, detail={"code": code, "message": message})


@router.get("/analyses/{analysis_id}/correlation")
def analysis_correlation(analysis_id: str, db: Session = Depends(get_db)) -> dict:
    if db.get(Analysis, analysis_id) is None:
        raise _not_found("NOT_FOUND", "Analysis not found.")
    return views.correlation_for(db, analysis_id)


@router.get("/campaigns")
def list_campaigns(status: Literal["candidate", "all"] = "candidate", db: Session = Depends(get_db)) -> dict:
    q = db.query(Campaign)
    if status == "candidate":
        q = q.filter(Campaign.status == "candidate")
    from app.correlation import DISCLAIMER
    return {"items": [views.campaign_brief(db, c) for c in q.order_by(Campaign.number).limit(200).all()],
            "disclaimer": DISCLAIMER}


@router.get("/campaigns/{campaign_id}")
def get_campaign(campaign_id: str, db: Session = Depends(get_db)) -> dict:
    c = db.get(Campaign, campaign_id)
    if c is None:
        raise _not_found("CAMPAIGN_NOT_FOUND", "Campaign not found.")
    return views.campaign_detail(db, c)


@router.get("/graph/entities/{entity_type}/{value}")
def entity_graph(entity_type: str, value: str, db: Session = Depends(get_db)) -> dict:
    out = views.entity_neighbourhood(db, entity_type, value)
    if out is None:
        raise _not_found("ENTITY_NOT_FOUND", "No such entity has been observed.")
    return out


@router.get("/search")
def search_endpoint(
    q: str = Query("", max_length=200),
    type: Literal["all", "analysis", "case", "entity", "campaign"] = "all",
    verdict: str | None = Query(None, max_length=40),
    entity_type: str | None = Query(None, max_length=32),
    date_from: date | None = None,
    date_to: date | None = None,
    limit: int = Query(20, ge=1, le=50),
    offset: int = Query(0, ge=0, le=10_000),
    db: Session = Depends(get_db),
) -> dict:
    assert type == "all" or type in KINDS
    result = search(db, q, type, verdict=verdict, entity_type=entity_type, date_from=date_from,
                    date_to=date_to, limit=limit, offset=offset)
    from app.cases.service import record_audit
    record_audit(db, "search_performed", target_type="search", detail={
        "type": type, "query": (q or "")[:64], "query_truncated": len(q or "") > 64,
        "filters": {k: v for k, v in {"verdict": verdict, "entity_type": entity_type,
                                      "date_from": str(date_from or ""), "date_to": str(date_to or "")}.items() if v},
        "offset": offset})
    db.commit()
    return result


@router.post("/correlation/rebuild")
def rebuild(db: Session = Depends(get_db)) -> dict:
    """Admin: backfill observations for all analyses and recompute campaigns (idempotent)."""
    from app.cases.service import record_audit
    result = rebuild_all(db)
    record_audit(db, "correlation_rebuilt", detail={k: v for k, v in result.items()})
    db.commit()
    from app.alerts.service import evaluate_campaigns_safely      # P5f: campaign alerts (isolated)
    evaluate_campaigns_safely(db, "correlation_rebuild")
    return result
