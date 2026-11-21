"""Infrastructure geolocation, analytics and system-info endpoints (P5g).

Every route is listed in the central permission map (app/security/permissions.py); none is anonymous.
None of them performs an external lookup.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.core.models import Analysis, Campaign
from app.geo import analytics
from app.geo.service import analysis_geo, campaign_geo

router = APIRouter(tags=["geo"])


def _not_found(message: str) -> HTTPException:
    return HTTPException(status_code=404, detail={"code": "NOT_FOUND", "message": message})


@router.get("/analyses/{analysis_id}/geo")
def get_analysis_geo(analysis_id: str, db: Session = Depends(get_db)) -> dict:
    rec = db.get(Analysis, analysis_id)
    if rec is None:
        raise _not_found("Analysis not found.")
    return analysis_geo(db, rec)


@router.get("/campaigns/{campaign_id}/geo")
def get_campaign_geo(campaign_id: str, db: Session = Depends(get_db)) -> dict:
    camp = db.get(Campaign, campaign_id)
    if camp is None:
        raise _not_found("Campaign not found.")
    return campaign_geo(db, camp)


@router.get("/analytics/summary")
def analytics_summary(days: int = Query(30, ge=1, le=analytics.MAX_DAYS),
                      db: Session = Depends(get_db)) -> dict:
    return analytics.summary(db, days)


@router.get("/system/info")
def system_info(db: Session = Depends(get_db)) -> dict:
    """Version / environment / database info for signed-in users (moved off the anonymous /health)."""
    from app.api.router import APP_VERSION, _db_connected
    from app.core.config import get_settings
    from app.core.db import engine
    from app.core.migrations import current_version
    return {"version": APP_VERSION, "environment": get_settings().env, "database": engine.dialect.name,
            "schema_version": current_version(engine), "db_connected": _db_connected(db)}
