"""Combined risk assessment endpoints (P5h). All routes are in the central permission map; responses pass
through the P5e masking middleware like every other /api/v1 JSON response."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.core.models import Analysis
from app.risk import service

router = APIRouter(tags=["risk"])


def _analysis(db: Session, analysis_id: str) -> Analysis:
    rec = db.get(Analysis, analysis_id)
    if rec is None:
        raise HTTPException(status_code=404, detail={"code": "NOT_FOUND", "message": "Analysis not found."})
    return rec


@router.get("/analyses/{analysis_id}/risk")
def get_risk(analysis_id: str, version: int | None = None, db: Session = Depends(get_db)) -> dict:
    _analysis(db, analysis_id)
    if version is not None:
        row = service.get_version(db, analysis_id, version)
        if row is None:
            raise HTTPException(status_code=404, detail={"code": "RISK_VERSION_NOT_FOUND",
                                                         "message": "No such combined risk version."})
    else:
        row = service.latest(db, analysis_id)
        if row is None:
            raise HTTPException(status_code=404, detail={"code": "RISK_NOT_COMPUTED",
                                                         "message": "No combined risk assessment has been computed yet."})
    return service.risk_dict(row)


@router.get("/analyses/{analysis_id}/risk/history")
def risk_history(analysis_id: str, db: Session = Depends(get_db)) -> list[dict]:
    _analysis(db, analysis_id)
    return service.history(db, analysis_id)


@router.post("/analyses/{analysis_id}/risk/recompute")
def recompute_risk(analysis_id: str, db: Session = Depends(get_db)) -> dict:
    """Recompute from the stored inputs; appends a version only if the result changed. Audited."""
    from app.cases.service import record_audit
    rec = _analysis(db, analysis_id)
    row, created = service.compute_and_store(db, rec, "recompute")
    record_audit(db, "risk_recomputed", analysis_id=rec.id, target_type="analysis", target_id=rec.id,
                 detail={"risk_id": row.id, "version": row.version, "new_version": created, "level": row.level,
                         "combined_score": row.combined_score, "engine_version": row.engine_version})
    db.commit()
    from app.alerts.service import evaluate_analysis_safely       # P5f: isolated; never alters the result
    evaluate_analysis_safely(db, rec.id, "recompute")
    return {**service.risk_dict(row), "new_version": created}
