"""MITRE ATT&CK mapping + source-type endpoints (P5d). All routes are in the central permission map."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.attack.service import compute_and_store, latest, mapping_dict
from app.core.db import get_db
from app.core.models import Analysis, AttackMapping

router = APIRouter(tags=["attack"])


def _analysis(db: Session, analysis_id: str) -> Analysis:
    rec = db.get(Analysis, analysis_id)
    if rec is None:
        raise HTTPException(status_code=404, detail={"code": "NOT_FOUND", "message": "Analysis not found."})
    return rec


@router.get("/analyses/{analysis_id}/attack")
def get_attack(analysis_id: str, version: int | None = None, db: Session = Depends(get_db)) -> dict:
    _analysis(db, analysis_id)
    if version is not None:
        row = db.query(AttackMapping).filter_by(analysis_id=analysis_id, version=version).one_or_none()
        if row is None:
            raise HTTPException(status_code=404, detail={"code": "ATTACK_VERSION_NOT_FOUND",
                                                         "message": "No such ATT&CK mapping version."})
    else:
        row = latest(db, analysis_id)
        if row is None:
            raise HTTPException(status_code=404, detail={"code": "ATTACK_NOT_COMPUTED",
                                                         "message": "No ATT&CK mapping has been computed yet."})
    return mapping_dict(row)


@router.get("/analyses/{analysis_id}/attack/history")
def attack_history(analysis_id: str, db: Session = Depends(get_db)) -> list[dict]:
    _analysis(db, analysis_id)
    rows = db.query(AttackMapping).filter_by(analysis_id=analysis_id).order_by(AttackMapping.version.desc()).all()
    return [{"mapping_id": r.id, "version": r.version, "source": r.source, "created_at": mapping_dict(r)["created_at"],
             "engine_version": r.mapping_engine_version, "catalog_version": r.catalog_version,
             "intel_run_id": r.intel_run_id, "ml_assessment_id": r.ml_assessment_id,
             "technique_count": len((r.results_json or {}).get("mappings") or [])} for r in rows]


@router.post("/analyses/{analysis_id}/attack/recompute")
def recompute_attack(analysis_id: str, db: Session = Depends(get_db)) -> dict:
    """Recompute with the latest intel run and ML assessment; appends a version only if anything changed."""
    from app.cases.service import record_audit
    rec = _analysis(db, analysis_id)
    row, created = compute_and_store(db, rec, "recompute")
    record_audit(db, "attack_recomputed", analysis_id=rec.id,
                 detail={"mapping_id": row.id, "version": row.version, "new_version": created,
                         "intel_run_id": row.intel_run_id})
    db.commit()
    return {**mapping_dict(row), "new_version": created}
