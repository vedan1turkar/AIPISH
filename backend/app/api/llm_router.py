"""LLM forensic-summary endpoints (additive; existing routes unchanged)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from sqlalchemy.orm import Session

from app.api.router import _ok_file, upload_eml
from app.core.db import get_db
from app.core.models import Analysis, AnalysisAssessment, utcnow
from app.llm import service

router = APIRouter(tags=["llm"])


def _analysis_dict(rec: Analysis) -> dict:
    return {c.name: getattr(rec, c.name) for c in Analysis.__table__.columns if c.name != "evidence_blob"}


def _ml_and_shap(raw: bytes | None) -> tuple[dict, dict]:
    if raw is None:
        reason = ("raw message not retained (CASE_EVIDENCE_STORE=hash_only); ML classification and SHAP "
                  "need the original bytes — use POST /api/v1/llm/forensic-summary with the .eml")
        return ({"status": "unavailable", "reason": reason},
                {"status": "unavailable", "reason": reason, "components": {}})
    from app.ml.explain import explain_raw
    from app.ml.features import run_rules_offline
    from app.ml.inference import classify_raw
    try:
        det = run_rules_offline(raw)
        return classify_raw(raw, det).to_dict(), explain_raw(raw, det)
    except Exception as exc:  # ML must never break the summary endpoint
        r = f"ML stage failed: {type(exc).__name__}"
        return {"status": "error", "reason": r}, {"status": "error", "reason": r, "components": {}}


def _store(db: Session, analysis_id: str, source: str, ml: dict, explanation: dict, summary: dict) -> dict:
    """Persist the latest assessment so the dashboard and PDF share one result."""
    row = db.get(AnalysisAssessment, analysis_id) or AnalysisAssessment(analysis_id=analysis_id)
    row.source, row.ml_json, row.explanation_json, row.summary_json = source, ml, explanation, summary
    row.created_at = utcnow()
    db.add(row)
    db.commit()
    return assessment_dict(row)


def assessment_dict(row: AnalysisAssessment) -> dict:
    return {"analysis_id": row.analysis_id, "source": row.source,
            "generated_at": row.created_at.isoformat() if row.created_at else None,
            "ml": row.ml_json, "explanation": row.explanation_json, "forensic_summary": row.summary_json}


@router.get("/analyses/{analysis_id}/assessment")
def get_assessment(analysis_id: str, db: Session = Depends(get_db)) -> dict:
    """Stored ML/SHAP/LLM assessment for an analysis (404 when never generated)."""
    if db.get(Analysis, analysis_id) is None:
        raise HTTPException(status_code=404, detail={"code": "NOT_FOUND", "message": "Analysis not found."})
    row = db.get(AnalysisAssessment, analysis_id)
    if row is None:
        raise HTTPException(status_code=404, detail={
            "code": "ASSESSMENT_NOT_GENERATED",
            "message": "No ML/SHAP/AI assessment has been generated for this analysis."})
    return assessment_dict(row)


@router.get("/llm/status")
def llm_status() -> dict:
    return service.status()


@router.post("/llm/forensic-summary")
def summary_from_upload(file: UploadFile = File(..., alias="file"), db: Session = Depends(get_db)) -> dict:
    """Run the normal analysis pipeline (stored as usual), then ML + SHAP + LLM summary."""
    raw = _ok_file(file)
    file.file.seek(0)
    detail = upload_eml(file, db)
    rec = db.get(Analysis, detail.id)
    ml, explanation = _ml_and_shap(raw)
    summary = service.forensic_summary(_analysis_dict(rec), ml, explanation)
    return _store(db, detail.id, "upload", ml, explanation, summary)


@router.post("/analyses/{analysis_id}/forensic-summary")
def summary_for_analysis(analysis_id: str, db: Session = Depends(get_db)) -> dict:
    rec = db.get(Analysis, analysis_id)
    if rec is None:
        raise HTTPException(status_code=404, detail={"code": "NOT_FOUND", "message": "Analysis not found."})
    prior = db.get(AnalysisAssessment, rec.id)
    if rec.evidence_blob is None and prior and (prior.ml_json or {}).get("status") == "ok":
        # bytes are gone (hash_only) but ML/SHAP were computed on them at upload: reuse, don't degrade
        ml, explanation = prior.ml_json, prior.explanation_json
    else:
        ml, explanation = _ml_and_shap(rec.evidence_blob)
    summary = service.forensic_summary(_analysis_dict(rec), ml, explanation)
    return _store(db, rec.id, "stored_analysis", ml, explanation, summary)
