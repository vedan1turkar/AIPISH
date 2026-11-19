"""LLM forensic-summary endpoints (additive; existing routes unchanged)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from sqlalchemy.orm import Session

from app.api.router import _ok_file, upload_eml
from app.core.db import get_db
from app.core.models import Analysis
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
    return {"analysis_id": detail.id, "ml": ml, "explanation": explanation,
            "forensic_summary": service.forensic_summary(_analysis_dict(rec), ml, explanation)}


@router.post("/analyses/{analysis_id}/forensic-summary")
def summary_for_analysis(analysis_id: str, db: Session = Depends(get_db)) -> dict:
    rec = db.get(Analysis, analysis_id)
    if rec is None:
        raise HTTPException(status_code=404, detail={"code": "NOT_FOUND", "message": "Analysis not found."})
    ml, explanation = _ml_and_shap(rec.evidence_blob)
    return {"analysis_id": rec.id, "ml": ml, "explanation": explanation,
            "forensic_summary": service.forensic_summary(_analysis_dict(rec), ml, explanation)}
