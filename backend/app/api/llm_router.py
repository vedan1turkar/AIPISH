"""LLM forensic-summary endpoints (additive; existing routes unchanged)."""
from __future__ import annotations

import threading
from contextlib import contextmanager

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from sqlalchemy.orm import Session

from app.api.router import _ok_file, upload_eml
from app.core.db import get_db
from app.core.models import Analysis, AssessmentVersion, utcnow
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
    """Append a new assessment version (never overwrites an earlier one)."""
    last = (db.query(AssessmentVersion).filter_by(analysis_id=analysis_id)
            .order_by(AssessmentVersion.version.desc()).first())
    row = AssessmentVersion(analysis_id=analysis_id, version=(last.version + 1) if last else 1, source=source,
                            ml_json=ml, explanation_json=explanation, summary_json=summary, created_at=utcnow())
    db.add(row)
    db.flush()
    from app.cases.service import record_audit
    record_audit(db, "assessment_run", analysis_id=analysis_id, detail={
        "assessment_id": row.id, "version": row.version, "source": source,
        "ml_status": (ml or {}).get("status"), "shap_status": (explanation or {}).get("status"),
        "llm_status": (summary or {}).get("status") or ("ok" if (summary or {}).get("summary") else None)})
    db.commit()
    return assessment_dict(row)


def assessment_dict(row: AssessmentVersion) -> dict:
    return {"analysis_id": row.analysis_id, "assessment_id": row.id, "version": row.version,
            "source": row.source, "generated_at": row.created_at.isoformat() if row.created_at else None,
            "ml": row.ml_json, "explanation": row.explanation_json, "forensic_summary": row.summary_json}


def latest_assessment(db: Session, analysis_id: str) -> AssessmentVersion | None:
    return (db.query(AssessmentVersion).filter_by(analysis_id=analysis_id)
            .order_by(AssessmentVersion.version.desc()).first())


def get_version(db: Session, analysis_id: str, assessment_id: str) -> AssessmentVersion | None:
    row = db.get(AssessmentVersion, assessment_id)
    return row if row is not None and row.analysis_id == analysis_id else None


# One generation per analysis at a time (in-process). Prevents accidental
# duplicate versions from double submits; a retry after completion is allowed.
_running: set[str] = set()
_running_lock = threading.Lock()


@contextmanager
def _exclusive(key: str):
    with _running_lock:
        if key in _running:
            raise HTTPException(status_code=409, detail={
                "code": "ASSESSMENT_IN_PROGRESS",
                "message": "An AI assessment for this analysis is already being generated. Wait for it to finish."})
        _running.add(key)
    try:
        yield
    finally:
        with _running_lock:
            _running.discard(key)


def _not_found() -> HTTPException:
    return HTTPException(status_code=404, detail={"code": "NOT_FOUND", "message": "Analysis not found."})


@router.get("/analyses/{analysis_id}/assessment")
def get_assessment(analysis_id: str, db: Session = Depends(get_db)) -> dict:
    """Latest stored ML/SHAP/LLM assessment (404 when never generated)."""
    if db.get(Analysis, analysis_id) is None:
        raise _not_found()
    row = latest_assessment(db, analysis_id)
    if row is None:
        raise HTTPException(status_code=404, detail={
            "code": "ASSESSMENT_NOT_GENERATED",
            "message": "No ML/SHAP/AI assessment has been generated for this analysis."})
    return assessment_dict(row)


@router.get("/analyses/{analysis_id}/assessments")
def list_assessments(analysis_id: str, db: Session = Depends(get_db)) -> list[dict]:
    """Assessment history, newest first (metadata only)."""
    if db.get(Analysis, analysis_id) is None:
        raise _not_found()
    rows = (db.query(AssessmentVersion).filter_by(analysis_id=analysis_id)
            .order_by(AssessmentVersion.version.desc()).all())
    return [{"assessment_id": r.id, "version": r.version, "source": r.source,
             "generated_at": r.created_at.isoformat() if r.created_at else None,
             "ml_status": (r.ml_json or {}).get("status"), "ml_label": (r.ml_json or {}).get("label"),
             "summary_status": (r.summary_json or {}).get("status")} for r in rows]


@router.get("/analyses/{analysis_id}/assessments/{assessment_id}")
def get_assessment_version(analysis_id: str, assessment_id: str, db: Session = Depends(get_db)) -> dict:
    if db.get(Analysis, analysis_id) is None:
        raise _not_found()
    row = get_version(db, analysis_id, assessment_id)
    if row is None:
        raise HTTPException(status_code=404, detail={"code": "ASSESSMENT_NOT_FOUND",
                                                     "message": "No such assessment for this analysis."})
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
    with _exclusive(detail.id):
        ml, explanation = _ml_and_shap(raw)
        summary = service.forensic_summary(_analysis_dict(rec), ml, explanation)
        return _store(db, detail.id, "upload", ml, explanation, summary)


@router.post("/analyses/{analysis_id}/forensic-summary")
def summary_for_analysis(analysis_id: str, db: Session = Depends(get_db)) -> dict:
    rec = db.get(Analysis, analysis_id)
    if rec is None:
        raise HTTPException(status_code=404, detail={"code": "NOT_FOUND", "message": "Analysis not found."})
    with _exclusive(rec.id):
        prior = (db.query(AssessmentVersion).filter_by(analysis_id=rec.id)
                 .order_by(AssessmentVersion.version.desc()).all())
        reuse = next((v for v in prior if (v.ml_json or {}).get("status") == "ok"), None)
        if rec.evidence_blob is None and reuse is not None:
            # bytes are gone (hash_only) but ML/SHAP were computed on them earlier: reuse, don't degrade
            ml = {**reuse.ml_json, "reused_from_assessment": reuse.id}
            explanation = reuse.explanation_json
        else:
            ml, explanation = _ml_and_shap(rec.evidence_blob)
        summary = service.forensic_summary(_analysis_dict(rec), ml, explanation)
        return _store(db, rec.id, "stored_analysis", ml, explanation, summary)
