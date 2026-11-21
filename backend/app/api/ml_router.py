"""ML classification endpoints (additive to /api/v1; existing routes unchanged).

The 18-rule engine stays the explainable layer; the ML result is reported
alongside it, never instead of it.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, File, UploadFile
from sqlalchemy.orm import Session

from app.api.router import _ok_file
from app.core.db import get_db
from app.ml import inference
from app.ml.features import run_rules_offline, run_rules_offline_current

router = APIRouter(prefix="/ml", tags=["ml"])


def _audit_ml(db: Session, endpoint: str, raw: bytes) -> None:
    """P5e: ad-hoc ML/SHAP runs on an uploaded file (not stored) — hash and size only."""
    import hashlib
    from app.cases.service import record_audit
    record_audit(db, "ml_run", target_type="file", target_id=hashlib.sha256(raw).hexdigest()[:64],
                 detail={"endpoint": endpoint, "size_bytes": len(raw)})
    db.commit()


@router.get("/status")
def ml_status() -> dict:
    return inference.status()


@router.post("/classify")
def ml_classify(file: UploadFile = File(..., alias="file"), db: Session = Depends(get_db)) -> dict:
    raw = _ok_file(file)
    _audit_ml(db, "classify", raw)
    detection = run_rules_offline(raw)               # legacy comparison: model features (ML parity)
    shown = run_rules_offline_current(raw)           # fixed comparison: what people see
    ml = inference.classify_raw(raw, detection)
    return {
        "ml": ml.to_dict(),
        "rules": {"score": shown.get("score"), "verdict": shown.get("verdict"),
                  "fired": [f["rule_id"] for f in shown.get("findings", [])],
                  "error": shown.get("error")},
        "note": "Rule engine run offline (no live DNS/auth/enrichment). ML probabilities are "
                "model outputs, not ground truth; untrained classes are never predicted.",
    }


@router.post("/explain")
def ml_explain(file: UploadFile = File(..., alias="file"), db: Session = Depends(get_db)) -> dict:
    """Classification + SHAP feature contributions. Rule evidence is returned unchanged."""
    from app.ml.explain import explain_raw
    raw = _ok_file(file)
    _audit_ml(db, "explain", raw)
    detection = run_rules_offline(raw)               # legacy comparison: model features (ML parity)
    shown = run_rules_offline_current(raw)           # fixed comparison: what people see
    return {
        "ml": inference.classify_raw(raw, detection).to_dict(),
        "explanation": explain_raw(raw, detection),
        "rules": {"score": shown.get("score"), "verdict": shown.get("verdict"),
                  "fired": [f["rule_id"] for f in shown.get("findings", [])],
                  "findings": shown.get("findings", []), "error": shown.get("error")},
    }
