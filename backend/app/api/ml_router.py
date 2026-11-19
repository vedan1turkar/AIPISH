"""ML classification endpoints (additive to /api/v1; existing routes unchanged).

The 18-rule engine stays the explainable layer; the ML result is reported
alongside it, never instead of it.
"""
from __future__ import annotations

from fastapi import APIRouter, File, UploadFile

from app.api.router import _ok_file
from app.ml import inference
from app.ml.features import run_rules_offline

router = APIRouter(prefix="/ml", tags=["ml"])


@router.get("/status")
def ml_status() -> dict:
    return inference.status()


@router.post("/classify")
def ml_classify(file: UploadFile = File(..., alias="file")) -> dict:
    raw = _ok_file(file)
    detection = run_rules_offline(raw)
    ml = inference.classify_raw(raw, detection)
    return {
        "ml": ml.to_dict(),
        "rules": {"score": detection.get("score"), "verdict": detection.get("verdict"),
                  "fired": [f["rule_id"] for f in detection.get("findings", [])],
                  "error": detection.get("error")},
        "note": "Rule engine run offline (no live DNS/auth/enrichment). ML probabilities are "
                "model outputs, not ground truth; untrained classes are never predicted.",
    }

