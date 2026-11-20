"""Threat-intelligence endpoints (P5a). Additive; existing routes unchanged."""
from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.core.models import Analysis
from app.intel.config import PROVIDERS, get_intel_config
from app.intel.service import RunInProgress, exclusive, get_run, latest_run, run_dict, run_threat_intel

router = APIRouter(tags=["threat-intel"])


class ThreatIntelRequest(BaseModel):
    consent: bool = Field(..., description="Explicit per-analysis consent to send bare indicators to providers.")
    providers: list[str] | None = Field(default=None, max_length=len(PROVIDERS))
    source: Literal["upload", "on_demand"] = "on_demand"


@router.get("/intel/status")
def intel_status() -> dict:
    """Per-provider configured/enabled booleans only — never credential values."""
    return get_intel_config().status()


def _analysis_or_404(db: Session, analysis_id: str) -> Analysis:
    rec = db.get(Analysis, analysis_id)
    if rec is None:
        raise HTTPException(status_code=404, detail={"code": "NOT_FOUND", "message": "Analysis not found."})
    return rec


@router.post("/analyses/{analysis_id}/threat-intel", status_code=201)
def run_intel(analysis_id: str, body: ThreatIntelRequest, db: Session = Depends(get_db)) -> dict:
    rec = _analysis_or_404(db, analysis_id)
    if body.providers is not None:
        unknown = sorted(set(body.providers) - set(PROVIDERS))
        if unknown or not body.providers:
            raise HTTPException(status_code=400, detail={
                "code": "UNKNOWN_PROVIDER",
                "message": f"Unknown or empty provider list. Allowed: {', '.join(PROVIDERS)}."})
    try:
        with exclusive(analysis_id):
            result = run_threat_intel(db, rec, consent=body.consent, source=body.source, providers=body.providers)
        # P5d: refresh the ATT&CK/source-type hypotheses with this run. Failure-isolated; the intel
        # result returned below is unchanged.
        from app.attack.service import compute_safely
        compute_safely(db, analysis_id, "intel_run")
        return result
    except RunInProgress:
        raise HTTPException(status_code=409, detail={
            "code": "INTEL_IN_PROGRESS",
            "message": "A threat-intel lookup for this analysis is already running. Wait for it to finish."})


@router.get("/analyses/{analysis_id}/threat-intel")
def get_intel(analysis_id: str, run_id: str | None = None, db: Session = Depends(get_db)) -> dict:
    _analysis_or_404(db, analysis_id)
    row = get_run(db, analysis_id, run_id) if run_id else latest_run(db, analysis_id)
    if row is None:
        raise HTTPException(status_code=404, detail={
            "code": "INTEL_RUN_NOT_FOUND" if run_id else "INTEL_NOT_RUN",
            "message": "No such threat-intel run for this analysis." if run_id
            else "No threat-intel lookup has been run for this analysis."})
    return run_dict(row)
