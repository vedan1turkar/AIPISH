"""Investigation-case + forensic-report endpoints."""
from __future__ import annotations

import hashlib
import os

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from fastapi.responses import Response
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.cases.service import (
    CASE_EVIDENCE_STORE,
    CASE_EVIDENCE_STORE_KEY,
    add_analysis_to_case,
    case_to_dict,
    create_investigation_from_analysis,
    evidence_policy,
    record_audit,
)
from app.core.db import get_db
from app.core.models import Analysis, Case
from app.reports.pdf import build_report_pdf
from datetime import datetime, timezone

router = APIRouter(prefix="/investigations", tags=["investigations"])


def _get_case_or_404(db: Session, case_id: str) -> Case:
    case = db.get(Case, case_id)
    if case is None:
        raise HTTPException(status_code=404,
                            detail={"code": "NOT_FOUND", "message": "Investigation not found."})
    return case


def _load_block(rec: Analysis, key: str) -> dict:
    return getattr(rec, key, None) or {}


@router.post("/from-analysis/{analysis_id}", status_code=201)
def create_from_analysis(analysis_id: str, db: Session = Depends(get_db)):
    case = create_investigation_from_analysis(db, analysis_id)
    if case is None:
        raise HTTPException(status_code=404,
                            detail={"code": "NOT_FOUND", "message": "Analysis not found."})
    return case_to_dict(db, case)


@router.get("")
def list_investigations(db: Session = Depends(get_db)):
    cases = db.query(Case).order_by(Case.created_at.desc()).limit(100).all()
    return [case_to_dict(db, c) for c in cases]


class AddAnalysisRequest(BaseModel):
    analysis_id: str = Field(..., min_length=1, max_length=32)


def _member_ids(db: Session, case_id: str) -> list[str]:
    from app.core.models import CaseAnalysisLink
    rows = (db.query(CaseAnalysisLink).filter(CaseAnalysisLink.case_id == case_id)
            .order_by(CaseAnalysisLink.added_at, CaseAnalysisLink.analysis_id).all())
    return [r.analysis_id for r in rows]


@router.get("/{case_id}/analyses")
def case_analyses(case_id: str, db: Session = Depends(get_db)):
    """Member analyses (summary only, never bodies) with their candidate-campaign badges."""
    from app.correlation.views import analysis_brief, campaigns_for
    _get_case_or_404(db, case_id)
    return [{"analysis": analysis_brief(db.get(Analysis, a)), "campaigns": campaigns_for(db, a)}
            for a in _member_ids(db, case_id) if db.get(Analysis, a) is not None]


@router.post("/{case_id}/analyses", status_code=201)
def add_case_analysis(case_id: str, body: AddAnalysisRequest, db: Session = Depends(get_db)):
    from app.core.models import CaseAnalysisLink
    case = _get_case_or_404(db, case_id)
    if db.get(Analysis, body.analysis_id) is None:
        raise HTTPException(status_code=404, detail={"code": "NOT_FOUND", "message": "Analysis not found."})
    if body.analysis_id in _member_ids(db, case.id):
        raise HTTPException(status_code=409, detail={"code": "ALREADY_MEMBER",
                                                     "message": "That analysis is already in this investigation."})
    db.add(CaseAnalysisLink(case_id=case.id, analysis_id=body.analysis_id))
    record_audit(db, "case_analysis_added", analysis_id=body.analysis_id, case_id=case.id,
                 detail={"case_number": case.case_number})
    db.commit()
    return case_to_dict(db, case)


@router.delete("/{case_id}/analyses/{analysis_id}")
def remove_case_analysis(case_id: str, analysis_id: str, db: Session = Depends(get_db)):
    from app.core.models import CaseAnalysisLink
    case = _get_case_or_404(db, case_id)
    link = (db.query(CaseAnalysisLink)
            .filter(CaseAnalysisLink.case_id == case.id, CaseAnalysisLink.analysis_id == analysis_id).one_or_none())
    if link is None:
        raise HTTPException(status_code=404, detail={"code": "NOT_A_MEMBER",
                                                     "message": "Analysis is not part of this investigation."})
    db.delete(link)
    record_audit(db, "case_analysis_removed", analysis_id=analysis_id, case_id=case.id,
                 detail={"case_number": case.case_number})
    db.commit()
    return case_to_dict(db, case)


@router.get("/{case_id}/indicators")
def case_indicators(case_id: str, db: Session = Depends(get_db)):
    """Indicators aggregated across the case's analyses, with generic/stop-list flags."""
    from app.correlation import DISCLAIMER
    from app.correlation.views import case_indicators as aggregate
    _get_case_or_404(db, case_id)
    return {"case_id": case_id, "indicators": aggregate(db, _member_ids(db, case_id)), "disclaimer": DISCLAIMER}


@router.get("/{case_id}")
def get_investigation(case_id: str, db: Session = Depends(get_db)):
    case = _get_case_or_404(db, case_id)
    return case_to_dict(db, case)


def _verify_integrity(db: Session, rec: Analysis) -> dict:
    policy = evidence_policy()
    if rec.evidence_blob is None:
        record_audit(db, "integrity_verified", analysis_id=rec.id,
                     detail={"result": "unavailable", "reason": "hash-only policy"})
        return {
            "result": "unavailable",
            "detail": "raw evidence bytes not retained (hash-only policy); "
                      "recorded SHA-256 remains the reference",
            "policy": policy,
        }
    actual = hashlib.sha256(rec.evidence_blob).hexdigest()
    matches = actual == rec.raw_sha256
    record_audit(db, "integrity_verified", analysis_id=rec.id,
                 detail={"result": "match" if matches else "mismatch"})
    return {
        "result": "match" if matches else "mismatch",
        "detail": "" if matches else (
            f"recomputed {actual} != recorded {rec.raw_sha256}"
        ),
        "policy": policy,
    }


@router.post("/{case_id}/evidence-integrity/{analysis_id}")
def evidence_integrity(case_id: str, analysis_id: str, db: Session = Depends(get_db)):
    case = _get_case_or_404(db, case_id)
    rec = db.get(Analysis, analysis_id)
    if rec is None:
        raise HTTPException(status_code=404,
                            detail={"code": "NOT_FOUND", "message": "Analysis not found."})
    # membership check
    from app.core.models import CaseAnalysisLink
    link = (db.query(CaseAnalysisLink)
              .filter(CaseAnalysisLink.case_id == case.id,
                      CaseAnalysisLink.analysis_id == analysis_id)
              .one_or_none())
    if link is None:
        raise HTTPException(status_code=400,
                            detail={"code": "NOT_A_MEMBER", "message": "Analysis is not part of this investigation."})
    result = _verify_integrity(db, rec)
    db.commit()  # audit event persisted
    return {"analysis_id": analysis_id, "sha256_recorded": rec.raw_sha256, **result}


def _assessment_for(db: Session, analysis_id: str, assessment_id: str | None) -> dict | None:
    """A stored assessment version (never re-run here): the requested one, else the latest."""
    from app.api.llm_router import assessment_dict, get_version, latest_assessment
    if assessment_id:
        row = get_version(db, analysis_id, assessment_id)
        if row is None:
            raise HTTPException(status_code=404, detail={"code": "ASSESSMENT_NOT_FOUND",
                                                         "message": "No such assessment for this analysis."})
        return assessment_dict(row)
    row = latest_assessment(db, analysis_id)
    return assessment_dict(row) if row else None


def _intel_for(db: Session, analysis_id: str, run_id: str | None) -> dict | None:
    """A stored threat-intel run (never re-run here): the requested one, else the latest."""
    from app.intel.service import get_run, latest_run, run_dict
    if run_id:
        row = get_run(db, analysis_id, run_id)
        if row is None:
            raise HTTPException(status_code=404, detail={"code": "INTEL_RUN_NOT_FOUND",
                                                         "message": "No such threat-intel run for this analysis."})
        return run_dict(row)
    row = latest_run(db, analysis_id)
    return run_dict(row) if row else None


def _attack_for(db: Session, analysis_id: str, attack_id: str | None) -> dict | None:
    """A stored ATT&CK mapping version (never recomputed here): the pinned one, else the latest."""
    from app.attack.service import latest, mapping_dict
    from app.core.models import AttackMapping
    if attack_id:
        row = db.get(AttackMapping, attack_id)
        if row is None or row.analysis_id != analysis_id:
            raise HTTPException(status_code=404, detail={"code": "ATTACK_VERSION_NOT_FOUND",
                                                         "message": "No such ATT&CK mapping for this analysis."})
        return mapping_dict(row)
    row = latest(db, analysis_id)
    return mapping_dict(row) if row else None


def _risk_for(db: Session, analysis_id: str, risk_id: str | None) -> dict | None:
    """A stored combined-risk version (P5h; never recomputed here): the pinned one, else the latest."""
    from app.core.models import RiskAssessment
    from app.risk.service import latest, risk_dict
    if risk_id:
        row = db.get(RiskAssessment, risk_id)
        if row is None or row.analysis_id != analysis_id:
            raise HTTPException(status_code=404, detail={"code": "RISK_VERSION_NOT_FOUND",
                                                         "message": "No such combined risk version for this analysis."})
        return risk_dict(row)
    row = latest(db, analysis_id)
    return risk_dict(row) if row else None


def _correlation_snapshot(db: Session, analysis_id: str) -> dict | None:
    """Correlation as of report generation; failures never block the PDF."""
    try:
        from app.correlation.views import correlation_for
        return {**correlation_for(db, analysis_id), "snapshot_at": datetime.now(timezone.utc).isoformat()}
    except Exception:  # noqa: BLE001
        return None


def report_inputs(db: Session, rec: Analysis, case: Case | None, request: Request | None,
                  assessment_id: str | None = None, intel_run_id: str | None = None, attack_id: str | None = None,
                  risk_id: str | None = None) -> dict:
    """The exact inputs of a forensic report (shared by the PDF and the P5k-lite HTML report so both print the
    same, identically masked and version-pinned data). Stored versions only; nothing is re-run here."""
    integrity = _verify_integrity(db, rec)
    report_id = f"RPT-{rec.id[:8]}-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
    # P5e: the same masking serializer as the API for roles without pii:view ("MASKED VIEW"); pinned
    # versions are identical for every role. Redacted analyses print the retention notice.
    from app.privacy.masking import mask_payload, role_sees_pii
    masked = not role_sees_pii(getattr(getattr(request, "state", None), "user_role", None)) if request else False
    view_notes = []
    if masked:
        view_notes.append("MASKED VIEW: personal data (addresses, display names, body) masked for the requesting role.")
    if rec.retention_state == "redacted":
        view_notes.append("Content redacted per retention policy: personal content was removed; hashes, "
                          "indicators, findings and scores are retained.")
    _m = mask_payload if masked else (lambda x: x)
    assessment = _assessment_for(db, rec.id, assessment_id)
    intel = _intel_for(db, rec.id, intel_run_id)
    corr = _correlation_snapshot(db, rec.id)
    attack = _attack_for(db, rec.id, attack_id)
    risk = _risk_for(db, rec.id, risk_id)
    kwargs = dict(
        view_notes=view_notes,
        case_dict=_m(case_to_dict(db, case)) if case is not None else {"case_number": None, "title": None},
        analysis_row=_m({
            "id": rec.id,
            "sha256": rec.raw_sha256,
            "size_bytes": rec.raw_size_bytes,
            "subject": rec.subject,
            "date": rec.date_header,
            "message_id": rec.message_id,
            "reply_to": [{"email": e} for e in (rec.reply_to_emails or [])],
            "return_path": rec.return_path,
            "to": [{"email": e} for e in (rec.to_emails or [])],
            "cc": [{"email": e} for e in (rec.cc_emails or [])],
            "sender": {
                "display_name": rec.from_display_name,
                "email": rec.from_email,
                "domain": rec.from_domain,
            },
            "parser_crosscheck": rec.parser_crosscheck,      # P5k-lite (counts/field names only)
            "retention_state": rec.retention_state,
        }),
        detection=_m(rec.detection_json or {}),
        forensics=_m(rec.forensics_json or {}),
        auth=_m(rec.auth_json or {}),
        enrichment=_m(rec.enrichment_json or {}),
        integrity=integrity,
        report_id=report_id,
        assessment=_m(assessment),
        intel=_m(intel),
        correlation=_m(corr),
        attack=_m(attack),
        risk=_m(risk),
    )
    return {"kwargs": kwargs, "masked": masked, "mask": _m, "assessment": assessment, "intel": intel,
            "correlation": corr, "attack": attack, "risk": risk}


def report_audit_detail(inputs: dict, size_bytes: int, report_format: str, redacted: bool) -> dict:
    a, i, c, t, r = (inputs["assessment"], inputs["intel"], inputs["correlation"], inputs["attack"], inputs["risk"])
    return {"report_id": inputs["kwargs"]["report_id"], "format": report_format, "size_bytes": size_bytes,
            "assessment_id": (a or {}).get("assessment_id"), "assessment_version": (a or {}).get("version"),
            "intel_run_id": (i or {}).get("run_id"), "intel_run_version": (i or {}).get("version"),
            "campaigns": [{"id": x["id"], "version": x["version"]} for x in (c or {}).get("campaigns", [])],
            "attack_mapping_id": (t or {}).get("mapping_id"), "attack_mapping_version": (t or {}).get("version"),
            "risk_id": (r or {}).get("risk_id"), "risk_version": (r or {}).get("version"),
            "masked": inputs["masked"], "redacted": redacted}


@router.get("/{case_id}/report/{analysis_id}")
def report_pdf(
    case_id: str,
    analysis_id: str,
    x_evidence_key: str | None = Header(default=None, convert_underscores=True),
    assessment_id: str | None = None,
    intel_run_id: str | None = None,
    attack_id: str | None = None,
    risk_id: str | None = None,
    request: Request = None,
    db: Session = Depends(get_db),
):
    """Download the forensic PDF for one analysis inside an investigation.

    `assessment_id` pins the AI-assessment version printed in section 8; without
    it the latest version at generation time is used and identified in the PDF."""
    case = _get_case_or_404(db, case_id)
    rec = db.get(Analysis, analysis_id)
    if rec is None:
        raise HTTPException(status_code=404,
                            detail={"code": "NOT_FOUND", "message": "Analysis not found."})

    # serving raw/derived evidence may be key-restricted when raw retention is on
    if CASE_EVIDENCE_STORE == "raw" and CASE_EVIDENCE_STORE_KEY:
        if x_evidence_key != CASE_EVIDENCE_STORE_KEY:
            raise HTTPException(status_code=401,
                                detail={"code": "EVIDENCE_KEY_REQUIRED",
                                        "message": "Configured policy requires a valid X-Evidence-Key header."})

    inputs = report_inputs(db, rec, case, request, assessment_id, intel_run_id, attack_id, risk_id)
    pdf = build_report_pdf(**inputs["kwargs"])
    report_id, masked = inputs["kwargs"]["report_id"], inputs["masked"]
    assessment, intel, corr, attack, risk = (inputs["assessment"], inputs["intel"], inputs["correlation"],
                                             inputs["attack"], inputs["risk"])
    record_audit(db, "report_generated", analysis_id=rec.id, case_id=case.id,
                 detail={"report_id": report_id, "size_bytes": len(pdf),
                         "assessment_id": (assessment or {}).get("assessment_id"),
                         "assessment_version": (assessment or {}).get("version"),
                         "intel_run_id": (intel or {}).get("run_id"),
                         "intel_run_version": (intel or {}).get("version"),
                         # P5c: the exact campaign versions printed in section 7B
                         "campaigns": [{"id": c["id"], "version": c["version"]}
                                       for c in (corr or {}).get("campaigns", [])],
                         # P5d: the exact ATT&CK mapping version printed in section 7C
                         "attack_mapping_id": (attack or {}).get("mapping_id"),
                         "attack_mapping_version": (attack or {}).get("version"),
                         # P5h: the exact combined-risk version printed in section 8A
                         "risk_id": (risk or {}).get("risk_id"), "risk_version": (risk or {}).get("version"),
                         "masked": masked, "redacted": rec.retention_state == "redacted"})
    db.commit()
    filename = f"forensic-report-{report_id}.pdf"
    return Response(
        content=pdf,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
