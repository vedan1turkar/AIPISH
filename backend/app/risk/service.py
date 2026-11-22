"""Persistence and pipeline hooks for the combined risk assessment (P5h).

- Upload-time ML classification (cheap ensemble only), bounded and failure-isolated.
- Append-only risk versions (new version only when the result changes), idempotent backfill.
Nothing here writes to the analysis row, the rule result or an ML/assessment row.
"""
from __future__ import annotations

import concurrent.futures
import hashlib
import json
import logging
from datetime import timezone

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.core.config import env
from app.core.models import (
    Analysis, AssessmentVersion, AttackMapping, Campaign, CampaignMember, MlClassification, RiskAssessment, utcnow,
)
from app.risk.engine import Inputs, compute

logger = logging.getLogger(__name__)
_EXECUTOR = concurrent.futures.ThreadPoolExecutor(max_workers=1, thread_name_prefix="ml-upload")


# ── upload-time ML ──────────────────────────────────────────────────────────

def ml_at_upload_enabled() -> bool:
    return (env("AIPISH_ML_AT_UPLOAD", "1") or "1").strip().lower() not in ("0", "false", "no")


def _timeout() -> float:
    try:
        return max(1.0, float(env("AIPISH_ML_UPLOAD_TIMEOUT_SECONDS", "20") or "20"))
    except ValueError:
        return 20.0


def _classify(raw: bytes) -> dict:
    from app.ml.features import run_rules_offline
    from app.ml.inference import classify_raw
    return classify_raw(raw, run_rules_offline(raw)).to_dict()


def classify_at_upload(db: Session, analysis_id: str, raw: bytes) -> str:
    """Run the cheap ML classification and store its outcome. Never raises; never alters the analysis."""
    if not ml_at_upload_enabled():
        return "disabled"
    try:
        fut = _EXECUTOR.submit(_classify, raw)
        try:
            result = fut.result(timeout=_timeout())
        except concurrent.futures.TimeoutError:
            result = {"status": "error", "reason": f"ML classification exceeded {_timeout():.0f}s at upload"}
        except Exception as exc:  # noqa: BLE001
            result = {"status": "error", "reason": f"ML classification failed: {type(exc).__name__}"}
        db.add(MlClassification(analysis_id=analysis_id, source="upload", status=str(result.get("status")),
                                model_version=result.get("model_version"), result_json=result, created_at=utcnow()))
        db.commit()
        return str(result.get("status"))
    except Exception as exc:  # noqa: BLE001 — isolation is the point
        db.rollback()
        logger.warning("upload-time ML classification could not be stored (%s); analysis unaffected",
                       type(exc).__name__)
        return "error"


# ── inputs ──────────────────────────────────────────────────────────────────

def _aware(dt):
    return dt.replace(tzinfo=timezone.utc) if dt is not None and dt.tzinfo is None else dt


def latest_ml(db: Session, analysis_id: str) -> dict | None:
    """Most recent successful ML result (assessment version or upload classification); otherwise the most
    recent attempt (so its unavailable/error state is shown); None when ML never ran."""
    cands = []
    for r in db.query(AssessmentVersion).filter_by(analysis_id=analysis_id).all():
        if r.ml_json:
            cands.append((_aware(r.created_at), r.version, "assessment", r.id, r.ml_json))
    for r in db.query(MlClassification).filter_by(analysis_id=analysis_id).all():
        cands.append((_aware(r.created_at), 0, "upload_classification", r.id, r.result_json or {"status": r.status}))
    if not cands:
        return None
    cands.sort(key=lambda c: (c[0] or utcnow(), c[1], c[3]))
    ok = [c for c in cands if (c[4] or {}).get("status") == "ok"]
    _, _, kind, sid, ml = (ok or cands)[-1]
    return {"status": ml.get("status"), "label": ml.get("label"), "confidence": ml.get("confidence"),
            "probabilities": ml.get("probabilities") or {}, "model_version": ml.get("model_version"),
            "reason": ml.get("reason"), "source_kind": kind, "source_id": sid}


def _intel(db: Session, analysis_id: str) -> dict | None:
    from app.intel.service import latest_run, run_dict
    row = latest_run(db, analysis_id)
    return run_dict(row) if row else None


def _campaigns(db: Session, analysis_id: str) -> list[dict]:
    rows = (db.query(Campaign).join(CampaignMember, CampaignMember.campaign_id == Campaign.id)
            .filter(CampaignMember.analysis_id == analysis_id, Campaign.status == "candidate")
            .order_by(Campaign.number).all())
    return [{"campaign_id": c.id, "label": c.label, "confidence": c.confidence} for c in rows]


def _attack(db: Session, analysis_id: str) -> dict | None:
    row = (db.query(AttackMapping).filter_by(analysis_id=analysis_id)
           .order_by(AttackMapping.version.desc()).first())
    if row is None:
        return None
    res = row.results_json or {}
    return {"mapping_id": row.id, "version": row.version,
            "techniques": [m.get("technique_id") for m in res.get("mappings") or []],
            "hypotheses": [{"hypothesis": h.get("hypothesis"), "band": h.get("band")}
                           for h in res.get("source_type") or []]}


def build_inputs(db: Session, rec: Analysis) -> Inputs:
    return Inputs(detection=rec.detection_json, ml=latest_ml(db, rec.id), intel_run=_intel(db, rec.id),
                  campaigns=_campaigns(db, rec.id), attack=_attack(db, rec.id))


# ── versions ────────────────────────────────────────────────────────────────

def fingerprint(results: dict) -> str:
    return hashlib.sha256(json.dumps(results, sort_keys=True, default=str).encode()).hexdigest()


def latest(db: Session, analysis_id: str) -> RiskAssessment | None:
    return (db.query(RiskAssessment).filter_by(analysis_id=analysis_id)
            .order_by(RiskAssessment.version.desc()).first())


def get_version(db: Session, analysis_id: str, version: int) -> RiskAssessment | None:
    return db.query(RiskAssessment).filter_by(analysis_id=analysis_id, version=version).first()


def history(db: Session, analysis_id: str) -> list[dict]:
    rows = (db.query(RiskAssessment).filter_by(analysis_id=analysis_id)
            .order_by(RiskAssessment.version.desc()).all())
    return [{"risk_id": r.id, "version": r.version, "source": r.source, "level": r.level,
             "combined_score": r.combined_score, "confidence": r.confidence, "engine_version": r.engine_version,
             "created_at": _aware(r.created_at).isoformat() if r.created_at else None} for r in rows]


def risk_dict(row: RiskAssessment) -> dict:
    return {"risk_id": row.id, "analysis_id": row.analysis_id, "version": row.version, "source": row.source,
            "created_at": _aware(row.created_at).isoformat() if row.created_at else None,
            **(row.results_json or {})}


def compute_and_store(db: Session, rec: Analysis, source: str) -> tuple[RiskAssessment, bool]:
    results = compute(build_inputs(db, rec))
    fp = fingerprint(results)
    cur = latest(db, rec.id)
    if cur is not None and cur.fingerprint == fp:
        return cur, False
    row = RiskAssessment(analysis_id=rec.id, version=(cur.version + 1) if cur else 1, source=source,
                         engine_version=results["engine_version"], config_version=results["config_version"],
                         combined_score=results["combined_score"], level=results["level"],
                         confidence=results["confidence"], fingerprint=fp, results_json=results, created_at=utcnow())
    db.add(row)
    db.flush()
    return row, True


def compute_safely(db: Session, analysis_id: str, source: str, alerts: bool = True) -> str:
    """Pipeline hook. Never raises and never alters the analysis or any other result.
    P5f: then evaluates alerts for the analysis (separately failure-isolated)."""
    try:
        rec = db.get(Analysis, analysis_id)
        if rec is None:
            return "missing"
        compute_and_store(db, rec, source)
        db.commit()
    except Exception as exc:  # noqa: BLE001
        db.rollback()
        logger.warning("combined risk assessment failed for an analysis (%s); analysis unaffected",
                       type(exc).__name__)
        return "error"
    if alerts:
        from app.alerts.service import evaluate_analysis_safely
        evaluate_analysis_safely(db, analysis_id, source)
    return "ok"


def backfill(db: Session, alerts: bool = False) -> dict:
    """Idempotent. P5f: no alerts by default (no alert storms); ``alerts=True`` evaluates each analysis."""
    created = unchanged = 0
    ids = [aid for (aid,) in db.query(Analysis.id).order_by(Analysis.created_at, Analysis.id).all()]
    for aid in ids:
        _row, new = compute_and_store(db, db.get(Analysis, aid), "backfill")
        created += int(new)
        unchanged += int(not new)
    db.commit()
    if alerts:
        from app.alerts.service import evaluate_analysis_safely
        for aid in ids:
            evaluate_analysis_safely(db, aid, "backfill")
    return {"analyses": created + unchanged, "versions_created": created, "unchanged": unchanged,
            "total_versions": db.query(RiskAssessment).count()}


def latest_summaries(db: Session, analysis_ids: list[str] | None = None) -> dict[str, dict]:
    """{analysis_id: {level, combined_score, confidence}} for the latest version of each analysis."""
    sub = db.query(RiskAssessment.analysis_id, func.max(RiskAssessment.version).label("v"))
    if analysis_ids is not None:
        if not analysis_ids:
            return {}
        sub = sub.filter(RiskAssessment.analysis_id.in_(analysis_ids))
    sub = sub.group_by(RiskAssessment.analysis_id).subquery()
    rows = (db.query(RiskAssessment.analysis_id, RiskAssessment.level, RiskAssessment.combined_score,
                     RiskAssessment.confidence)
            .join(sub, (RiskAssessment.analysis_id == sub.c.analysis_id) & (RiskAssessment.version == sub.c.v)).all())
    return {a: {"level": lvl, "combined_score": s, "confidence": c} for a, lvl, s, c in rows}
