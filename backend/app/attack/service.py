"""Persistence for ATT&CK mappings (P5d): append-only versions, idempotent, failure-isolated."""
from __future__ import annotations

import hashlib
import json
import logging
from datetime import timezone

from sqlalchemy.orm import Session

from app.attack.engine import ENGINE_VERSION, Inputs, compute
from app.attack.catalog import get_catalog
from app.core.models import Analysis, AssessmentVersion, AttackMapping, utcnow

logger = logging.getLogger(__name__)
_ANALYSIS_FIELDS = ("id", "detection_json", "forensics_json", "auth_json", "urls", "attachments",
                    "from_domain", "reply_to_emails", "return_path")


def _analysis_dict(rec: Analysis) -> dict:
    return {k: getattr(rec, k) for k in _ANALYSIS_FIELDS}


def _latest_ml(db: Session, analysis_id: str) -> dict | None:
    rows = (db.query(AssessmentVersion).filter_by(analysis_id=analysis_id)
            .order_by(AssessmentVersion.version.desc()).all())
    for r in rows:
        ml = r.ml_json or {}
        if ml.get("status") == "ok":
            probs = ml.get("probabilities") or {}
            return {"status": "ok", "label": ml.get("label"), "confidence": ml.get("confidence"),
                    "assessment_id": r.id, "_probs": len(probs)}
    return None


def _latest_intel(db: Session, analysis_id: str) -> dict | None:
    from app.intel.service import latest_run, run_dict
    row = latest_run(db, analysis_id)
    return run_dict(row) if row else None


def build_inputs(db: Session, rec: Analysis) -> Inputs:
    ml = _latest_ml(db, rec.id)
    if ml:
        ml.pop("_probs", None)
    return Inputs(analysis=_analysis_dict(rec), intel_run=_latest_intel(db, rec.id), ml=ml)


def fingerprint(results: dict) -> str:
    return hashlib.sha256(json.dumps(results, sort_keys=True, default=str).encode()).hexdigest()


def latest(db: Session, analysis_id: str) -> AttackMapping | None:
    return (db.query(AttackMapping).filter_by(analysis_id=analysis_id)
            .order_by(AttackMapping.version.desc()).first())


def mapping_dict(row: AttackMapping) -> dict:
    created = row.created_at
    if created is not None and created.tzinfo is None:
        created = created.replace(tzinfo=timezone.utc)
    return {"mapping_id": row.id, "analysis_id": row.analysis_id, "version": row.version, "source": row.source,
            "created_at": created.isoformat() if created else None, **(row.results_json or {})}


def compute_and_store(db: Session, rec: Analysis, source: str) -> tuple[AttackMapping, bool]:
    """Append a new version only if results changed. Returns (row, created)."""
    results = compute(build_inputs(db, rec))
    fp = fingerprint(results)
    cur = latest(db, rec.id)
    if cur is not None and cur.fingerprint == fp:
        return cur, False
    row = AttackMapping(analysis_id=rec.id, version=(cur.version + 1) if cur else 1, source=source,
                        mapping_engine_version=ENGINE_VERSION, catalog_version=get_catalog().version,
                        intel_run_id=results["inputs"]["intel_run_id"],
                        ml_assessment_id=results["inputs"]["ml_assessment_id"], fingerprint=fp,
                        results_json=results, created_at=utcnow())
    db.add(row)
    db.flush()
    return row, True


def compute_safely(db: Session, analysis_id: str, source: str) -> str:
    """Pipeline hook. Never raises and never alters the analysis."""
    try:
        rec = db.get(Analysis, analysis_id)
        if rec is None:
            return "missing"
        compute_and_store(db, rec, source)
        db.commit()
        return "ok"
    except Exception as exc:  # noqa: BLE001 — isolation is the point
        db.rollback()
        logger.warning("ATT&CK mapping failed for an analysis (%s); analysis unaffected", type(exc).__name__)
        return "error"


def backfill(db: Session) -> dict:
    created = unchanged = 0
    for (aid,) in db.query(Analysis.id).order_by(Analysis.created_at, Analysis.id).all():
        _row, new = compute_and_store(db, db.get(Analysis, aid), "backfill")
        created += int(new)
        unchanged += int(not new)
    db.commit()
    return {"analyses": created + unchanged, "versions_created": created, "unchanged": unchanged,
            "total_versions": db.query(AttackMapping).count()}
