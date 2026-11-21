"""Retention enforcement, legal holds and erasure (P5e).

Nothing is purged unless explicitly enabled AND applied:
- RETENTION_ANALYSIS_DAYS (0 = disabled), RETENTION_EVIDENCE_DAYS (0 = disabled), RETENTION_MODE
  (redact | delete, default redact), RETENTION_GRACE_DAYS (default 0);
- runs are dry-run unless ``apply=True`` (CLI ``--apply``, API ``dry_run: false``);
- audit events are NEVER purged.

redact: removes personal content (body, subject, sender/recipient addresses, display names, raw bytes,
attachment file names, AI summaries that quote content, display-name correlation entities) and keeps hashes,
IOCs, verdict/scores, findings, correlation observations, ATT&CK mappings, intel results and geo data, so
cases and campaigns stay valid. The analysis is flagged (retention_state="redacted", redacted_at).
delete: removes the analysis and every row that references it (generic: every table with an analysis_id
column except audit_event), cleans orphan correlation entities and recomputes campaigns.
Legal holds (analysis or case) exempt an analysis from retention and from erasure.
Each analysis is processed in its own transaction; every purge writes an audit event (ids/counts only).
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from app.core.config import env
from app.core.models import (
    Analysis, AnalysisAssessment, AssessmentVersion, AuditEvent, Base, CaseAnalysisLink, Entity, LegalHold,
    Observation, utcnow,
)

REDACTED_MARK = "content redacted per retention policy"
MODES = ("redact", "delete")


def _int(name: str, default: int = 0) -> int:
    try:
        return max(0, int(env(name, str(default)) or default))
    except ValueError:
        return default


@dataclass(frozen=True)
class Policy:
    analysis_days: int
    evidence_days: int
    mode: str
    grace_days: int

    @property
    def enabled(self) -> bool:
        return self.analysis_days > 0 or self.evidence_days > 0

    def as_dict(self) -> dict:
        return {"analysis_days": self.analysis_days, "evidence_days": self.evidence_days, "mode": self.mode,
                "grace_days": self.grace_days, "enabled": self.enabled,
                "audit_events_purged": False,
                "note": "Nothing is purged unless a retention period is set and a run is applied. "
                        "Audit events are never purged."}


def get_policy() -> Policy:
    mode = (env("RETENTION_MODE", "redact") or "redact").strip().lower()
    return Policy(analysis_days=_int("RETENTION_ANALYSIS_DAYS"), evidence_days=_int("RETENTION_EVIDENCE_DAYS"),
                  mode=mode if mode in MODES else "redact", grace_days=_int("RETENTION_GRACE_DAYS"))


def _aware(dt: datetime | None) -> datetime | None:
    if dt is not None and dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


# ── legal holds ──────────────────────────────────────────────────────────────
class RetentionError(Exception):
    def __init__(self, status: int, code: str, message: str):
        super().__init__(message)
        self.status, self.code, self.message = status, code, message


def active_holds(db: Session) -> list[LegalHold]:
    return db.query(LegalHold).filter(LegalHold.cleared_at.is_(None)).order_by(LegalHold.created_at.desc()).all()


def held_analysis_ids(db: Session) -> set[str]:
    held: set[str] = set()
    case_ids: set[str] = set()
    for h in active_holds(db):
        (held if h.target_type == "analysis" else case_ids).add(h.target_id)
    if case_ids:
        held |= {link.analysis_id for link in
                 db.query(CaseAnalysisLink).filter(CaseAnalysisLink.case_id.in_(sorted(case_ids))).all()}
    return held


def set_hold(db: Session, target_type: str, target_id: str, reason: str, actor_id: str | None) -> LegalHold:
    from app.cases.service import record_audit
    from app.core.models import Case
    reason = (reason or "").strip()
    if target_type not in ("analysis", "case"):
        raise RetentionError(400, "INVALID_TARGET", "Legal holds apply to an analysis or a case.")
    if len(reason) < 3:
        raise RetentionError(400, "REASON_REQUIRED", "A reason is required to set a legal hold.")
    model = Analysis if target_type == "analysis" else Case
    if db.get(model, target_id) is None:
        raise RetentionError(404, "NOT_FOUND", f"No such {target_type}.")
    existing = (db.query(LegalHold).filter_by(target_type=target_type, target_id=target_id)
                .filter(LegalHold.cleared_at.is_(None)).first())
    if existing is not None:
        raise RetentionError(409, "ALREADY_HELD", f"This {target_type} already has an active legal hold.")
    hold = LegalHold(target_type=target_type, target_id=target_id, reason=reason[:500], created_by=actor_id)
    db.add(hold)
    db.flush()
    record_audit(db, "legal_hold_set", analysis_id=target_id if target_type == "analysis" else None,
                 case_id=target_id if target_type == "case" else None, target_type=target_type, target_id=target_id,
                 detail={"hold_id": hold.id, "reason_length": len(reason)})
    db.commit()
    return hold


def clear_hold(db: Session, hold_id: str, reason: str, actor_id: str | None) -> LegalHold:
    from app.cases.service import record_audit
    reason = (reason or "").strip()
    if len(reason) < 3:
        raise RetentionError(400, "REASON_REQUIRED", "A reason is required to clear a legal hold.")
    hold = db.get(LegalHold, hold_id)
    if hold is None or hold.cleared_at is not None:
        raise RetentionError(404, "NOT_FOUND", "No active legal hold with that id.")
    hold.cleared_at, hold.cleared_by, hold.clear_reason = utcnow(), actor_id, reason[:500]
    record_audit(db, "legal_hold_cleared", analysis_id=hold.target_id if hold.target_type == "analysis" else None,
                 case_id=hold.target_id if hold.target_type == "case" else None, target_type=hold.target_type,
                 target_id=hold.target_id, detail={"hold_id": hold.id, "reason_length": len(reason)})
    db.commit()
    return hold


def hold_dict(h: LegalHold) -> dict:
    return {"id": h.id, "target_type": h.target_type, "target_id": h.target_id, "reason": h.reason,
            "created_by": h.created_by, "created_at": (_aware(h.created_at) or utcnow()).isoformat(),
            "cleared_at": _aware(h.cleared_at).isoformat() if h.cleared_at else None,
            "clear_reason": h.clear_reason, "active": h.cleared_at is None}


# ── redact / delete ──────────────────────────────────────────────────────────
def _mask_json(value):
    from app.audit.sanitize import mask_email
    if isinstance(value, dict):
        return {k: _mask_json(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_mask_json(v) for v in value]
    return mask_email(value) if isinstance(value, str) else value


def redact_analysis(db: Session, rec: Analysis) -> dict:
    """Remove personal content in place (one transaction). Returns counts."""
    from app.correlation.engine import record_observations, recompute_campaigns
    rec.subject = None
    rec.from_display_name = None
    rec.from_email = None                          # from_domain is kept (IOC)
    rec.to_emails, rec.cc_emails, rec.reply_to_emails = None, None, None
    rec.return_path = None
    rec.body_text = None
    rec.evidence_blob = None
    rec.attachments = [{**a, "filename": "[redacted]"} if isinstance(a, dict) and a.get("filename") else a
                       for a in (rec.attachments or [])]
    rec.detection_json = _mask_json(rec.detection_json)
    rec.forensics_json = _mask_json(rec.forensics_json)
    rec.auth_json = _mask_json(rec.auth_json)
    rec.retention_state, rec.redacted_at = "redacted", utcnow()
    summaries = 0
    for model in (AssessmentVersion, AnalysisAssessment):
        for row in db.query(model).filter(model.analysis_id == rec.id).all():
            if row.summary_json is not None:
                row.summary_json = {"redacted": True, "note": REDACTED_MARK}
                summaries += 1
    db.flush()
    record_observations(db, rec)                   # re-extract: drops display-name entities
    recompute_campaigns(db)
    return {"assessment_summaries_redacted": summaries}


def dependent_models() -> list:
    """Every mapped table with an analysis_id column, except the (never purged) audit log."""
    out = []
    for mapper in Base.registry.mappers:
        cls = mapper.class_
        if cls is AuditEvent or cls is Analysis:
            continue
        if "analysis_id" in cls.__table__.columns:
            out.append(cls)
    return out


def delete_analysis(db: Session, rec: Analysis) -> dict:
    """Delete the analysis and every dependent row; clean orphan entities; recompute campaigns."""
    from app.correlation.engine import recompute_campaigns
    counts: dict[str, int] = {}
    touched = {o.entity_id for o in db.query(Observation).filter_by(analysis_id=rec.id).all()}
    for model in dependent_models():
        n = db.query(model).filter(model.analysis_id == rec.id).delete(synchronize_session=False)
        if n:
            counts[model.__tablename__] = n
    db.delete(rec)
    db.flush()
    if touched:
        live = {r.entity_id for r in db.query(Observation.entity_id).filter(Observation.entity_id.in_(sorted(touched)))}
        orphan = sorted(touched - live)
        if orphan:
            counts["corr_entity"] = db.query(Entity).filter(Entity.id.in_(orphan)).delete(synchronize_session=False)
    recompute_campaigns(db)
    return counts


def erase_analysis(db: Session, analysis_id: str, reason: str, actor_id: str | None) -> dict:
    """Erasure request: delete one analysis now (refused while held). Audited with ids/counts only."""
    from app.cases.service import record_audit
    reason = (reason or "").strip()
    if len(reason) < 3:
        raise RetentionError(400, "REASON_REQUIRED", "A reason is required for an erasure.")
    rec = db.get(Analysis, analysis_id)
    if rec is None:
        raise RetentionError(404, "NOT_FOUND", "Analysis not found.")
    if analysis_id in held_analysis_ids(db):
        record_audit(db, "analysis_erasure_refused", analysis_id=analysis_id, outcome="denied",
                     detail={"reason": "legal_hold"})
        db.commit()
        raise RetentionError(409, "LEGAL_HOLD", "This analysis is under legal hold and cannot be erased.")
    sha = rec.raw_sha256
    counts = delete_analysis(db, rec)
    record_audit(db, "analysis_erased", analysis_id=analysis_id,
                 detail={"sha256": sha, "dependents_removed": counts, "reason_length": len(reason)})
    db.commit()
    return {"analysis_id": analysis_id, "deleted": True, "dependents_removed": counts}


# ── runs ─────────────────────────────────────────────────────────────────────
def eligibility(db: Session, policy: Policy | None = None, now: datetime | None = None) -> dict:
    policy = policy or get_policy()
    now = now or utcnow()
    held = held_analysis_ids(db)
    analyses, evidence, skipped = [], [], []
    if policy.analysis_days:
        cutoff = now - timedelta(days=policy.analysis_days + policy.grace_days)
        for rec in db.query(Analysis).filter(Analysis.created_at < cutoff).order_by(Analysis.created_at).all():
            if policy.mode == "redact" and rec.retention_state == "redacted":
                continue
            (skipped if rec.id in held else analyses).append(rec.id)
    if policy.evidence_days:
        cutoff = now - timedelta(days=policy.evidence_days + policy.grace_days)
        for rec in (db.query(Analysis).filter(Analysis.created_at < cutoff, Analysis.evidence_blob.isnot(None))
                    .order_by(Analysis.created_at).all()):
            if rec.id in analyses:
                continue
            if rec.id in held:
                if rec.id not in skipped:
                    skipped.append(rec.id)
            else:
                evidence.append(rec.id)
    return {"analyses": analyses, "evidence_only": evidence, "held_skipped": skipped}


def run(db: Session, apply: bool = False, source: str = "cli") -> dict:
    from app.cases.service import record_audit
    policy = get_policy()
    el = eligibility(db, policy)
    result = {"dry_run": not apply, "policy": policy.as_dict(), "mode": policy.mode,
              "eligible_analyses": el["analyses"], "eligible_evidence_only": el["evidence_only"],
              "held_skipped": el["held_skipped"], "redacted": [], "deleted": [], "evidence_purged": [],
              "errors": []}
    if not apply or not policy.enabled:
        record_audit(db, "retention_run", target_type="retention", detail={
            "dry_run": True if not apply else False, "enabled": policy.enabled, "mode": policy.mode, "source": source,
            "eligible_analyses": len(el["analyses"]), "eligible_evidence_only": len(el["evidence_only"]),
            "held_skipped": len(el["held_skipped"])})
        db.commit()
        return result
    for aid in el["analyses"]:
        try:
            rec = db.get(Analysis, aid)
            if rec is None:
                continue
            if policy.mode == "delete":
                counts = delete_analysis(db, rec)
                record_audit(db, "retention_purge", analysis_id=aid, detail={"mode": "delete", "counts": counts})
                result["deleted"].append(aid)
            else:
                counts = redact_analysis(db, rec)
                record_audit(db, "retention_purge", analysis_id=aid, detail={"mode": "redact", "counts": counts})
                result["redacted"].append(aid)
            db.commit()
        except Exception as exc:  # noqa: BLE001 — one failure never blocks the rest; reported by id
            db.rollback()
            result["errors"].append({"analysis_id": aid, "error": type(exc).__name__})
    for aid in el["evidence_only"]:
        try:
            rec = db.get(Analysis, aid)
            if rec is None or rec.evidence_blob is None:
                continue
            rec.evidence_blob = None
            rec.evidence_purged_at = utcnow()
            if rec.retention_state is None:
                rec.retention_state = "evidence_purged"
            record_audit(db, "retention_purge", analysis_id=aid, detail={"mode": "evidence_bytes"})
            result["evidence_purged"].append(aid)
            db.commit()
        except Exception as exc:  # noqa: BLE001
            db.rollback()
            result["errors"].append({"analysis_id": aid, "error": type(exc).__name__})
    record_audit(db, "retention_run", target_type="retention", detail={
        "dry_run": False, "mode": policy.mode, "source": source,
        "redacted": result["redacted"], "deleted": result["deleted"], "evidence_purged": result["evidence_purged"],
        "held_skipped": el["held_skipped"], "errors": len(result["errors"])})
    db.commit()
    return result


def status(db: Session) -> dict:
    policy = get_policy()
    el = eligibility(db, policy)
    last = (db.query(AuditEvent).filter(AuditEvent.event_type == "retention_run")
            .order_by(AuditEvent.seq.desc()).first())
    return {"policy": policy.as_dict(), "eligible_analyses": len(el["analyses"]),
            "eligible_evidence_only": len(el["evidence_only"]), "held_skipped": len(el["held_skipped"]),
            "eligible_ids": el["analyses"][:200], "holds": [hold_dict(h) for h in active_holds(db)],
            "redacted_total": db.query(Analysis).filter(Analysis.retention_state == "redacted").count(),
            "last_run": ({"at": (_aware(last.created_at) or utcnow()).isoformat(), "seq": last.seq,
                          "detail": last.detail} if last else None),
            "scheduler": "none built in: run scripts/retention-run.sh from cron or the compose 'retention' profile"}
