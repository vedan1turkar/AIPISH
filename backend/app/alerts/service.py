"""Risk-based alert engine (P5f): rules, dedupe, lifecycle and analyst transitions.

Alerts are raised when an analysis is processed (upload, intel run, AI assessment, recompute) and when
candidate campaigns are updated. Nothing here watches a mailbox. Alerts hold system-written titles and
identifiers/labels only; never subject, body, recipients, sender addresses or display names.

Rules and lifecycle are documented in docs/alerts/README.md.
"""
from __future__ import annotations

import logging
from datetime import timedelta, timezone

from sqlalchemy import func, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.alerts.config import CONFIDENCE_RANK, LEVEL_RANK, SEVERITY_RANK, AlertConfig, get_alert_config
from app.core.models import Alert, AlertEvent, Analysis, Campaign, CampaignMember, RiskAssessment, utcnow

logger = logging.getLogger(__name__)

TYPES = ("high_risk_analysis", "hard_evidence_floor", "review_conflict", "new_campaign", "campaign_growth")
TYPE_LABEL = {
    "high_risk_analysis": "High-risk analysis",
    "hard_evidence_floor": "Hard-evidence floor fired",
    "review_conflict": "Rules and ML disagree (review)",
    "new_campaign": "New candidate campaign",
    "campaign_growth": "Candidate campaign grew",
}
ACTIVE = ("new", "acknowledged")
MAX_TRACKED_ANALYSES = 50
NOTE_MAX = 1000


class TransitionError(Exception):
    def __init__(self, code: str, message: str, status: int = 409):
        super().__init__(message)
        self.code, self.message, self.status = code, message, status


def severity_for_level(level: str | None) -> str:
    return {"critical": "critical", "high": "high", "medium": "medium"}.get(level or "", "low")


def _aware(dt):
    return dt.replace(tzinfo=timezone.utc) if dt is not None and dt.tzinfo is None else dt


def _event(db: Session, alert: Alert, action: str, *, actor: str | None = None, note: str | None = None,
           from_state: str | None = None, to_state: str | None = None, detail: dict | None = None) -> None:
    db.add(AlertEvent(alert_id=alert.id, analysis_id=alert.analysis_id, action=action, actor_user_id=actor,
                      note=note, from_state=from_state, to_state=to_state, detail_json=detail, created_at=utcnow()))


def _audit(db: Session, event_type: str, alert: Alert, detail: dict) -> None:
    from app.cases.service import record_audit
    record_audit(db, event_type, analysis_id=alert.analysis_id, target_type="alert", target_id=alert.id,
                 detail={"alert_id": alert.id, "type": alert.type, "severity": alert.severity, **detail})


# ── analysis alerts ────────────────────────────────────────────────────────

def _analysis_summary(rec: Analysis, risk: RiskAssessment) -> dict:
    """Only identifiers, labels and scores (see the model docstring)."""
    res = risk.results_json or {}
    comps = {c.get("name"): c for c in res.get("components") or []}
    ml = comps.get("ml") or {}
    ml_label = (ml.get("value") or {}).get("label") if isinstance(ml.get("value"), dict) else None
    floors = (comps.get("hard_evidence") or {}).get("value") or []
    return {"analysis_id": rec.id, "combined_level": risk.level, "combined_score": risk.combined_score,
            "rule_verdict": rec.detection_verdict, "ml_class": ml_label, "ml_status": ml.get("status"),
            "floors": list(floors), "conflict": res.get("conflict"), "risk_version": risk.version}


def _candidates(cfg: AlertConfig, summary: dict) -> list[tuple[str, str]]:
    level = summary["combined_level"]
    out: list[tuple[str, str]] = []
    if level in LEVEL_RANK and LEVEL_RANK[level] >= LEVEL_RANK[cfg.min_level]:
        out.append(("high_risk_analysis", severity_for_level(level)))
    elif summary["floors"] and cfg.floor_alerts:
        sev = severity_for_level(level)
        out.append(("hard_evidence_floor", sev if SEVERITY_RANK[sev] >= SEVERITY_RANK["medium"] else "medium"))
    if summary["conflict"] and cfg.conflict_alerts:
        out.append(("review_conflict", "low"))
    return out


def _latest_for_key(db: Session, key: str) -> Alert | None:
    return db.query(Alert).filter_by(dedupe_key=key).order_by(Alert.created_at.desc(), Alert.id.desc()).first()


def _create(db: Session, *, key: str, type_: str, severity: str, title: str, summary: dict,
            analysis_id: str | None = None, campaign_id: str | None = None, risk_id: str | None = None,
            source: str) -> Alert | None:
    now = utcnow()
    a = Alert(dedupe_key=key, active_key=key, type=type_, severity=severity, status="new", analysis_id=analysis_id,
              campaign_id=campaign_id, risk_id=risk_id, title=title[:200], summary_json=summary, occurrence_count=1,
              created_at=now, updated_at=now, last_seen_at=now, version=1,
              delivery_json={"email": {"status": "pending"}})
    try:
        with db.begin_nested():
            db.add(a)
            db.flush()
    except IntegrityError:            # a concurrent writer opened the active alert for this key first
        return None
    _event(db, a, "raised", to_state="new", detail={"source": source, "severity": severity})
    _audit(db, "alert_raised", a, {"source": source})
    return a


def _apply(db: Session, cfg: AlertConfig, *, key: str, type_: str, severity: str, title: str, summary: dict,
           analysis_id: str, risk_id: str, source: str, changed: list[Alert]) -> None:
    cur = _latest_for_key(db, key)
    now = utcnow()
    if cur is None:
        a = _create(db, key=key, type_=type_, severity=severity, title=title, summary=summary,
                    analysis_id=analysis_id, risk_id=risk_id, source=source)
        if a is not None:
            changed.append(a)
        return
    rank_new, rank_cur = SEVERITY_RANK[severity], SEVERITY_RANK[cur.severity]
    tracked = list((cur.summary_json or {}).get("analysis_ids") or [cur.analysis_id])
    if cur.status in ACTIVE:
        if analysis_id not in tracked:                      # identical re-upload (same SHA-256): count only
            cur.occurrence_count += 1
            cur.last_seen_at = now
            cur.summary_json = {**(cur.summary_json or {}),
                                "analysis_ids": (tracked + [analysis_id])[-MAX_TRACKED_ANALYSES:],
                                "latest_analysis_id": analysis_id}
            _event(db, cur, "occurrence", detail={"analysis_id": analysis_id, "occurrence_count": cur.occurrence_count})
        if rank_new > rank_cur:                             # escalate (and reopen if acknowledged)
            frm = cur.status
            cur.severity, cur.risk_id, cur.updated_at, cur.last_seen_at = severity, risk_id, now, now
            cur.summary_json = {**(cur.summary_json or {}), **summary,
                                "analysis_ids": (cur.summary_json or {}).get("analysis_ids") or tracked}
            cur.version += 1
            if frm == "acknowledged":
                cur.status, cur.acknowledged_by, cur.acknowledged_at = "new", None, None
            _event(db, cur, "escalated", from_state=frm, to_state=cur.status,
                   detail={"source": source, "severity": severity, "previous_severity": severity_from(rank_cur)})
            _audit(db, "alert_escalated", cur, {"source": source, "from_state": frm, "to_state": cur.status})
            changed.append(cur)
        elif rank_new < rank_cur and analysis_id in tracked:  # never auto-resolve on a lower level
            now_level = summary["combined_level"]
            if (cur.summary_json or {}).get("combined_level_now") != now_level:
                cur.summary_json = {**(cur.summary_json or {}), "combined_level_now": now_level}
                _event(db, cur, "level_lowered", detail={"source": source, "severity_now": severity,
                                                         "note": "level lowered; alert left open (no auto-resolve)"})
        return
    # resolved: only a level above the level at resolution opens a new alert
    resolved_rank = SEVERITY_RANK.get(cur.level_at_resolution or cur.severity, rank_cur)
    if rank_new > resolved_rank:
        a = _create(db, key=key, type_=type_, severity=severity, title=title, summary=summary,
                    analysis_id=analysis_id, risk_id=risk_id, source=source)
        if a is not None:
            _event(db, a, "supersedes", detail={"previous_alert_id": cur.id})
            changed.append(a)


def severity_from(rank: int) -> str:
    return next(k for k, v in SEVERITY_RANK.items() if v == rank)


def evaluate_analysis(db: Session, analysis_id: str, source: str, cfg: AlertConfig | None = None) -> list[Alert]:
    cfg = cfg or get_alert_config()
    if not cfg.enabled:
        return []
    rec = db.get(Analysis, analysis_id)
    if rec is None:
        return []
    risk = (db.query(RiskAssessment).filter_by(analysis_id=analysis_id)
            .order_by(RiskAssessment.version.desc()).first())
    if risk is None or risk.combined_score is None:
        return []
    summary = _analysis_summary(rec, risk)
    changed: list[Alert] = []
    for type_, severity in _candidates(cfg, summary):
        title = f"{TYPE_LABEL[type_]}: combined {risk.level} {risk.combined_score}/100 (analysis {rec.id[:8]})"
        _apply(db, cfg, key=f"{type_}:{rec.raw_sha256}", type_=type_, severity=severity, title=title,
               summary={**summary, "analysis_ids": [rec.id], "latest_analysis_id": rec.id},
               analysis_id=rec.id, risk_id=risk.id, source=source, changed=changed)
    return changed


# ── campaign alerts ────────────────────────────────────────────────────────

def evaluate_campaigns(db: Session, source: str, cfg: AlertConfig | None = None) -> list[Alert]:
    cfg = cfg or get_alert_config()
    if not cfg.enabled:
        return []
    min_rank = CONFIDENCE_RANK[cfg.campaign_min_confidence]
    counts = dict(db.query(CampaignMember.campaign_id, func.count(CampaignMember.analysis_id))
                  .group_by(CampaignMember.campaign_id).all())
    camps = (db.query(Campaign).filter_by(status="candidate").order_by(Campaign.number)
             .limit(cfg.max_campaigns_per_pass).all())
    changed: list[Alert] = []
    now = utcnow()
    for c in camps:
        if CONFIDENCE_RANK.get(c.confidence, 0) < min_rank:
            continue
        members = int(counts.get(c.id, 0))
        summary = {"campaign_id": c.id, "campaign_label": c.label, "campaign_confidence": c.confidence,
                   "member_count": members}
        new_key = f"new_campaign:{c.id}"
        first = _latest_for_key(db, new_key)
        if first is None:
            a = _create(db, key=new_key, type_="new_campaign", severity="high" if c.confidence == "high" else "medium",
                        title=f"{TYPE_LABEL['new_campaign']}: {c.label} ({c.confidence}, {members} members)",
                        summary=summary, campaign_id=c.id, source=source)
            if a is not None:
                changed.append(a)
            continue
        grow_key = f"campaign_growth:{c.id}"
        grow = _latest_for_key(db, grow_key)
        baseline = int(((grow or first).summary_json or {}).get("member_count") or 0)
        if members - baseline < cfg.growth_min_new_members:
            continue
        last = _aware((grow or first).updated_at) or now
        if now - last < timedelta(minutes=cfg.growth_debounce_minutes):
            continue                                        # debounced: picked up by a later pass
        if grow is not None and grow.status in ACTIVE:
            grow.occurrence_count += 1
            grow.last_seen_at = grow.updated_at = now
            grow.summary_json = {**summary, "previous_member_count": baseline}
            grow.title = f"{TYPE_LABEL['campaign_growth']}: {c.label} ({members} members)"[:200]
            _event(db, grow, "occurrence", detail={"member_count": members, "previous_member_count": baseline})
        else:
            a = _create(db, key=grow_key, type_="campaign_growth", severity="medium",
                        title=f"{TYPE_LABEL['campaign_growth']}: {c.label} ({members} members)",
                        summary={**summary, "previous_member_count": baseline}, campaign_id=c.id, source=source)
            if a is not None:
                changed.append(a)
    return changed


# ── failure-isolated pipeline hooks ────────────────────────────────────────

def _record_engine_error(db: Session, where: str, exc: Exception) -> None:
    logger.warning("alert evaluation failed (%s: %s); the analysis is unaffected", where, type(exc).__name__)
    try:
        from app.cases.service import record_audit
        record_audit(db, "alert_engine_error", target_type="alert", outcome="failure",
                     detail={"where": where, "error": type(exc).__name__})
        db.commit()
    except Exception:  # noqa: BLE001
        db.rollback()


def _notify(alerts: list[Alert]) -> None:
    if not alerts:
        return
    from app.alerts.notify import dispatch
    for a in alerts:
        dispatch(a.id, f"{a.status}:{a.severity}:{a.version}")


def evaluate_analysis_safely(db: Session, analysis_id: str, source: str) -> str:
    """Never raises and never alters the analysis, its rule result, ML output or risk result."""
    try:
        changed = evaluate_analysis(db, analysis_id, source)
        db.commit()
        _notify(changed)
        return "ok"
    except Exception as exc:  # noqa: BLE001 — isolation is the point
        db.rollback()
        _record_engine_error(db, f"analysis:{source}", exc)
        return "error"


def evaluate_campaigns_safely(db: Session, source: str) -> str:
    try:
        changed = evaluate_campaigns(db, source)
        db.commit()
        _notify(changed)
        return "ok"
    except Exception as exc:  # noqa: BLE001
        db.rollback()
        _record_engine_error(db, f"campaigns:{source}", exc)
        return "error"


# ── analyst transitions (concurrency-safe) ─────────────────────────────────

AUDIT_EVENT = {"acknowledge": "alert_acknowledged", "resolve": "alert_resolved", "reopen": "alert_reopened"}
ALLOWED = {"acknowledge": (("new",), "acknowledged"), "resolve": (("new", "acknowledged"), "resolved"),
           "reopen": (("acknowledged", "resolved"), "new")}


def transition(db: Session, alert_id: str, action: str, actor_id: str | None, note: str | None,
               expected_version: int | None = None) -> Alert:
    a = db.get(Alert, alert_id)
    if a is None:
        raise TransitionError("NOT_FOUND", "Alert not found.", 404)
    sources, target = ALLOWED[action]
    if a.status not in sources:
        raise TransitionError("INVALID_TRANSITION", f"Cannot {action} an alert that is {a.status}.")
    if action == "resolve":
        note = (note or "").strip()
        if not note:
            raise TransitionError("NOTE_REQUIRED", "A resolution note is required.", 400)
        if len(note) > NOTE_MAX:
            raise TransitionError("NOTE_TOO_LONG", f"The note is limited to {NOTE_MAX} characters.", 400)
    elif note is not None and len(note) > NOTE_MAX:
        raise TransitionError("NOTE_TOO_LONG", f"The note is limited to {NOTE_MAX} characters.", 400)
    version = expected_version if expected_version is not None else a.version
    now = utcnow()
    values: dict = {"status": target, "updated_at": now, "version": a.version + 1}
    if action == "acknowledge":
        values.update(acknowledged_by=actor_id, acknowledged_at=now)
    elif action == "resolve":
        values.update(resolved_by=actor_id, resolved_at=now, resolution_note=note, active_key=None,
                      level_at_resolution=a.severity)
    else:
        values.update(active_key=a.dedupe_key, resolved_by=None, resolved_at=None, acknowledged_by=None,
                      acknowledged_at=None, level_at_resolution=None)
    frm = a.status
    try:
        with db.begin_nested():
            res = db.execute(update(Alert).where(Alert.id == alert_id, Alert.version == version,
                                                 Alert.status.in_(sources)).values(**values)
                             .execution_options(synchronize_session=False))
    except IntegrityError as exc:
        raise TransitionError("ACTIVE_ALERT_EXISTS",
                              "Another open alert already exists for the same subject; it cannot be reopened.") from exc
    if res.rowcount != 1:
        db.rollback()
        raise TransitionError("CONFLICT", "The alert was changed by someone else. Reload and try again.")
    db.expire(a)
    _event(db, a, action, actor=actor_id, note=note, from_state=frm, to_state=target)
    _audit(db, AUDIT_EVENT[action], a, {"from_state": frm, "to_state": target, "note_length": len(note or "")})
    db.commit()
    if action == "reopen":
        _notify([a])
    return a
