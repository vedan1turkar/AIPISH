"""Case service: investigation creation, membership, audit events.

Sanitization guarantees at storage time:
- subject is length-capped and control-char-stripped,
- email addresses are kept (needed for triage) but display names truncated,
- body text and attachment contents are NEVER copied into the case record.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy.orm import Session

from app.core.config import env
from app.core.models import Analysis, AuditEvent, Case, CaseAnalysisLink, new_id

_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
CASE_EVIDENCE_STORE = env("CASE_EVIDENCE_STORE", "hash_only") or "hash_only"   # hash_only | raw
CASE_EVIDENCE_STORE_KEY = (env("CASE_EVIDENCE_STORE_KEY", "") or "").strip()
CASE_EVIDENCE_RETENTION_DAYS = int(env("CASE_EVIDENCE_RETENTION_DAYS", "90") or "90")


def _clean(text: str | None, cap: int = 200) -> str | None:
    if text is None:
        return None
    return _CONTROL.sub(" ", text).strip()[:cap]


def next_case_number(db: Session) -> str:
    year = datetime.now(timezone.utc).year
    count = db.query(Case).filter(Case.case_number.like(f"CASE-{year}-%")).count()
    return f"CASE-{year}-{count + 1:04d}"


def create_investigation_from_analysis(db: Session, analysis_id: str) -> Case | None:
    rec = db.get(Analysis, analysis_id)
    if rec is None:
        return None
    case = Case(
        id=new_id(),
        case_number=next_case_number(db),
        title=_clean(f"Review of {_clean(rec.subject, 80)}", 120),
        status="open",
    )
    db.add(case)
    db.flush()
    db.add(CaseAnalysisLink(case_id=case.id, analysis_id=analysis_id))
    record_audit(db, "analysis_created", analysis_id=analysis_id, case_id=case.id,
                 detail={"case_number": case.case_number,
                         "evidence_store_policy": CASE_EVIDENCE_STORE})
    db.commit()
    return case


def add_analysis_to_case(db: Session, case_id: str, analysis_id: str) -> Case | None:
    case = db.get(Case, case_id)
    rec = db.get(Analysis, analysis_id)
    if case is None or rec is None:
        return None
    existing = (db.query(CaseAnalysisLink)
                  .filter(CaseAnalysisLink.case_id == case_id,
                          CaseAnalysisLink.analysis_id == analysis_id)
                  .one_or_none())
    if existing is None:
        db.add(CaseAnalysisLink(case_id=case_id, analysis_id=analysis_id))
    db.commit()
    return case


def record_audit(db: Session, event_type: str, analysis_id: str | None = None,
                 case_id: str | None = None, detail: dict | None = None,
                 actor_user_id: str | None = None) -> None:
    """Append an audit row. The actor defaults to the authenticated user of the
    current request (P5b); never pass passwords or tokens in ``detail``."""
    if actor_user_id is None:
        from app.security.context import current_actor_id
        actor_user_id = current_actor_id()
    db.add(AuditEvent(
        id=new_id(),
        event_type=event_type,
        analysis_id=analysis_id,
        case_id=case_id,
        detail=detail or {},
        actor_user_id=actor_user_id,
    ))


def evidence_policy() -> dict:
    return {
        "store_mode": CASE_EVIDENCE_STORE,
        "key_required": bool(CASE_EVIDENCE_STORE_KEY) and CASE_EVIDENCE_STORE == "raw",
        "retention_days": CASE_EVIDENCE_RETENTION_DAYS,
        "note": "Default is hash-only: raw message bytes are not stored. "
                "An integrity check recomputes over preserved bytes only when "
                "raw evidence was explicitly retained; hash-only cases report "
                "'not possible' honestly.",
    }


def case_to_dict(db: Session, case: Case) -> dict:
    links = (db.query(CaseAnalysisLink)
               .filter(CaseAnalysisLink.case_id == case.id)
               .all())
    analyses = []
    for link in links:
        rec = db.get(Analysis, link.analysis_id)
        if rec is None:
            continue
        analyses.append({
            "analysis_id": rec.id,
            "sha256": rec.raw_sha256,
            "size_bytes": rec.raw_size_bytes,
            "subject": _clean(rec.subject, 120),
            "from_domain": rec.from_domain,
            "threat_score": rec.detection_score,
            "verdict": rec.detection_verdict,
            "authentication_status": {
                p: (rec.auth_json or {}).get(p, {}).get("status", "unknown")
                for p in ("spf", "dkim", "dmarc")
            },
            "relay_summary": {
                "hops": (rec.forensics_json or {}).get("trusted_boundary_index", 0) if False else len(((rec.forensics_json or {}).get("relay_chain") or [])),
                "earliest_candidate_ip": (rec.forensics_json or {}).get("earliest_candidate_ip"),
                "verified_originating_ip": (rec.forensics_json or {}).get("verified_originating_ip"),
            },
            "enrichment": {
                "providers_run": len(set(r["provider"] for r in (rec.enrichment_json or {}).get("results", []))),
                "degraded": (rec.enrichment_json or {}).get("degraded", [])[:3],
            },
            "findings_count": len(((rec.detection_json or {}).get("findings") or [])),
            "added_at": link.added_at.isoformat(),
        })
    return {
        "id": case.id,
        "case_number": case.case_number,
        "title": case.title,
        "status": case.status,
        "created_at": case.created_at.isoformat(),
        "evidence_policy": evidence_policy(),
        "analyses": analyses,
    }
