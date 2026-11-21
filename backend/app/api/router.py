"""API routes: health + .eml ingestion."""
from __future__ import annotations

import platform

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.api.schemas import (
    AddressOut,
    AnalysisDetail,
    AnalysisSummary,
    AttachmentOut,
    AuthOut,
    DetectionOut,
    EnrichmentOut,
    ForensicsOut,
    HealthResponse,
    UrlOut,
)
from app.core.config import get_settings
from app.core.db import get_db
from app.auth import run_auth_analysis
from app.core.config import get_settings
from app.core.models import Analysis
from app.cases import service as case_service
from app.detection import run_detection
from app.enrichment import run_enrichment, EnrichmentResult
from app.enrichment.iocs import is_private_ip, is_global_ip
from app.forensics import run_header_forensics
from app.ingestion.parser import parse_eml


def auth_live_enabled() -> bool:
    """Auth DNS checks run live only when the app-level flag allows."""
    env = (get_settings().env or "").lower()
    return env not in ("test", "offline", "demo")


def enrichment_live_enabled() -> bool:
    """Enrichment runs unless explicitly disabled by env; offline in tests."""
    if not _enrich_env_enabled():
        return False
    return True


def _enrich_env_enabled() -> bool:
    env = (get_settings().env or "").lower()
    if env in ("test", "offline", "demo"):
        return False
    from app.core.config import env as _env
    return (_env("ENRICH_ENABLE_ALL", "1") or "1").strip().lower() not in ("0", "false")

router = APIRouter()

APP_VERSION = "0.1.0"


def _db_connected(db: Session) -> bool:
    try:
        db.execute(text("SELECT 1"))
        return True
    except Exception:
        return False


@router.get("/health", response_model=HealthResponse)
def health(db: Session = Depends(get_db)) -> HealthResponse:
    settings = get_settings()
    return HealthResponse(
        status="ok" if _db_connected(db) else "degraded",
        version=APP_VERSION,
        env=settings.env,
        db_connected=_db_connected(db),
    )


@router.get("/health/ready", include_in_schema=True)
def health_ready(db: Session = Depends(get_db)):
    """Readiness (P5i): anonymous, used by container health checks and load balancers.

    Returns only ``{"status": "ok"}`` (200) or ``{"status": "unavailable"}`` (503) — never versions,
    hostnames, paths or database errors.
    """
    from fastapi.responses import JSONResponse
    ok = _db_connected(db)
    if not ok:
        try:
            db.rollback()
        except Exception:
            pass
    return JSONResponse({"status": "ok" if ok else "unavailable"}, status_code=200 if ok else 503)


# ── .eml ingestion ─────────────────────────────────────────────────────────

def _ok_file(upload: UploadFile) -> bytes:
    """Read + validate an uploaded .eml; raises HTTPException with a coded detail."""
    settings = get_settings()
    max_bytes = settings.upload_max_mb * 1024 * 1024

    name = (upload.filename or "").lower()
    if not (name.endswith(".eml") or upload.content_type in ("message/rfc822", "application/octet-stream", "")):
        raise HTTPException(
            status_code=415,
            detail={"code": "UNSUPPORTED_MEDIA_TYPE", "message": "Only .eml (message/rfc822) files are accepted."},
        )

    data = upload.file.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise HTTPException(
            status_code=413,
            detail={"code": "PAYLOAD_TOO_LARGE", "message": f"File exceeds the {settings.upload_max_mb} MB limit."},
        )
    if len(data) == 0:
        raise HTTPException(status_code=400, detail={"code": "EMPTY_FILE", "message": "Empty file — nothing to analyse."})
    return data


def _addr_out(a) -> AddressOut | None:
    if a is None:
        return None
    return AddressOut(display_name=a.display_name, email=a.email, domain=a.domain)


def _url_out(u) -> UrlOut:
    return UrlOut(url=u.url, host=u.host, scheme=u.scheme, in_html=u.in_html, in_text=u.in_text)


def _att_out(a) -> AttachmentOut:
    return AttachmentOut(
        filename=a.filename,
        content_type=a.content_type,
        size_bytes=a.size_bytes,
        sha256=a.sha256,
        is_inline=a.is_inline,
        content_id=a.content_id,
    )


@router.post("/analyses", response_model=AnalysisDetail, status_code=201)
def upload_eml(file: UploadFile = File(..., alias="file"), db: Session = Depends(get_db)) -> AnalysisDetail:
    raw = _ok_file(file)

    parsed = parse_eml(raw)

    # forensics + auth, then enrichment, then detection bridging all evidence
    forensics = run_header_forensics(parsed)
    forensic_public_ips = forensics.candidate_ips
    earliest_ip = forensics.earliest_candidate_ip
    auth = run_auth_analysis(parsed, raw, relay_origin_ip=earliest_ip, live=auth_live_enabled())

    # enrichment runs (offline-safe: entirely mocked in tests):
    enr_result, enr_iocs = run_enrichment(parsed, forensic_ips=forensic_public_ips) if enrichment_live_enabled() else (EnrichmentResult(), [])

    # derive bridged enrichment evidence (only provider-backed facts)
    url_ip_not_global: list[str] = []
    for r in enr_result.results:
        if r.provider == "dns" and r.status == "ok":
            a_records = (r.evidence or {}).get("records", {}).get("A") or []
            if r.ioc_kind in ("ip", "hostname") and not any(is_global_ip(x) for x in a_records):
                url_ip_not_global.append(r.ioc_value)
    domain_no_mx_new: list[str] = []
    for r in enr_result.results:
        if r.provider == "dns" and r.status in ("not_found", "ok") and r.ioc_kind == "domain":
            mx = ((r.evidence or {}).get("records") or {}).get("MX") or []
            if not mx:
                # corroborate with RDAP freshness when available
                rdap_new = False
                for r2 in enr_result.results:
                    if r2.provider == "rdap" and r2.ioc_value == r.ioc_value and r2.status == "ok":
                        created = (r2.evidence or {}).get("creation_date")
                        if created and ("2025" in str(created) or "2026" in str(created)):
                            rdap_new = True
                if rdap_new:
                    # Only fire "no MX AND newly registered" when RDAP actually
                    # corroborates recent registration. A bare DNS not_found is
                    # just absence-of-evidence (reserved domains like
                    # example.* never have MX) — not proof of shortlived fraud
                    # infrastructure.
                    domain_no_mx_new.append(r.ioc_value)

    # conflict detection: verified-fail contradicting a header claim of pass
    conflicts: list[str] = []
    for proto_status, name in ((auth.spf, "spf"), (auth.dkim, "dkim"), (auth.dmarc, "dmarc")):
        claimed_pass = any(v in ("pass",) for v in proto_status.claims)
        if proto_status.status == "verified_fail" and claimed_pass:
            conflicts.append(f"{name}: header claimed pass, locally verified fail")
        if proto_status.status == "verified_pass" and any(v == "fail" for v in proto_status.claims):
            conflicts.append(f"{name}: header claimed fail, locally verified pass")

    # Only findings of medium+ severity bridge into the threat score.
    # Informational ones (e.g. no_received: the transport path cannot be
    # reconstructed) stay visible in the forensics report but add no points —
    # absence of evidence is not evidence of fraud.
    consequential = [i.rule_id for i in forensics.inconsistencies if i.severity in ("medium", "high")]

    detection = run_detection(
        parsed,
        forensic_inconsistencies=consequential,
        auth_verified_fail_protocols=[
            s.protocol for s in (auth.spf, auth.dkim, auth.dmarc) if s.status == "verified_fail"
        ],
        auth_has_conflict=bool(conflicts),
        auth_conflict_detail="; ".join(conflicts),
        auth_alignment=auth.alignment,
        enrichment_url_ip_not_global=url_ip_not_global,
        enrichment_domain_no_mx_and_new=domain_no_mx_new,
    )

    rec = Analysis(
        raw_sha256=parsed.raw_sha256,
        raw_size_bytes=parsed.raw_size_bytes,
        subject=parsed.subject,
        from_display_name=parsed.from_.display_name if parsed.from_ else None,
        from_email=parsed.from_.email if parsed.from_ else None,
        from_domain=parsed.from_.domain if parsed.from_ else None,
        to_emails=[a.email for a in parsed.to],
        cc_emails=[a.email for a in parsed.cc],
        reply_to_emails=[a.email for a in parsed.reply_to],
        return_path=parsed.return_path,
        date_header=parsed.date,
        message_id=parsed.message_id,
        received_count=len(parsed.received),
        authentication_results=parsed.authentication_results,
        dkim_signature_count=len(parsed.dkim_signatures),
        body_text=parsed.body_text,
        body_has_html=parsed.has_html_body,
        urls=[_url_out(u).model_dump() for u in parsed.urls],
        attachments=[_att_out(a).model_dump() for a in parsed.attachments],
        header_counts=parsed.header_counts,
        detection_score=detection.score,
        detection_verdict=detection.verdict,
        detection_json=detection.to_dict(),
        forensics_json=forensics.to_dict(),
        auth_json=auth.to_dict(),
        enrichment_json=enr_result.to_dict(),
        parse_defects=parsed.parse_defects,
        evidence_blob=raw if case_service.CASE_EVIDENCE_STORE == "raw" else None,
    )
    db.add(rec)
    db.commit()

    detail = AnalysisDetail(
        id=rec.id,
        created_at=rec.created_at.isoformat(),
        sha256=rec.raw_sha256,
        size_bytes=rec.raw_size_bytes,
        subject=rec.subject,
        **{"from": _addr_out(parsed.from_)},
        to=[_addr_out(a) for a in parsed.to],
        cc=[_addr_out(a) for a in parsed.cc],
        reply_to=[_addr_out(a) for a in parsed.reply_to],
        return_path=rec.return_path,
        date=rec.date_header,
        message_id=rec.message_id,
        received_count=rec.received_count,
        authentication_results=rec.authentication_results or [],
        dkim_signature_count=rec.dkim_signature_count,
        has_html_body=rec.body_has_html,
        body_text=rec.body_text,
        urls=[UrlOut(**u) for u in (rec.urls or [])],
        attachments=[AttachmentOut(**a) for a in (rec.attachments or [])],
        header_counts=rec.header_counts or {},
        detection=DetectionOut(**detection.to_dict()),
        forensics=ForensicsOut(**(rec.forensics_json or {})),
        authentication=AuthOut(**(rec.auth_json or {})),
        enrichment=EnrichmentOut(**(rec.enrichment_json or {})),
        parse_defects=rec.parse_defects or [],
    )
    # P5c: record observations + update candidate campaigns. Failure-isolated: the analysis is
    # already committed and the response above is built; an error only sets corr_state=error.
    from app.correlation.engine import correlate_safely
    correlate_safely(db, detail.id)
    # P5d: ATT&CK mapping + source-type hypotheses, equally failure-isolated and informational only.
    from app.attack.service import compute_safely as attack_safely
    attack_safely(db, detail.id, "auto")
    return detail


@router.get("/analyses", response_model=list[AnalysisSummary])
def list_analyses(db: Session = Depends(get_db)) -> list[AnalysisSummary]:
    recs = db.query(Analysis).order_by(Analysis.created_at.desc()).limit(100).all()
    return [
        AnalysisSummary(
            id=r.id,
            created_at=r.created_at.isoformat(),
            sha256=r.raw_sha256,
            size_bytes=r.raw_size_bytes,
            subject=r.subject,
            sender=AddressOut(
                display_name=r.from_display_name or "",
                email=r.from_email or "",
                domain=r.from_domain or "",
            )
            if r.from_email
            else None,
            received_count=r.received_count,
            url_count=len(r.urls or []),
            attachment_count=len(r.attachments or []),
            detection_score=r.detection_score,
            detection_verdict=r.detection_verdict,
            has_defects=bool(r.parse_defects),
        )
        for r in recs
    ]


@router.get("/analyses/{analysis_id}", response_model=AnalysisDetail)
def get_analysis(analysis_id: str, db: Session = Depends(get_db)) -> AnalysisDetail:
    rec = db.get(Analysis, analysis_id)
    if rec is None:
        raise HTTPException(status_code=404, detail={"code": "NOT_FOUND", "message": "Analysis not found."})
    return AnalysisDetail(
        id=rec.id,
        created_at=rec.created_at.isoformat(),
        sha256=rec.raw_sha256,
        size_bytes=rec.raw_size_bytes,
        subject=rec.subject,
        **{"from": AddressOut(
            display_name=rec.from_display_name or "",
            email=rec.from_email or "",
            domain=rec.from_domain or "",
        ) if rec.from_email else None},
        to=[AddressOut(email=e) for e in (rec.to_emails or [])],
        cc=[AddressOut(email=e) for e in (rec.cc_emails or [])],
        reply_to=[AddressOut(email=e) for e in (rec.reply_to_emails or [])],
        return_path=rec.return_path,
        date=rec.date_header,
        message_id=rec.message_id,
        received_count=rec.received_count,
        authentication_results=rec.authentication_results or [],
        dkim_signature_count=rec.dkim_signature_count,
        has_html_body=rec.body_has_html,
        body_text=rec.body_text,
        urls=[UrlOut(**u) for u in (rec.urls or [])],
        attachments=[AttachmentOut(**a) for a in (rec.attachments or [])],
        header_counts=rec.header_counts or {},
        detection=DetectionOut(**(rec.detection_json or {})),
        forensics=ForensicsOut(**(rec.forensics_json or {})),
        authentication=AuthOut(**(rec.auth_json or {})),
        enrichment=EnrichmentOut(**(rec.enrichment_json or {})),
        parse_defects=rec.parse_defects or [],
    )
