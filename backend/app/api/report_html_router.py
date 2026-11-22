"""Self-contained HTML forensic report (P5k-lite, R55). Same inputs, masking and version pinning as the PDF
(``case_router.report_inputs``); rendered with Jinja2 (autoescape on). The PDF remains ReportLab."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from fastapi.responses import Response
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.core.models import Analysis, Case, CaseAnalysisLink

router = APIRouter(tags=["reports"])

HTML_CSP = ("default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; font-src 'none'; connect-src 'none'; "
            "script-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")


def _case_for(db: Session, analysis_id: str) -> Case | None:
    link = (db.query(CaseAnalysisLink).filter_by(analysis_id=analysis_id)
            .order_by(CaseAnalysisLink.id).first())
    return db.get(Case, link.case_id) if link else None


def _iocs(rec: Analysis, mask) -> dict:
    urls = [{"host": u.get("host") or "", "scheme": u.get("scheme") or "",
             "where": ", ".join(w for w, on in (("text", u.get("in_text")), ("html", u.get("in_html"))) if on) or "—"}
            for u in (rec.urls or [])[:100]]
    atts = [{"filename": a.get("filename") or "", "content_type": a.get("content_type") or "",
             "size_bytes": a.get("size_bytes"), "sha256": a.get("sha256") or ""} for a in (rec.attachments or [])[:50]]
    return mask({"urls": urls, "attachments": atts, "redacted": rec.retention_state == "redacted"})


def _geo(db: Session, rec: Analysis) -> dict | None:
    try:
        from app.geo.service import analysis_geo
        g = analysis_geo(db, rec)
    except Exception:  # noqa: BLE001 — a geo failure never blocks the report
        return None
    pts = [{"ip": p.get("ip"), "role": p.get("role") or "",
            "place": " / ".join(x for x in (p.get("country"), p.get("region"), p.get("city")) if x) or "—",
            "network": " ".join(str(x) for x in (p.get("asn"), p.get("org")) if x) or "—",
            "source": p.get("source") or "—", "simulated": bool(p.get("simulated")), "stale": bool(p.get("stale"))}
           for p in g.get("points") or []]
    return {"points": pts, "no_location": ", ".join(u.get("ip") for u in g.get("unlocated") or [] if u.get("ip"))}


@router.get("/analyses/{analysis_id}/report.html")
def report_html(
    analysis_id: str,
    request: Request,
    x_evidence_key: str | None = Header(default=None, convert_underscores=True),
    assessment_id: str | None = None,
    intel_run_id: str | None = None,
    attack_id: str | None = None,
    risk_id: str | None = None,
    db: Session = Depends(get_db),
):
    """Download the forensic report as one self-contained HTML file (no scripts, no external resources)."""
    from app.api.case_router import (CASE_EVIDENCE_STORE, CASE_EVIDENCE_STORE_KEY, report_audit_detail,
                                     report_inputs)
    from app.audit import GUARANTEE, INTEGRITY_NOTE
    from app.cases.service import record_audit
    from app.reports.html import render_report_html

    rec = db.get(Analysis, analysis_id)
    if rec is None:
        raise HTTPException(status_code=404, detail={"code": "NOT_FOUND", "message": "Analysis not found."})
    if CASE_EVIDENCE_STORE == "raw" and CASE_EVIDENCE_STORE_KEY and x_evidence_key != CASE_EVIDENCE_STORE_KEY:
        raise HTTPException(status_code=401, detail={"code": "EVIDENCE_KEY_REQUIRED",
                                                     "message": "Configured policy requires a valid X-Evidence-Key header."})
    case = _case_for(db, rec.id)
    inputs = report_inputs(db, rec, case, request, assessment_id, intel_run_id, attack_id, risk_id)
    html = render_report_html(inputs["kwargs"], iocs=_iocs(rec, inputs["mask"]), geo=_geo(db, rec),
                              custody={"guarantee": GUARANTEE, "integrity_note": INTEGRITY_NOTE})
    body = html.encode("utf-8")
    record_audit(db, "report_generated", analysis_id=rec.id, case_id=case.id if case else None,
                 detail=report_audit_detail(inputs, len(body), "html", rec.retention_state == "redacted"))
    db.commit()
    report_id = inputs["kwargs"]["report_id"]
    return Response(content=body, media_type="text/html; charset=utf-8", headers={
        "Content-Disposition": f'attachment; filename="forensic-report-{report_id}.html"',
        "Content-Security-Policy": HTML_CSP,
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
        "Cache-Control": "no-store",
    })
