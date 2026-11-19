"""PDF forensic report builder — ReportLab.

Untrusted email-derived text is XML-escaped before insertion (ReportLab
Platypus parses mini-HTML in Paragraphs; escaping prevents markup injection).
Never invents results: unavailable data renders as "unavailable".
"""
from __future__ import annotations

import html
import io
from datetime import datetime, timezone
from typing import Any

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    HRFlowable,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

styles = getSampleStyleSheet()
H1 = ParagraphStyle("H1x", parent=styles["Title"], fontSize=16, spaceAfter=6)
H2 = ParagraphStyle("H2x", parent=styles["Heading2"], fontSize=12, spaceBefore=10, spaceAfter=4)
BODY = ParagraphStyle("BODYx", parent=styles["BodyText"], fontSize=9, leading=12)
MONO = ParagraphStyle("MONOx", parent=styles["BodyText"], fontName="Courier", fontSize=7.5, leading=9.5)
CAVEAT = ParagraphStyle("CAVx", parent=styles["BodyText"], fontSize=8, textColor=colors.HexColor("#7a5b00"))

VERDICT_COLORS = {
    "minimal": colors.HexColor("#1b7f3b"),
    "suspicious": colors.HexColor("#b7791f"),
    "phishing_fraud_likely": colors.HexColor("#b91c1c"),
}

KNOWN_TAG_WIDTH = 14 * mm


def esc(text: Any) -> str:
    """Escape untrusted text for Paragraph (mini-HTML) insertion."""
    return html.escape(str(text if text is not None else ""))


def _kv_table(rows: list[tuple[str, str]]) -> Table:
    data = [[Paragraph("<b>%s</b>" % esc(k), BODY), Paragraph(v, BODY)] for k, v in rows]
    t = Table(data, colWidths=[45 * mm, 115 * mm])
    t.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#dddddd")),
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f5f5f5")),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
    ]))
    return t


def _finding_row(f: dict) -> list:
    knowledge = f.get("knowledge", "unknown")
    tag = {"fact": "OBSERVED FACT", "heuristic": "HEURISTIC"}.get(knowledge, knowledge.upper())
    return [
        Paragraph("<b>%s</b>" % esc(f.get("rule_id", "?")), MONO),
        Paragraph(esc(f.get("severity", "?")), BODY),
        Paragraph(esc("+" + str(f.get("contribution", 0))), BODY),
        Paragraph("<b>%s</b>" % esc(tag) if knowledge != "fact" else esc(tag), BODY),
        Paragraph(esc(f.get("evidence", "")), MONO),
        Paragraph(esc(f.get("rationale", "")), BODY),
    ]


def build_report_pdf(
    case_dict: dict,
    analysis_row: dict,
    detection: dict,
    forensics: dict,
    auth: dict,
    enrichment: dict,
    integrity: dict,
    report_id: str,
    generated_at: str | None = None,
    assessment: dict | None = None,
) -> bytes:
    """Builds the full PDF. Returns bytes; raises nothing — caller handles."""
    generated_at = generated_at or datetime.now(timezone.utc).isoformat()

    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=14 * mm, rightMargin=14 * mm, topMargin=14 * mm, bottomMargin=16 * mm,
        title="Email Forensic Report",
        subject=f"{case_dict.get('case_number', '')} / {analysis_row.get('sha256', '')[:16]}",
    )
    story: list = []

    # ── 1. Header/headerline ────────────────────────────────────────────────
    story.append(Paragraph("Email Forensic Report", H1))
    story.append(HRFlowable(width="100%", thickness=0.8, color=colors.HexColor("#333")))
    verdict = detection.get("verdict", "unknown")
    score = detection.get("score", 0)
    verdict_color = VERDICT_COLORS.get(verdict, colors.black)
    # reportlab wants full HTML hex, e.g. #b91c1c

    banner_tbl = Table(
        [
            [Paragraph("<b>Report ID</b>", BODY), Paragraph("<b>Generated</b>", BODY),
             Paragraph("<b>Threat Verdict</b>", BODY), Paragraph("<b>Score</b>", BODY)],
            [Paragraph(esc(report_id), MONO), Paragraph(esc(generated_at), BODY),
             Paragraph(f'<font color="#{verdict_color.hexval()[2:]}"><b>{esc(verdict).upper()}</b></font>', BODY),
             Paragraph(f"<b>{score}/100</b>", BODY)],
        ],
        colWidths=[45 * mm, 50 * mm, 45 * mm, 22 * mm],
    )
    banner_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#efefef")),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cccccc")),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(banner_tbl)
    story.append(Spacer(1, 6))

    # ── 2. Evidence & integrity ────────────────────────────────────────────
    story.append(Paragraph("1. Evidence & Integrity", H2))
    integ_status = integrity.get("result", "unavailable")
    integ_rows = [
        ("Evidence SHA-256", esc(analysis_row.get("sha256", "unavailable"))),
        ("Evidence size", esc(f"{analysis_row.get('size_bytes', 'unavailable')} bytes")),
        ("Report generation time", esc(generated_at)),
        ("Integrity re-verification", esc(integ_status)),
        ("Integrity detail", esc(integrity.get("detail", ""))),
    ]
    if integ_status == "match":
        integ_rows.append(("Integrity result", "Preserved bytes matched the recorded SHA-256."))
    elif integ_status == "mismatch":
        integ_rows.append(("Integrity result", "PRESERVED BYTES DID NOT MATCH the recorded hash — investigation of the discrepancy is required."))
    elif integ_status == "unavailable":
        integ_rows.append(("Integrity result",
                           "Raw evidence bytes were not retained (hash-only storage policy). "
                           "Integrity cannot be re-verified without the original bytes; "
                           "the recorded hash remains the reference."))
    story.append(_kv_table(integ_rows))
    story.append(Spacer(1, 4))

    # ── 3. Email metadata ────────────────────────────────────────────────
    story.append(Paragraph("2. Email Metadata", H2))
    sender = analysis_row.get("sender") or {}
    meta_rows = [
        ("From", esc(f"{sender.get('display_name') or 'unavailable'} <{sender.get('email') or 'unavailable'}> "
                     f"(domain: {sender.get('domain') or 'unavailable'})")),
        ("Subject", esc(analysis_row.get("subject", "unavailable"))),
        ("Date header", esc(analysis_row.get("date", "unavailable"))),
        ("Message-ID", esc(analysis_row.get("message_id", "unavailable"))),
        ("Reply-To", esc(", ".join(a["email"] for a in analysis_row.get("reply_to", [])) or "none")),
        ("Return-Path", esc(analysis_row.get("return_path", "unavailable"))),
        ("To", esc(", ".join(a["email"] for a in analysis_row.get("to", [])) or "unavailable")),
        ("Cc", esc(", ".join(a["email"] for a in analysis_row.get("cc", [])) or "none")),
    ]
    story.append(_kv_table(meta_rows))

    # ── 4. Findings table ─────────────────────────────────────────────────
    story.append(Paragraph("3. Findings — Explainable Indicators", H2))
    findings = detection.get("findings") or []
    if findings:
        table_data = [[
            Paragraph("<b>Rule</b>", BODY), Paragraph("<b>Severity</b>", BODY),
            Paragraph("<b>Pts</b>", BODY), Paragraph("<b>Type</b>", BODY),
            Paragraph("<b>Evidence</b>", BODY), Paragraph("<b>Rationale</b>", BODY),
        ]] + [_finding_row(f) for f in findings]
        t = Table(table_data, colWidths=[26 * mm, 16 * mm, 9 * mm, 20 * mm, 55 * mm, 38 * mm])
        t.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cccccc")),
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e8e8e8")),
            ("FONTSIZE", (0, 0), (-1, -1), 7.5),
        ]))
        story.append(t)
    else:
        story.append(Paragraph("No weighted indicators fired on this message.", BODY))
    story.append(Spacer(1, 4))
    story.append(Paragraph(
        "<b>Reading the table:</b> <i>OBSERVED FACT</i> rows are deterministically "
        "provable from the message bytes; <i>HEURISTIC</i> rows are judgment calls "
        "on noisy evidence. Contributions are bounded: no single indicator can dominate.",
        BODY))

    # ── 5. Authentication: claims vs verified ≈──
    story.append(Paragraph("4. Authentication — Claims vs Independently Verified", H2))
    for proto in ("spf", "dkim", "dmarc"):
        p = auth.get(proto, {})
        status = p.get("status", "unavailable")
        claims = p.get("claims") or []
        claim_str = ", ".join(claims) if claims else "none"
        verified_note = {
            "verified_pass": "re-verified locally: PASS",
            "verified_fail": "re-verified locally: FAIL",
            "parsed": "header claim only — NOT verified by this system",
            "unavailable": "check could not run (see detail)",
            "unknown": "no evidence either way",
        }.get(status, status)
        rows = [
            (f"{proto.upper()} status", esc(status) + " — " + esc(verified_note)),
            (f"{proto.upper()} header claims", esc(claim_str)),
        ]
        if p.get("reason"):
            rows.append((f"{proto.upper()} reason", esc(p["reason"])))
        detail = p.get("detail") or {}
        if detail.get("published_policy"):
            rows.append((f"{proto.upper()} published policy", esc(detail["published_policy"])))
        story.append(_kv_table(rows))
    align = auth.get("alignment") or {}
    story.append(_kv_table([
        ("SPF alignment", esc(align.get("spf", "unknown"))),
        ("DKIM alignment", esc(align.get("dkim", "unknown"))),
    ]))

    # ── 6. Header anomalies ────────────────────────────────────────────────
    story.append(Paragraph("5. Header Anomalies", H2))
    incs = forensics.get("inconsistencies") or []
    if incs:
        for i in incs:
            story.append(Paragraph(
                f"<b>{esc(i.get('rule_id'))}</b> ({esc(i.get('severity'))}): "
                f"{esc(i.get('evidence'))}", BODY))
            story.append(Paragraph(f"<i>Why it matters: {esc(i.get('rationale'))}</i>", BODY))
    else:
        story.append(Paragraph("No header-field inconsistencies detected.", BODY))

    # ── 7. Relay chain ─────────────────────────────────────────────────────
    story.append(Paragraph("6. Observed Relay Chain", H2))
    hops = forensics.get("relay_chain") or []
    if hops:
        hop_rows = [[
            Paragraph("<b>#</b>", BODY), Paragraph("<b>From (IP)</b>", BODY),
            Paragraph("<b>To</b>", BODY), Paragraph("<b>Trusted</b>", BODY),
            Paragraph("<b>Conf.</b>", BODY), Paragraph("<b>Notes</b>", BODY),
        ]]
        for h in hops:
            hop_rows.append([
                Paragraph(esc(h.get("index")), BODY),
                Paragraph(esc(str(h.get("from_host") or "?") + " (" + str(h.get("from_ip") or "no IP") + ", "
                              + str(h.get("from_ip_category") or "?") + ")"), MONO),
                Paragraph(esc(h.get("by_host") or "?"), BODY),
                Paragraph("yes" if h.get("trusted") else "NO", BODY),
                Paragraph(esc(str(h.get("confidence"))), BODY),
                Paragraph(esc("; ".join(h.get("confidence_reasons", [])[:2])[:70]), BODY),
            ])
        t = Table(hop_rows, colWidths=[6 * mm, 58 * mm, 40 * mm, 14 * mm, 14 * mm, 32 * mm])
        t.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cccccc")),
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e8e8e8")),
            ("FONTSIZE", (0, 0), (-1, -1), 7),
        ]))
        story.append(t)
        idx = forensics.get("trusted_boundary_index")
        if idx is not None:
            story.append(Paragraph(
                f"Trusted boundary at observed hop {esc(idx)}: hops at/after it are "
                "receiver-side traces; earlier hops may be forged (RFC 5321).", BODY))
    else:
        story.append(Paragraph("No Received headers — no path reconstructable.", BODY))
    story.append(Paragraph(esc(forensics.get("forgery_note", "")), CAVEAT))

    # ── 8. Candidate IP/domain intelligence ────────────────────────────────
    story.append(Paragraph("7. Infrastructure Intelligence", H2))
    story.append(_kv_table([
        ("Earliest candidate IP", esc(forensics.get("earliest_candidate_ip", "unavailable"))),
        ("Verified originating IP", esc(forensics.get("verified_originating_ip", "unavailable"))),
        ("All candidates", esc(", ".join(forensics.get("candidate_ips") or []) or "none")),
        ("Confidence rules", esc(" | ".join(forensics.get("confidence_rules") or []))),
    ]))
    enr = enrichment or {}
    results = enr.get("results") or []
    if results:
        prov_rows = [[Paragraph("<b>Provider</b>", BODY), Paragraph("<b>IOC</b>", BODY),
                      Paragraph("<b>Status</b>", BODY), Paragraph("<b>Latency</b>", BODY),
                      Paragraph("<b>Provenance</b>", BODY)]]
        for r in results[:20]:
            prov_rows.append([
                Paragraph(esc(r.get("provider")), BODY),
                Paragraph(esc(str(r.get("ioc", {}).get("value"))[:40]), MONO),
                Paragraph(esc(r.get("status")), BODY),
                Paragraph(esc(str(r.get("latency_ms")) + " ms"), BODY),
                Paragraph(esc(str(r.get("provenance"))[:70]), BODY),
            ])
        t = Table(prov_rows, colWidths=[22 * mm, 45 * mm, 20 * mm, 18 * mm, 59 * mm])
        t.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cccccc")),
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e8e8e8")),
            ("FONTSIZE", (0, 0), (-1, -1), 7),
        ]))
        story.append(t)
    else:
        story.append(Paragraph("No infrastructure enrichment results available "
                               "(providers skipped or disabled).", BODY))
    if enr.get("degraded"):
        story.append(Paragraph("<b>Degraded providers:</b> " + esc("; ".join(enr["degraded"][:5])), CAVEAT))

    # ── 8. ML, SHAP and AI-assisted interpretation (P4) ──────────────────
    _assessment_section(story, assessment)

    # ── 9. Confidence + limitations ───────────────────────────────────────
    story.append(Paragraph("9. Confidence & Limitations", H2))
    for line in [
        "<b>Attribution and geolocation are investigative indicators, not proof</b> of any "
        "person's identity or physical location; an IP identifies network infrastructure only.",
        "Received headers written before the trusted boundary may be forged; origin claims "
        "carry confidence rather than certainty, and a 'verified origin IP' is the best-evidenced "
        "<i>candidate</i>, not a proven origin.",
        "Header claims (Authentication-Results) are untrusted unless independently re-verified by "
        "this system; statuses reported as parsed / locally verified / failed / unavailable / unknown.",
        "Enrichment provider data is <b>external third-party data</b>; provider skips, outages, and "
        "rate limits are reported rather than guessed around. Missing credentials yield skipped statuses.",
        "This report reflects <b>application-level integrity checks and audit logging</b>, not a "
        "tamper-resistant cryptographic chain of custody. Any immutability claim would require "
        "additional (e.g. hash-chained / WORM) storage not implemented here.",
    ]:
        story.append(Paragraph("• " + line, CAVEAT))
    unknowns = detection.get("unknowns") or []
    if unknowns:
        story.append(Paragraph("<b>Missing/unknown evidence:</b>", BODY))
        for u in unknowns:
            story.append(Paragraph(f"• {esc(u.get('field'))}: {esc(u.get('reason'))}", CAVEAT))

    note = forensics.get("disclaimer", "")
    if note:
        story.append(Spacer(1, 4))
        story.append(Paragraph(esc(note), CAVEAT))

    doc.build(story)
    return buf.getvalue()


# ── ML / SHAP / local-LLM section ─────────────────────────────────────────
AI_STATUS_TEXT = {
    "ok": "completed",
    "unavailable": "UNAVAILABLE — did not run",
    "timeout": "TIMED OUT — no output",
    "invalid_output": "INVALID OUTPUT — rejected, nothing shown",
    "error": "ERROR — did not complete",
    "not_applicable": "NOT APPLICABLE — message outside model scope",
}


def _status_line(label: str, block: dict | None) -> Paragraph:
    status = (block or {}).get("status") or "missing"
    text = AI_STATUS_TEXT.get(status, f"{status.upper()} — not reported")
    reason = (block or {}).get("reason")
    extra = f" — {esc(reason)}" if reason and status != "ok" else ""
    return Paragraph(f"<b>{esc(label)}:</b> {esc(text)}{extra}", BODY)


def _grid(rows: list, widths: list) -> Table:
    t = Table(rows, colWidths=widths, repeatRows=1)
    t.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cccccc")),
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e8e8e8")),
        ("LEFTPADDING", (0, 0), (-1, -1), 3), ("RIGHTPADDING", (0, 0), (-1, -1), 3),
    ]))
    return t


def _num(v: Any, fmt: str = "{:.4f}") -> str:
    return fmt.format(v) if isinstance(v, (int, float)) and not isinstance(v, bool) else "n/a"


def _assessment_section(story: list, a: dict | None) -> None:
    story.append(Paragraph("8. ML Classification, SHAP and AI-Assisted Interpretation", H2))
    story.append(Paragraph(
        "These components are separate from, and do not replace, the 18-rule verdict above. "
        "Each block states whether it actually ran.", CAVEAT))
    if not a:
        story.append(Paragraph("No ML / SHAP / AI assessment has been generated for this analysis; "
                               "none of these components are reported.", BODY))
        return
    story.append(Paragraph(f"Assessment generated {esc(a.get('generated_at') or 'at an unknown time')} "
                           f"(source: {esc(a.get('source') or 'unknown')}).", BODY))

    # 8.1 ML
    ml = a.get("ml") or {}
    story.append(Paragraph("<b>8.1 ML classification</b>", BODY))
    story.append(_status_line("Classifier", ml))
    if ml.get("status") == "ok":
        story.append(_kv_table([
            ("Predicted class", "<b>%s</b>" % esc(ml.get("label"))),
            ("Ensemble score", esc(_num(ml.get("confidence"))) + " (model probability for the predicted "
             "class; uncalibrated, not a certainty)"),
            ("Model version", esc(ml.get("model_version"))),
            ("Never-predicted classes", esc(", ".join(ml.get("untrained_classes") or []) or "none")),
        ]))
        probs = ml.get("probabilities") or {}
        if probs:
            rows = [[Paragraph("<b>Class</b>", BODY), Paragraph("<b>Score</b>", BODY)]]
            rows += [[Paragraph(esc(k), BODY), Paragraph(esc(_num(v)), BODY)] for k, v in probs.items()]
            story.append(_grid(rows, [60 * mm, 30 * mm]))

    # 8.2 SHAP
    ex = a.get("explanation") or {}
    story.append(Spacer(1, 4))
    story.append(Paragraph("<b>8.2 SHAP feature contributions</b>", BODY))
    story.append(_status_line("Explanation", ex))
    comps = ex.get("components") or {}
    if ex.get("status") == "ok" and comps:
        for name, c in comps.items():
            story.append(Paragraph(
                f"Component <b>{esc(name)}</b> ({esc(c.get('explainer'))}, ensemble weight "
                f"{esc(_num(c.get('ensemble_weight'), '{:.2f}'))}) toward class "
                f"<b>{esc(ex.get('explained_label'))}</b>; output space: {esc(c.get('output_space'))}; "
                f"base {esc(_num(c.get('base_value')))} → output {esc(_num(c.get('output_value')))}; "
                f"additivity check {'passed' if c.get('additivity_ok') else 'FAILED'}.", BODY))
            rows = [[Paragraph(h, BODY) for h in ("<b>Feature</b>", "<b>Group</b>", "<b>Value</b>",
                                                   "<b>SHAP</b>", "<b>Direction</b>")]]
            for r in (c.get("top_contributions") or []) + (c.get("aggregated") or []):
                rows.append([Paragraph(esc(r.get("feature")), MONO), Paragraph(esc(r.get("group")), BODY),
                             Paragraph(esc(r.get("value") if r.get("value") is not None
                                           else (r.get("detail") or "")), BODY),
                             Paragraph(esc(_num(r.get("shap_value"), "{:+.4f}")), BODY),
                             Paragraph(esc(r.get("direction") or "aggregate"), BODY)])
            story.append(_grid(rows, [45 * mm, 24 * mm, 50 * mm, 20 * mm, 21 * mm]))
    for ne in ex.get("not_explained") or []:
        story.append(Paragraph(f"Not explained: <b>{esc(ne.get('component'))}</b> — {esc(ne.get('reason'))}",
                               CAVEAT))
    story.append(Paragraph(
        "SHAP covers only the explained component(s) listed above (the XGBoost half of the served "
        "ensemble); it does not explain the DistilRoBERTa component or the ensemble as a whole.", CAVEAT))
    if ex.get("disclaimer"):
        story.append(Paragraph(esc(ex["disclaimer"]), CAVEAT))

    # 8.3 LLM
    fs = a.get("forensic_summary") or {}
    story.append(Spacer(1, 4))
    story.append(Paragraph("<b>8.3 AI-generated forensic interpretation (local LLM)</b>", BODY))
    model = fs.get("model") or {}
    story.append(Paragraph(
        "<b>AI-GENERATED INTERPRETATION.</b> " + esc(fs.get("label") or "Produced by a language model; "
        "may be wrong.") + " It never replaces the rule-engine or ML verdicts.", CAVEAT))
    story.append(_status_line("Summary", fs))
    if model:
        story.append(Paragraph(f"Model: {esc(model.get('provider'))} / {esc(model.get('name'))} "
                               f"(digest {esc(str(model.get('digest') or 'n/a')[:12])}, local: "
                               f"{esc(model.get('local'))})", BODY))
    if fs.get("status") == "ok":
        if fs.get("summary"):
            story.append(Paragraph("<b>Summary:</b> " + esc(fs["summary"]).replace("\n", "<br/>"), BODY))
        else:
            story.append(Paragraph("Summary withheld: it failed evidence validation.", CAVEAT))
        if fs.get("assessment"):
            story.append(Paragraph("<b>Assessment:</b> " + esc(fs["assessment"]), BODY))
        findings = fs.get("findings") or []
        if findings:
            rows = [[Paragraph(h, BODY) for h in ("<b>#</b>", "<b>Finding</b>", "<b>Basis</b>",
                                                   "<b>Evidence</b>")]]
            for i, f in enumerate(findings, 1):
                basis = "VERIFIED" if f.get("basis") == "verified" else "INFERRED"
                rows.append([Paragraph(str(i), BODY), Paragraph(esc(f.get("statement")), BODY),
                             Paragraph(f"<b>{basis}</b>", BODY),
                             Paragraph(esc(", ".join(f.get("evidence_ids") or [])), MONO)])
            story.append(_grid(rows, [8 * mm, 112 * mm, 20 * mm, 20 * mm]))
        else:
            story.append(Paragraph("No findings passed validation.", BODY))
        rejected = fs.get("rejected_findings") or []
        if rejected:
            story.append(Paragraph("<b>Rejected by validation (not evidence):</b>", BODY))
            for r in rejected:
                story.append(Paragraph(f"• {esc(r.get('statement'))} — <i>{esc(r.get('reason'))}</i>", CAVEAT))
        for title, key in (("Recommended actions", "recommended_actions"), ("Model-stated limitations", "limitations")):
            items = fs.get(key) or []
            if items:
                story.append(Paragraph(f"<b>{title}:</b>", BODY))
                for x in items:
                    story.append(Paragraph("• " + esc(x), BODY))
    unavailable = fs.get("unavailable_information") or []
    if unavailable:
        story.append(Paragraph("<b>Checks unavailable to the interpretation (not passed):</b>", BODY))
        for u in unavailable:
            story.append(Paragraph(f"• {esc(u.get('check'))}: {esc(u.get('reason'))}", CAVEAT))
    evidence = fs.get("evidence") or []
    if evidence:
        story.append(Paragraph("<b>Evidence items cited above</b> (deterministic, produced by the pipeline — "
                               "not by the LLM)", BODY))
        rows = [[Paragraph(h, BODY) for h in ("<b>ID</b>", "<b>Category</b>", "<b>Source</b>", "<b>Statement</b>")]]
        for e in evidence:
            rows.append([Paragraph(esc(e.get("id")), MONO), Paragraph(esc(e.get("category")), BODY),
                         Paragraph(esc(e.get("source")), MONO), Paragraph(esc(e.get("statement")), BODY)])
        story.append(_grid(rows, [12 * mm, 20 * mm, 38 * mm, 110 * mm]))
