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
H2 = ParagraphStyle("H2x", parent=styles["Heading2"], fontSize=12, spaceBefore=10, spaceAfter=4,
                    keepWithNext=1)   # never strand a section heading at the bottom of a page
BODY = ParagraphStyle("BODYx", parent=styles["BodyText"], fontSize=9, leading=12)
MONO = ParagraphStyle("MONOx", parent=styles["BodyText"], fontName="Courier", fontSize=7.5, leading=9.5)
CAVEAT = ParagraphStyle("CAVx", parent=styles["BodyText"], fontSize=8, textColor=colors.HexColor("#7a5b00"))
# compact styles for dense tables (P4.1 layout fix: headers and short values stay on one line)
CELL = ParagraphStyle("CELLx", parent=BODY, fontSize=8, leading=10)
SUBHEAD = ParagraphStyle("SUBx", parent=BODY, keepWithNext=1)
CELL_B = ParagraphStyle("CELLBx", parent=CELL, fontName="Helvetica-Bold")
CELL_MONO = ParagraphStyle("CELLMx", parent=MONO, fontSize=7.5, leading=9.5)
NOWRAP_PAD = [("LEFTPADDING", (0, 0), (-1, -1), 3), ("RIGHTPADDING", (0, 0), (-1, -1), 3),
              ("TOPPADDING", (0, 0), (-1, -1), 2), ("BOTTOMPADDING", (0, 0), (-1, -1), 3)]


_BREAK = '<font size="1"> </font>'   # invisible break opportunity (standard fonts have no zero-width space)


def soft_wrap(identifier: Any) -> str:
    """Escape an identifier and allow line breaks only after '_' / '.' / '-' / ':'."""
    text = esc(identifier)
    for ch in ("_", ".", "-", ":"):
        text = text.replace(ch, ch + _BREAK)
    return text


def short_time(iso: Any) -> str:
    """'2026-11-19T16:35:32.724935+00:00' -> '2026-11-19 16:35:32 UTC' (full value kept in section 1)."""
    text = str(iso or "")
    try:
        d = datetime.fromisoformat(text)
        if d.tzinfo is not None:
            d = d.astimezone(timezone.utc)
            return d.strftime("%Y-%m-%d %H:%M:%S UTC")
        return d.strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        return text

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
    tag = {"fact": "OBSERVED FACT", "heuristic": "HEURISTIC"}.get(knowledge, str(knowledge).upper())
    return [
        Paragraph("<b>%s</b>" % soft_wrap(f.get("rule_id", "?")), CELL_MONO),
        Paragraph(esc(f.get("severity", "?")), CELL),
        Paragraph(esc("+" + str(f.get("contribution", 0))), CELL),
        Paragraph(esc(tag), CELL_B if knowledge != "fact" else CELL),
        Paragraph(esc(f.get("evidence", "")), CELL_MONO),
        Paragraph(esc(f.get("rationale", "")), CELL),
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
    intel: dict | None = None,
    correlation: dict | None = None,
    attack: dict | None = None,
    view_notes: list[str] | None = None,
    risk: dict | None = None,
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
    for note in view_notes or []:          # P5e: MASKED VIEW / retention redaction notices
        story.append(Paragraph(f"<b>{esc(note)}</b>", CELL))
        story.append(Spacer(1, 3))
    verdict = detection.get("verdict", "unknown")
    score = detection.get("score", 0)
    verdict_color = VERDICT_COLORS.get(verdict, colors.black)
    # reportlab wants full HTML hex, e.g. #b91c1c

    banner_tbl = Table(
        [
            [Paragraph("<b>Report ID</b>", CELL), Paragraph("<b>Generated</b>", CELL),
             Paragraph("<b>Threat Verdict</b>", CELL), Paragraph("<b>Score</b>", CELL)],
            [Paragraph(soft_wrap(report_id), CELL_MONO), Paragraph(esc(short_time(generated_at)), CELL),
             Paragraph(f'<font color="#{verdict_color.hexval()[2:]}"><b>{soft_wrap(str(verdict).upper())}</b></font>',
                       CELL),
             Paragraph(f"<b>{esc(score)}/100</b>", CELL)],
        ],
        colWidths=[50 * mm, 42 * mm, 60 * mm, 24 * mm],
    )
    banner_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#efefef")),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cccccc")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        *NOWRAP_PAD,
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
        ("Subject", esc(analysis_row.get("subject") or "not present")),
        ("Date header", esc(analysis_row.get("date") or "not present")),
        ("Message-ID", esc(analysis_row.get("message_id") or "not present")),
        ("Reply-To", esc(", ".join(a["email"] for a in analysis_row.get("reply_to", [])) or "none")),
        ("Return-Path", esc(analysis_row.get("return_path") or "not present")),
        ("To", esc(", ".join(a["email"] for a in analysis_row.get("to", [])) or "unavailable")),
        ("Cc", esc(", ".join(a["email"] for a in analysis_row.get("cc", [])) or "none")),
    ]
    story.append(_kv_table(meta_rows))

    # ── 4. Findings table ─────────────────────────────────────────────────
    story.append(Paragraph("3. Findings — Explainable Indicators", H2))
    findings = detection.get("findings") or []
    if findings:
        table_data = [[
            Paragraph("<b>Rule</b>", CELL), Paragraph("<b>Severity</b>", CELL),
            Paragraph("<b>Points</b>", CELL), Paragraph("<b>Type</b>", CELL),
            Paragraph("<b>Evidence</b>", CELL), Paragraph("<b>Rationale</b>", CELL),
        ]] + [_finding_row(f) for f in findings]
        # 176 mm usable frame width; short columns sized so headers and values never split mid-word
        t = Table(table_data, colWidths=[32 * mm, 16 * mm, 13 * mm, 26 * mm, 46 * mm, 43 * mm], repeatRows=1)
        t.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cccccc")),
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e8e8e8")),
            *NOWRAP_PAD,
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
    _crosscheck_subsection(story, analysis_row)

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
        story.append(Paragraph("No Received headers are present. The message's transport path cannot be "
                               "reconstructed from the available evidence.", BODY))
    story.append(Paragraph(esc(forensics.get("forgery_note", "")), CAVEAT))

    # ── 8. Candidate IP/domain intelligence ────────────────────────────────
    story.append(Paragraph("7. Infrastructure Intelligence", H2))
    story.append(_kv_table([
        ("Earliest candidate IP", esc(forensics.get("earliest_candidate_ip") or "none identified")),
        ("Verified originating IP", esc(forensics.get("verified_originating_ip") or "not verified")),
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

    # ── 7A. Threat intelligence lookups (P5a, informational only) ───────
    _intel_section(story, intel)

    # ── 7B. Related analyses / candidate campaigns (P5c, snapshot at report time) ──
    _correlation_section(story, correlation)

    # ── 7C. MITRE ATT&CK mapping + source-type hypotheses (P5d, version-pinned) ──
    _attack_section(story, attack)

    # ── 8. ML, SHAP and AI-assisted interpretation (P4) ──────────────────
    _assessment_section(story, assessment)

    # ── 8A. Combined risk assessment (P5h, version-pinned, additional result) ──
    _risk_section(story, risk)

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
    story.append(_kv_table([
        ("Assessment version", esc(f"v{a.get('version')}" if a.get("version") is not None else "not versioned")),
        ("Assessment ID", soft_wrap(a.get("assessment_id") or "not recorded")),
        ("Generated", esc(a.get("generated_at") or "unknown")),
        ("Source", esc(a.get("source") or "unknown")),
    ]))
    story.append(Paragraph("This report prints exactly the assessment version identified above; regenerating "
                           "the assessment later creates a new version and does not change it.", CAVEAT))
    _financial_warning(story, a.get("forensic_summary") or {})     # prominent: before any model output

    # 8.1 ML
    ml = a.get("ml") or {}
    story.append(Paragraph("<b>8.1 ML classification</b>", SUBHEAD))
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
    story.append(Paragraph("<b>8.2 SHAP feature contributions</b>", SUBHEAD))
    story.append(_status_line("Explanation", ex))
    comps = ex.get("components") or {}
    if ex.get("status") == "ok" and comps:
        from app.ml.shap_view import component_view
        for name, c in comps.items():
            v = component_view(name, c, ex.get("explained_label"), ml.get("label"), ml)
            story.append(Paragraph(
                f"Component <b>{esc(v['component_name'])}</b> ({esc(c.get('explainer'))}, ensemble weight "
                f"{esc(_num(c.get('ensemble_weight'), '{:.2f}'))}) for class "
                f"<b>{esc(ex.get('explained_label'))}</b>. Values are in the <b>raw-margin</b> space "
                f"({esc(c.get('output_space'))}); they are not probabilities.", BODY))
            story.append(Paragraph(esc(v["net_sentence"]), BODY))
            if v["divergence_note"]:
                story.append(Paragraph("<b>Why the ensemble still predicts this class:</b> "
                                       + esc(v["divergence_note"]), CAVEAT))
            rows = [[Paragraph(h, CELL) for h in ("<b>Feature</b>", "<b>Group</b>", "<b>Value</b>",
                                                   "<b>SHAP (raw margin)</b>", "<b>Direction</b>")]]
            for r in v["rows"]:
                agg = r.get("aggregated")
                value = (f"aggregate of {r.get('detail') or 'components'}; not an individually interpretable "
                         "word or phrase") if agg else (r.get("value") if r.get("value") is not None else "")
                rows.append([Paragraph(soft_wrap(r.get("feature")), CELL_MONO), Paragraph(esc(r.get("group")), CELL),
                             Paragraph(esc(value), CELL),
                             Paragraph(esc(_num(r.get("shap_value"), "{:+.4f}")), CELL),
                             Paragraph(esc("aggregate " + ("toward" if r["shap_value"] > 0 else "away"))
                                       if agg else esc(r.get("direction") or ""), CELL)])
            if v["has_remainder"]:
                rows.append([Paragraph("other features (not listed)", CELL), Paragraph("—", CELL),
                             Paragraph("sum of contributions below the top-10 cut-off", CELL),
                             Paragraph(esc(_num(v["remainder"], "{:+.4f}")), CELL), Paragraph("—", CELL)])
            story.append(_grid(rows, [40 * mm, 20 * mm, 58 * mm, 30 * mm, 28 * mm]))
            check = ("passed" if v["displayed_additivity_ok"] or v["has_remainder"] else "FAILED")
            story.append(Paragraph(
                f"Additivity: base {esc(_num(v['base']))} + sum of contributions "
                f"{esc(_num((v['shown_sum'] or 0) + (v['remainder'] if v['has_remainder'] else 0)))} = output "
                f"{esc(_num(v['output']))} (check {check}; backend check "
                f"{'passed' if c.get('additivity_ok') else 'FAILED'}).", BODY))
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
    story.append(Paragraph("<b>8.3 AI-generated forensic interpretation (local LLM)</b>", SUBHEAD))
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
        items = fs.get("limitations") or []
        if items:
            story.append(Paragraph("<b>Model-stated limitations:</b>", BODY))
            for x in items:
                story.append(Paragraph("• " + esc(x), BODY))
    _recommendations(story, fs)
    story.append(Paragraph(
        "<b>Privacy:</b> before reaching the local model, secrets, account and card numbers, phone numbers, "
        "address local parts and URL paths are redacted, as are personal names taken from the From/To/Cc "
        "headers and names after greetings or sign-offs. Other personal names in the body are <b>not</b> "
        "reliably detected and may reach the local model; nothing is sent to an external service.", CAVEAT))
    unavailable = fs.get("unavailable_information") or []
    if unavailable:
        story.append(Paragraph("<b>Checks unavailable to the interpretation (not passed):</b>", BODY))
        for u in unavailable:
            story.append(Paragraph(f"• {esc(u.get('check'))}: {esc(u.get('reason'))}", CAVEAT))
    evidence = fs.get("evidence") or []
    if evidence:
        story.append(Paragraph("<b>Evidence items cited above</b> (deterministic, produced by the pipeline — "
                               "not by the LLM)", SUBHEAD))
        rows = [[Paragraph(h, BODY) for h in ("<b>ID</b>", "<b>Category</b>", "<b>Source</b>", "<b>Statement</b>")]]
        for e in evidence:
            rows.append([Paragraph(esc(e.get("id")), MONO), Paragraph(esc(e.get("category")), BODY),
                         Paragraph(soft_wrap(e.get("source")), CELL_MONO), Paragraph(esc(e.get("statement")), BODY)])
        story.append(_grid(rows, [12 * mm, 20 * mm, 36 * mm, 108 * mm]))


WARN = ParagraphStyle("WARNx", parent=BODY, fontSize=9, leading=12, textColor=colors.HexColor("#7f1d1d"))


def _financial_warning(story: list, fs: dict) -> None:
    fin = fs.get("financial_context") or {}
    if not fin.get("detected"):
        return
    terms = ", ".join(sorted({s.get("term", "") for s in fin.get("evidence_signals") or []} |
                             set(fin.get("email_text_terms") or [])))
    box = Table([[Paragraph("<b>INDEPENDENT VERIFICATION REQUIRED.</b> " + esc(fin.get("warning") or "")
                            + (f" <i>(signals: {esc(terms)})</i>" if terms else ""), WARN)]],
                colWidths=[176 * mm])
    box.setStyle(TableStyle([("BOX", (0, 0), (-1, -1), 1.2, colors.HexColor("#b91c1c")),
                             ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#fef2f2")),
                             ("LEFTPADDING", (0, 0), (-1, -1), 6), ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                             ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 6)]))
    story.append(Spacer(1, 4))
    story.append(box)
    story.append(Spacer(1, 4))


def _recommendations(story: list, fs: dict) -> None:
    if fs.get("recommendation_policy") == "p4.2-constrained":
        _recommendations_p42(story, fs)
        return
    if fs.get("status") != "ok":
        return
    recs = fs.get("recommendations")
    if recs is None:   # assessment generated before P4.1 grounding: show, but unclassified
        items = fs.get("recommended_actions") or []
        if items:
            story.append(Paragraph("<b>Recommended actions (model, generated before recommendation grounding; "
                                   "not checked against the evidence):</b>", BODY))
            for x in items:
                story.append(Paragraph("• " + esc(x), BODY))
        return
    linked = [r for r in recs if r.get("kind") == "evidence_linked"]
    general = [r for r in recs if r.get("kind") == "general"]
    if linked:
        story.append(Paragraph("<b>Evidence-linked recommendations</b> (model; each relies on the cited items):", BODY))
        for r in linked:
            story.append(Paragraph(f"• {esc(r.get('text'))} <font face='Courier' size='7.5'>"
                                   f"[{esc(', '.join(r.get('evidence_ids') or []))}]</font>", BODY))
    if general:
        story.append(Paragraph("<b>General investigative recommendations</b> (not established by a specific "
                               "evidence item):", BODY))
        for r in general:
            origin = "system" if r.get("origin") == "system" else "model"
            story.append(Paragraph(f"• {esc(r.get('text'))} <i>({origin})</i>", BODY))
    for r in fs.get("rejected_recommendations") or []:
        story.append(Paragraph(f"• Rejected recommendation: {esc(r.get('text'))} — <i>{esc(r.get('reason'))}</i>",
                               CAVEAT))


def _recommendations_p42(story: list, fs: dict) -> None:
    recs = fs.get("recommendations") or []
    linked = [r for r in recs if r.get("kind") == "evidence_linked"]
    general = [r for r in recs if r.get("kind") == "general"]
    if linked:
        story.append(Paragraph("<b>Evidence-linked recommendations</b> (system template text; evidence IDs chosen "
                               "deterministically from the evidence list, not from the model):", SUBHEAD))
        for r in linked:
            story.append(Paragraph(f"• {esc(r.get('text'))} <font face='Courier' size='7.5'>"
                                   f"[{esc(', '.join(r.get('evidence_ids') or []))}]</font>", BODY))
    if general:
        story.append(Paragraph("<b>General recommendations (system templates; standard practice, not findings and "
                               "not AI-discovered):</b>", SUBHEAD))
        for r in general:
            story.append(Paragraph("• " + esc(r.get("text")), BODY))
    rejected = fs.get("rejected_recommendations") or []
    if rejected:
        story.append(Paragraph("<b>Rejected unsafe or unsupported model suggestions</b> (shown for transparency; "
                               "do not follow):", SUBHEAD))
        for r in rejected:
            story.append(Paragraph(f"• <strike>{esc(r.get('text'))}</strike> — <i>{esc(r.get('reason'))}</i>", CAVEAT))


# ── 7A. Threat intelligence (P5a) ─────────────────────────────────────────
INTEL_STATUS_TEXT = {
    "malicious_or_flagged": "FLAGGED by provider",
    "reported_clean_no_flags": "No flags reported (not proof of safety)",
    "record_found": "Record found, no verdict (not proof of safety)",
    "no_record": "No record / no reports (not proof of safety)",
    "provider_error": "PROVIDER ERROR — no result",
    "rate_limited": "RATE LIMITED — not looked up",
    "auth_failed": "AUTH FAILED — not looked up",
    "timeout": "TIMED OUT — no result",
    "malformed_response": "MALFORMED RESPONSE — no result",
    "not_permitted": "NOT PERMITTED — not looked up",
    "not_attempted_consent_disabled": "NOT ATTEMPTED — no consent",
    "not_attempted_offline": "NOT ATTEMPTED — offline mode",
    "not_attempted_cap_reached": "NOT LOOKED UP — indicator cap reached",
    "missing_credentials": "NOT ATTEMPTED — credential not configured",
    "not_applicable_indicator": "NOT APPLICABLE — indicator not eligible",
    "quota_exhausted": "QUOTA EXHAUSTED — not looked up",
}

_FACT_KEYS = {
    "virustotal": ("malicious", "suspicious", "engines_total", "reputation", "as_owner", "country",
                   "registrar", "type_description"),
    "abuseipdb": ("abuse_confidence_score", "total_reports", "country_code", "isp", "usage_type",
                  "last_reported_at"),
    "shodan": ("open_ports", "org", "asn", "hostnames", "tags", "country"),
    "ipinfo": ("country", "region", "city", "org", "is_vpn", "is_proxy", "is_tor", "is_relay", "is_hosting"),
    "tor_exit_list": ("listed", "list_size", "list_fetched_at"),
}


def _intel_facts(r: dict) -> str:
    data = r.get("data") or {}
    parts = []
    for k in _FACT_KEYS.get(r.get("provider"), ()):
        v = data.get(k)
        if v is None or v == [] or v == "":
            continue
        if isinstance(v, bool):
            v = "yes" if v else "no"
        elif isinstance(v, list):
            v = ", ".join(str(x) for x in v[:8])
        parts.append(f"{k}={v}")
    text = "; ".join(parts) or (r.get("message") or "")
    return text[:220]


def _intel_section(story: list, run: dict | None) -> None:
    story.append(Paragraph("7A. Threat Intelligence Lookups (external providers, informational only)", H2))
    if not run:
        story.append(Paragraph("<b>Threat-intelligence lookup: NOT RUN</b> for this analysis. No indicator was "
                               "sent to any external provider.", BODY))
        story.append(Paragraph("Absence of a lookup is not evidence either way.", CAVEAT))
        return
    consent = run.get("consent") or {}
    counts = run.get("counts") or {}
    rows = [
        ("Run", esc(f"{run.get('run_id', '?')} (version {run.get('version', '?')})")),
        ("Run at", esc(short_time(run.get("created_at")))),
        ("Consent", esc(("GRANTED" if consent.get("granted") else "NOT GIVEN — no external lookups attempted")
                        + f" at {short_time(consent.get('decided_at'))} via {consent.get('source', '?')}")),
        ("Providers requested", esc(", ".join(consent.get("providers") or []) or "none")),
        ("Offline mode", esc("ON — external calls blocked; cached results only, labelled" if run.get("offline")
                             else "off")),
        ("Indicators", esc(f"{counts.get('total', 0)} found, {counts.get('eligible', 0)} eligible, "
                           f"{counts.get('looked_up', 0)} looked up, {counts.get('rejected', 0)} rejected, "
                           f"{counts.get('cap_skipped', 0)} over the cap of {run.get('ioc_cap', '?')}")),
        ("Not configured", esc("; ".join((run.get("not_configured") or {}).values()) or "none")),
    ]
    if run.get("simulated"):
        rows.insert(0, ("DATA SOURCE", "<b>SIMULATED providers (local stub) — not real provider data</b>"))
    story.append(_kv_table(rows))
    story.append(Spacer(1, 4))
    head = [Paragraph(f"<b>{h}</b>", CELL) for h in ("Indicator", "Provider", "Status", "Fetched / cache",
                                                       "Key facts (provider-supplied, sanitised)")]
    table = [head]
    for ind in (run.get("indicators") or [])[:40]:
        label = f"{ind.get('indicator', '')} ({ind.get('indicator_type', '')})"
        if ind.get("state") != "looked_up":
            table.append([Paragraph(soft_wrap(label[:120]), CELL_MONO), Paragraph("—", CELL),
                          Paragraph(esc(INTEL_STATUS_TEXT.get(ind.get("state"), ind.get("state"))), CELL_B),
                          Paragraph("never sent", CELL),
                          Paragraph(esc((ind.get("rejection_reason") or ind.get("message") or "")[:200]), CELL)])
            continue
        for r in ind.get("results") or []:
            cache = r.get("cache_state") or "none"
            fetched = short_time(r.get("fetched_at")) if r.get("fetched_at") else "—"
            cache_txt = {"fresh": "cached (fresh)", "stale": "STALE cache", "none": "live"}.get(cache, cache)
            if r.get("status") not in ("malicious_or_flagged", "reported_clean_no_flags", "record_found",
                                       "no_record"):
                cache_txt = "no data" if cache == "none" else cache_txt
            table.append([
                Paragraph(soft_wrap(label[:120]), CELL_MONO),
                Paragraph(esc(r.get("provider_label") or r.get("provider")), CELL),
                Paragraph(esc(INTEL_STATUS_TEXT.get(r.get("status"), str(r.get("status")))),
                          CELL_B if r.get("status") == "malicious_or_flagged" else CELL),
                Paragraph(esc(f"{fetched} · {cache_txt}"), CELL),
                Paragraph(esc(_intel_facts(r)), CELL),
            ])
    if len(table) == 1:
        story.append(Paragraph("No indicators were extracted from this analysis.", BODY))
    else:
        story.append(_grid(table, [40 * mm, 20 * mm, 36 * mm, 28 * mm, 52 * mm]))
    story.append(Spacer(1, 3))
    story.append(Paragraph(esc(run.get("disclaimer") or ""), CAVEAT))
    story.append(Paragraph("Stale results are earlier cached provider data shown because a live lookup was not "
                           "possible; they carry their original fetch time. No credential is printed in this "
                           "report.", CAVEAT))


# ── 7B. Related analyses / candidate campaigns (P5c) ──────────────────────
def _correlation_section(story: list, corr: dict | None) -> None:
    story.append(Paragraph("7B. Related Analyses / Candidate Campaigns (shared infrastructure)", H2))
    if corr is None:
        story.append(Paragraph("Correlation data was not available when this report was generated.", BODY))
        return
    story.append(Paragraph(esc(f"Snapshot taken at report time ({short_time(corr.get('snapshot_at'))}). "
                               f"Correlation status: {corr.get('status', 'unknown')}."), CAVEAT))
    camps = corr.get("campaigns") or []
    if camps:
        rows = [(c.get("label", "?"), esc(f"{c.get('confidence', '?')} confidence ({c.get('confidence_score')}), "
                                          f"{c.get('member_count', 0)} members, id {c.get('id')}, "
                                          f"version {c.get('version')}")) for c in camps]
        story.append(_kv_table(rows))
        story.append(Spacer(1, 3))
    related = [r for r in (corr.get("related") or []) if r.get("indicators")]
    if not related:
        story.append(Paragraph("<b>No related analyses recorded at report time.</b> This is not a claim that "
                               "the message is unique.", BODY))
    else:
        head = [Paragraph(f"<b>{h}</b>", CELL) for h in ("Related analysis", "Linked?", "Score",
                                                         "Shared indicators (type, value, strength)")]
        table = [head]
        for r in related[:15]:
            a = r.get("analysis") or {}
            inds = "; ".join(f"{i.get('type')} {i.get('value')} ({i.get('tier')})" for i in r.get("indicators", [])[:6])
            table.append([
                Paragraph(soft_wrap(f"{str(a.get('id', ''))[:8]} · {short_time(a.get('created_at'))}"), CELL_MONO),
                Paragraph(esc("yes" if r.get("qualifies") else "no (below threshold)"),
                          CELL_B if r.get("qualifies") else CELL),
                Paragraph(esc(r.get("score")), CELL),
                Paragraph(esc(inds[:400]), CELL),
            ])
        story.append(_grid(table, [38 * mm, 28 * mm, 14 * mm, 96 * mm]))
    generic = (corr.get("generic_only_overlaps") or {})
    if generic.get("count"):
        vals = ", ".join(f"{g.get('value')} ({g.get('type')})" for g in (generic.get("indicators") or [])[:6])
        story.append(Paragraph(esc(f"{generic['count']} other analyses share only generic indicators "
                                   f"({vals}); these never link analyses."), CAVEAT))
    story.append(Spacer(1, 3))
    story.append(Paragraph(esc(corr.get("rule") or ""), CAVEAT))
    story.append(Paragraph(esc(corr.get("disclaimer") or ""), CAVEAT))


# ── 7C. MITRE ATT&CK mapping + source-type hypotheses (P5d) ───────────────
BAND_TEXT = {"likely": "LIKELY", "possible": "POSSIBLE", "not_indicated": "NOT INDICATED (not proof of safety)",
             "undetermined": "UNDETERMINED (insufficient evidence)", "not_assessed": "NOT ASSESSED"}


def _attack_section(story: list, att: dict | None) -> None:
    story.append(Paragraph("7C. MITRE ATT&amp;CK Mapping and Source-Type Hypotheses (informational only)", H2))
    if not att:
        story.append(Paragraph("<b>ATT&amp;CK mapping: NOT COMPUTED</b> for this analysis.", BODY))
        return
    inputs = att.get("inputs") or {}
    rows = [
        ("Mapping", esc(f"{att.get('mapping_id', '?')} (version {att.get('version', '?')}, "
                        f"{short_time(att.get('created_at'))})")),
        ("Catalog", esc(f"MITRE ATT&CK Enterprise {att.get('attack_version')} · {att.get('catalog_version')} · "
                        + ("IDs verified against official data" if att.get("catalog_verified")
                           else "IDs NOT verified against official data"))),
        ("Engine", esc(att.get("engine_version"))),
        ("Inputs", esc(f"intel run {inputs.get('intel_run_id') or 'none'}"
                       + (" (SIMULATED provider data)" if inputs.get("intel_simulated") else "")
                       + f"; ML assessment {inputs.get('ml_assessment_id') or 'none'}")),
    ]
    story.append(_kv_table(rows))
    story.append(Spacer(1, 4))
    maps = att.get("mappings") or []
    if not maps:
        story.append(Paragraph(esc(att.get("empty_state") or "No ATT&CK techniques could be mapped."), BODY))
    else:
        head = [Paragraph(f"<b>{h}</b>", CELL) for h in ("Technique", "Tactic", "Basis / confidence",
                                                         "Evidence", "Rationale and limitations")]
        table = [head]
        for m in maps:
            note = m.get("rationale") or ""
            if m.get("limitations"):
                note += f" Limitation: {m['limitations']}"
            ev = ", ".join(m.get("evidence_ids") or [])
            if m.get("supporting_evidence_ids"):
                ev += " (support: " + ", ".join(m["supporting_evidence_ids"]) + ")"
            table.append([Paragraph(soft_wrap(f"{m.get('technique_id')} {m.get('name')}"), CELL_MONO),
                          Paragraph(esc(", ".join(m.get("tactics") or [])), CELL),
                          Paragraph(esc(f"{str(m.get('basis', '')).upper()} · {m.get('confidence')}"), CELL_B),
                          Paragraph(esc(ev), CELL),
                          Paragraph(esc(note[:420]), CELL)])
        story.append(_grid(table, [38 * mm, 24 * mm, 24 * mm, 20 * mm, 70 * mm]))
    story.append(Spacer(1, 4))
    head = [Paragraph(f"<b>{h}</b>", CELL) for h in ("Source-type hypothesis", "Assessment", "Evidence",
                                                     "Rationale / missing data")]
    table = [head]
    for h in att.get("source_type") or []:
        band = BAND_TEXT.get(h.get("band"), str(h.get("band")))
        if h.get("band") == "not_assessed" and h.get("reason"):
            band = f"NOT ASSESSED: {h['reason']}"
        why = h.get("rationale") or ""
        if h.get("missing_data"):
            why += " Missing: " + "; ".join(h["missing_data"])
        table.append([Paragraph(esc(h.get("label")), CELL), Paragraph(esc(band), CELL_B),
                      Paragraph(esc(", ".join(h.get("evidence_ids") or []) or "—"), CELL),
                      Paragraph(esc(why[:420]), CELL)])
    story.append(_grid(table, [42 * mm, 38 * mm, 18 * mm, 78 * mm]))
    ev = att.get("evidence") or []
    if ev:
        story.append(Spacer(1, 3))
        head = [Paragraph(f"<b>{h}</b>", CELL) for h in ("ID", "Category", "Source field", "Statement")]
        table = [head] + [[Paragraph(esc(e.get("id")), CELL_MONO), Paragraph(esc(e.get("category")), CELL),
                           Paragraph(soft_wrap(e.get("source_field")), CELL_MONO),
                           Paragraph(esc(e.get("statement")), CELL)] for e in ev[:40]]
        story.append(_grid(table, [12 * mm, 20 * mm, 50 * mm, 94 * mm]))
    story.append(Spacer(1, 3))
    story.append(Paragraph(esc(att.get("note") or ""), CAVEAT))
    story.append(Paragraph(esc(att.get("disclaimer") or ""), CAVEAT))


# ── 8A. Combined risk assessment (P5h) ────────────────────────────────────
RISK_STATUS_TEXT = {"available": "available", "unavailable": "UNAVAILABLE", "not_run": "NOT RUN",
                    "declined": "DECLINED (no consent)", "error": "ERROR"}


def _risk_value(c: dict) -> str:
    v = c.get("value")
    if v is None:
        return "—"
    if c.get("name") == "rules" and isinstance(v, dict):
        return f"{v.get('score')}/100 {v.get('verdict')}"
    if c.get("name") == "ml" and isinstance(v, dict):
        return f"threat index {_num(v.get('threat_index'))}; class {v.get('label')}"
    if c.get("name") == "threat_intel" and isinstance(v, dict):
        flagged = ", ".join(v.get("flagged_providers") or []) or "no flags"
        return f"run v{v.get('version')}: {flagged}" + (" (SIMULATED)" if v.get("simulated") else "")
    if isinstance(v, list):
        return ", ".join(str(x) for x in v) or "none"
    if isinstance(v, dict):
        return ", ".join(f"{k}: {x}" for k, x in v.items() if not isinstance(x, (dict, list)))
    return str(v)


def _risk_section(story: list, r: dict | None) -> None:
    story.append(Paragraph("8A. Combined Risk Assessment (additional result, not a probability)", H2))
    story.append(Paragraph(
        "An additional, separately labelled risk index that combines the rule engine, the ML ensemble, "
        "hard-evidence floors and consented threat intelligence by documented rules. It does not replace or "
        "change the rule verdict (above) or the ML classification (section 8).", CAVEAT))
    if not r:
        story.append(Paragraph("<b>Combined risk: NOT COMPUTED</b> for this analysis.", BODY))
        return
    score = r.get("combined_score")
    inputs = r.get("inputs") or {}
    ml_src = inputs.get("ml_source") or {}
    rows = [
        ("Result", esc(f"{str(r.get('level', '?')).upper()} — "
                       + (f"{score}/100" if score is not None else "no score (indeterminate)")
                       + f"; confidence {r.get('confidence')}; agreement {r.get('agreement')}")),
        ("Version", esc(f"{r.get('risk_id', '?')} (version {r.get('version', '?')}, {short_time(r.get('created_at'))}); "
                        f"{r.get('engine_version')} / {r.get('config_version')}")),
        ("Inputs", esc(f"rules {inputs.get('detection_score')}/{inputs.get('detection_verdict')}; "
                       f"ML {ml_src.get('status')} (source {ml_src.get('kind') or 'none'}, "
                       f"model {ml_src.get('model_version') or 'n/a'}); "
                       f"intel run {inputs.get('intel_run_id') or 'none'}"
                       + (" (SIMULATED)" if inputs.get("intel_simulated") else "")
                       + f"; ATT&CK mapping {inputs.get('attack_mapping_id') or 'none'}")),
        ("Flags", esc(", ".join(r.get("flags") or []) or "none")),
    ]
    story.append(_kv_table(rows))
    story.append(Spacer(1, 4))
    head = [Paragraph(f"<b>{h}</b>", CELL) for h in ("Component", "Status", "Value", "Role / effect", "Evidence")]
    body = [head]
    for c in r.get("components") or []:
        body.append([Paragraph(esc(c.get("label") or c.get("name")), CELL),
                     Paragraph(esc(RISK_STATUS_TEXT.get(c.get("status"), str(c.get("status")))), CELL),
                     Paragraph(esc(_risk_value(c)), CELL),
                     Paragraph(esc(f"{c.get('role')} · {c.get('effect') or 'none'}"), CELL),
                     Paragraph(esc(", ".join(c.get("evidence_ids") or []) or "—"), CELL_MONO)])
    story.append(_grid(body, [38 * mm, 24 * mm, 46 * mm, 40 * mm, 34 * mm]))
    story.append(Spacer(1, 3))
    for line in r.get("explanation") or []:
        story.append(Paragraph("• " + esc(line), BODY))
    ev = r.get("evidence") or []
    if ev:
        story.append(Paragraph("<b>Evidence</b>", BODY))
        for e in ev[:40]:
            story.append(Paragraph(f"{esc(e.get('id'))} [{esc(e.get('source'))}] {esc(e.get('statement'))}", CAVEAT))
    for d in r.get("disclaimers") or []:
        story.append(Paragraph("• " + esc(d), CAVEAT))


# ── 5 (subsection). Parser cross-check (P5k-lite, informational) ──────────
CROSSCHECK_STATUS_TEXT = {
    "agree": "AGREE — both parsers produced the same normalised view",
    "minor_differences": "MINOR DIFFERENCES — informational only",
    "security_relevant_differences": "SECURITY-RELEVANT DIFFERENCES — review the raw message",
    "unavailable": "UNAVAILABLE — cross-check did not run",
}


def _crosscheck_subsection(story: list, analysis_row: dict) -> None:
    story.append(Paragraph("<b>Parser cross-check (informational; does not change any score)</b>", SUBHEAD))
    if analysis_row.get("retention_state") == "redacted":
        story.append(Paragraph("Parser cross-check: redacted per retention policy.", BODY))
        return
    cc = analysis_row.get("parser_crosscheck")
    if not cc:
        story.append(Paragraph("Parser cross-check: not recorded for this analysis (stored before it existed).", BODY))
        return
    status = cc.get("status", "unavailable")
    line = CROSSCHECK_STATUS_TEXT.get(status, str(status))
    if status == "unavailable" and cc.get("reason"):
        line += f" ({cc['reason']})"
    story.append(Paragraph(f"<b>Status:</b> {esc(line)}", BODY))
    story.append(Paragraph(esc(f"Primary: {cc.get('primary')}; secondary: {cc.get('secondary')} "
                               f"{cc.get('secondary_version') or ''}"), CAVEAT))
    diffs = cc.get("differences") or []
    if diffs:
        rows = [[Paragraph(f"<b>{h}</b>", CELL) for h in ("ID", "Field", "Severity", "Description")]]
        for d in diffs[:30]:
            rows.append([Paragraph(esc(d.get("evidence_id")), CELL_MONO), Paragraph(soft_wrap(d.get("field")), CELL_MONO),
                         Paragraph(esc(str(d.get("severity", "")).replace("_", " ")),
                                   CELL_B if d.get("severity") == "security_relevant" else CELL),
                         Paragraph(esc(d.get("description")), CELL)])
        story.append(_grid(rows, [12 * mm, 36 * mm, 28 * mm, 100 * mm]))
    story.append(Paragraph(esc(cc.get("note") or ""), CAVEAT))
