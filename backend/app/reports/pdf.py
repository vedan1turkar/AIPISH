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
    story.append(_kv_table([
        ("Assessment version", esc(f"v{a.get('version')}" if a.get("version") is not None else "not versioned")),
        ("Assessment ID", soft_wrap(a.get("assessment_id") or "not recorded")),
        ("Generated", esc(a.get("generated_at") or "unknown")),
        ("Source", esc(a.get("source") or "unknown")),
    ]))
    story.append(Paragraph("This report prints exactly the assessment version identified above; regenerating "
                           "the assessment later creates a new version and does not change it.", CAVEAT))

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
        _recommendations(story, fs)
        items = fs.get("limitations") or []
        if items:
            story.append(Paragraph("<b>Model-stated limitations:</b>", BODY))
            for x in items:
                story.append(Paragraph("• " + esc(x), BODY))
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
                               "not by the LLM)", BODY))
        rows = [[Paragraph(h, BODY) for h in ("<b>ID</b>", "<b>Category</b>", "<b>Source</b>", "<b>Statement</b>")]]
        for e in evidence:
            rows.append([Paragraph(esc(e.get("id")), MONO), Paragraph(esc(e.get("category")), BODY),
                         Paragraph(soft_wrap(e.get("source")), CELL_MONO), Paragraph(esc(e.get("statement")), BODY)])
        story.append(_grid(rows, [12 * mm, 20 * mm, 36 * mm, 108 * mm]))


def _recommendations(story: list, fs: dict) -> None:
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
