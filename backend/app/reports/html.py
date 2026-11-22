"""Self-contained HTML forensic report (P5k-lite, R55) rendered with Jinja2.

- Uses exactly the inputs of the PDF (``app.api.case_router.report_inputs``: same masking, same pinned
  versions) and reuses the PDF's own wording helpers, so the two formats say the same thing.
- Autoescape is ON for every template; no ``|safe`` is used anywhere. No scripts, no external resources
  (inline CSS only), so the saved file renders offline. The PDF remains ReportLab (``app.reports.pdf``).
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, Undefined, select_autoescape

from app.reports import pdf as P

_ENV = Environment(loader=FileSystemLoader(str(Path(__file__).parent / "templates")),
                   autoescape=select_autoescape(enabled_extensions=("html", "j2"), default=True,
                                                default_for_string=True),
                   undefined=Undefined, trim_blocks=True, lstrip_blocks=True)

INTEGRITY_TEXT = {
    "match": "Preserved bytes matched the recorded SHA-256.",
    "mismatch": "PRESERVED BYTES DID NOT MATCH the recorded hash — investigation of the discrepancy is required.",
    "unavailable": ("Raw evidence bytes were not retained (hash-only storage policy). Integrity cannot be "
                    "re-verified without the original bytes; the recorded hash remains the reference."),
}
AUTH_NOTE = {"verified_pass": "re-verified locally: PASS", "verified_fail": "re-verified locally: FAIL",
             "parsed": "header claim only — NOT verified by this system",
             "unavailable": "check could not run (see detail)", "unknown": "no evidence either way"}
LIMITATIONS = [
    "Attribution and geolocation are investigative indicators, not proof of any person's identity or physical "
    "location; an IP identifies network infrastructure only.",
    "Received headers written before the trusted boundary may be forged; origin claims carry confidence rather "
    "than certainty, and a 'verified origin IP' is the best-evidenced candidate, not a proven origin.",
    "Header claims (Authentication-Results) are untrusted unless independently re-verified by this system.",
    "Enrichment and threat-intel provider data is external third-party data; absence of reports, flags or "
    "records is not proof of safety.",
    P.CUSTODY_LIMITATION,
]


def _s(v: Any) -> str:
    return "" if v is None else str(v)


def _intel(run: dict | None) -> dict | None:
    if not run:
        return None
    consent, counts = run.get("consent") or {}, run.get("counts") or {}
    rows = []
    for ind in (run.get("indicators") or [])[:40]:
        label = f"{ind.get('indicator', '')} ({ind.get('indicator_type', '')})"[:120]
        if ind.get("state") != "looked_up":
            rows.append({"indicator": label, "provider": "—", "flag": False,
                         "status": P.INTEL_STATUS_TEXT.get(ind.get("state"), _s(ind.get("state"))),
                         "fetched": "never sent", "facts": (ind.get("rejection_reason") or ind.get("message") or "")[:200]})
            continue
        for r in ind.get("results") or []:
            cache = r.get("cache_state") or "none"
            fetched = P.short_time(r.get("fetched_at")) if r.get("fetched_at") else "—"
            cache_txt = {"fresh": "cached (fresh)", "stale": "STALE cache", "none": "live"}.get(cache, cache)
            if r.get("status") not in ("malicious_or_flagged", "reported_clean_no_flags", "record_found", "no_record"):
                cache_txt = "no data" if cache == "none" else cache_txt
            rows.append({"indicator": label, "provider": r.get("provider_label") or r.get("provider"),
                         "status": P.INTEL_STATUS_TEXT.get(r.get("status"), _s(r.get("status"))),
                         "flag": r.get("status") == "malicious_or_flagged", "fetched": f"{fetched} · {cache_txt}",
                         "facts": P._intel_facts(r)})
    return {
        "run_id": run.get("run_id"), "version": run.get("version"), "created": P.short_time(run.get("created_at")),
        "simulated": bool(run.get("simulated")), "offline": bool(run.get("offline")),
        "consent": ("GRANTED" if consent.get("granted") else "NOT GIVEN — no external lookups attempted")
                   + f" at {P.short_time(consent.get('decided_at'))} via {consent.get('source', '?')}",
        "providers": ", ".join(consent.get("providers") or []) or "none",
        "counts": (f"{counts.get('total', 0)} found, {counts.get('eligible', 0)} eligible, "
                   f"{counts.get('looked_up', 0)} looked up, {counts.get('rejected', 0)} rejected, "
                   f"{counts.get('cap_skipped', 0)} over the cap of {run.get('ioc_cap', '?')}"),
        "not_configured": "; ".join((run.get("not_configured") or {}).values()) or "none",
        "rows": rows, "disclaimer": run.get("disclaimer") or "",
    }


def _shap(ex: dict, ml: dict) -> list[dict]:
    out = []
    comps = ex.get("components") or {}
    if ex.get("status") != "ok" or not comps:
        return out
    from app.ml.shap_view import component_view
    for name, c in comps.items():
        v = component_view(name, c, ex.get("explained_label"), ml.get("label"), ml)
        rows = []
        for r in v["rows"]:
            agg = r.get("aggregated")
            value = (f"aggregate of {r.get('detail') or 'components'}; not an individually interpretable word or "
                     "phrase") if agg else (r.get("value") if r.get("value") is not None else "")
            rows.append({"feature": r.get("feature"), "group": r.get("group"), "value": value,
                         "shap": P._num(r.get("shap_value"), "{:+.4f}"),
                         "direction": ("aggregate " + ("toward" if r["shap_value"] > 0 else "away")) if agg
                         else (r.get("direction") or "")})
        out.append({"name": v["component_name"], "explainer": c.get("explainer"),
                    "weight": P._num(c.get("ensemble_weight"), "{:.2f}"), "label": ex.get("explained_label"),
                    "space": c.get("output_space"), "net": v["net_sentence"], "divergence": v["divergence_note"],
                    "rows": rows, "remainder": P._num(v["remainder"], "{:+.4f}") if v["has_remainder"] else None,
                    "additivity": (f"base {P._num(v['base'])} + contributions "
                                   f"{P._num((v['shown_sum'] or 0) + (v['remainder'] if v['has_remainder'] else 0))} = "
                                   f"output {P._num(v['output'])} (check "
                                   f"{'passed' if v['displayed_additivity_ok'] or v['has_remainder'] else 'FAILED'}; "
                                   f"backend check {'passed' if c.get('additivity_ok') else 'FAILED'})")})
    return out


def _recommendations(fs: dict) -> list[dict]:
    """Groups of {title, items[{text, ids, note, struck}]} mirroring the PDF's two recommendation policies."""
    groups: list[dict] = []
    recs = fs.get("recommendations")
    if fs.get("recommendation_policy") == "p4.2-constrained":
        recs = recs or []
        linked = [r for r in recs if r.get("kind") == "evidence_linked"]
        general = [r for r in recs if r.get("kind") == "general"]
        if linked:
            groups.append({"title": "Evidence-linked recommendations (system template text; evidence IDs chosen "
                                    "deterministically from the evidence list, not from the model)",
                           "entries": [{"text": r.get("text"), "ids": ", ".join(r.get("evidence_ids") or [])} for r in linked]})
        if general:
            groups.append({"title": "General recommendations (system templates; standard practice, not findings and "
                                    "not AI-discovered)", "entries": [{"text": r.get("text")} for r in general]})
        rej = fs.get("rejected_recommendations") or []
        if rej:
            groups.append({"title": "Rejected unsafe or unsupported model suggestions (shown for transparency; do "
                                    "not follow)", "entries": [{"text": r.get("text"), "note": r.get("reason"),
                                                              "struck": True} for r in rej]})
        return groups
    if fs.get("status") != "ok":
        return groups
    if recs is None:
        items = fs.get("recommended_actions") or []
        if items:
            groups.append({"title": "Recommended actions (model, generated before recommendation grounding; not "
                                    "checked against the evidence)", "entries": [{"text": x} for x in items]})
        return groups
    linked = [r for r in recs if r.get("kind") == "evidence_linked"]
    general = [r for r in recs if r.get("kind") == "general"]
    if linked:
        groups.append({"title": "Evidence-linked recommendations (model; each relies on the cited items)",
                       "entries": [{"text": r.get("text"), "ids": ", ".join(r.get("evidence_ids") or [])} for r in linked]})
    if general:
        groups.append({"title": "General investigative recommendations (not established by a specific evidence item)",
                       "entries": [{"text": r.get("text"), "note": "system" if r.get("origin") == "system" else "model"}
                                 for r in general]})
    rej = fs.get("rejected_recommendations") or []
    if rej:
        groups.append({"title": "Rejected recommendations", "entries": [{"text": r.get("text"), "note": r.get("reason"),
                                                                       "struck": True} for r in rej]})
    return groups


def _assessment(a: dict | None) -> dict | None:
    if not a:
        return None
    ml, ex, fs = a.get("ml") or {}, a.get("explanation") or {}, a.get("forensic_summary") or {}
    fin = fs.get("financial_context") or {}
    status = lambda b: P.AI_STATUS_TEXT.get((b or {}).get("status") or "missing",  # noqa: E731
                                            f"{str((b or {}).get('status') or 'missing').upper()} — not reported")
    return {
        "version": f"v{a.get('version')}" if a.get("version") is not None else "not versioned",
        "id": a.get("assessment_id") or "not recorded", "generated": a.get("generated_at") or "unknown",
        "source": a.get("source") or "unknown",
        "financial": ({"warning": fin.get("warning") or "", "terms": ", ".join(sorted(
            {s.get("term", "") for s in fin.get("evidence_signals") or []} | set(fin.get("email_text_terms") or [])))}
            if fin.get("detected") else None),
        "ml": {"status": status(ml), "reason": ml.get("reason") if ml.get("status") != "ok" else None,
               "ok": ml.get("status") == "ok", "label": ml.get("label"), "confidence": P._num(ml.get("confidence")),
               "model": ml.get("model_version"), "untrained": ", ".join(ml.get("untrained_classes") or []) or "none",
               "probs": [(k, P._num(v)) for k, v in (ml.get("probabilities") or {}).items()]},
        "shap": {"status": status(ex), "reason": ex.get("reason") if ex.get("status") != "ok" else None,
                 "components": _shap(ex, ml),
                 "not_explained": [(n.get("component"), n.get("reason")) for n in ex.get("not_explained") or []],
                 "disclaimer": ex.get("disclaimer")},
        "llm": {"status": status(fs), "reason": fs.get("reason") if fs.get("status") != "ok" else None,
                "label": fs.get("label") or "Produced by a language model; may be wrong.",
                "model": fs.get("model") or {}, "ok": fs.get("status") == "ok", "summary": fs.get("summary"),
                "assessment": fs.get("assessment"),
                "findings": [{"statement": f.get("statement"), "basis": "VERIFIED" if f.get("basis") == "verified"
                              else "INFERRED", "ids": ", ".join(f.get("evidence_ids") or [])}
                             for f in fs.get("findings") or []],
                "rejected": [(r.get("statement"), r.get("reason")) for r in fs.get("rejected_findings") or []],
                "limitations": list(fs.get("limitations") or []), "recommendations": _recommendations(fs),
                "unavailable": [(u.get("check"), u.get("reason")) for u in fs.get("unavailable_information") or []],
                "evidence": [(e.get("id"), e.get("category"), e.get("source"), e.get("statement"))
                             for e in fs.get("evidence") or []]},
    }


def _risk(r: dict | None) -> dict | None:
    if not r:
        return None
    inputs = r.get("inputs") or {}
    ml_src = inputs.get("ml_source") or {}
    return {"level": str(r.get("level", "?")).upper(), "score": r.get("combined_score"),
            "confidence": r.get("confidence"), "agreement": r.get("agreement"),
            "version": f"{r.get('risk_id', '?')} (version {r.get('version', '?')}, {P.short_time(r.get('created_at'))}); "
                       f"{r.get('engine_version')} / {r.get('config_version')}",
            "inputs": (f"rules {inputs.get('detection_score')}/{inputs.get('detection_verdict')}; ML {ml_src.get('status')} "
                       f"(source {ml_src.get('kind') or 'none'}, model {ml_src.get('model_version') or 'n/a'}); intel run "
                       f"{inputs.get('intel_run_id') or 'none'}" + (" (SIMULATED)" if inputs.get("intel_simulated") else "")
                       + f"; ATT&CK mapping {inputs.get('attack_mapping_id') or 'none'}"),
            "flags": ", ".join(r.get("flags") or []) or "none",
            "components": [{"label": c.get("label") or c.get("name"),
                            "status": P.RISK_STATUS_TEXT.get(c.get("status"), _s(c.get("status"))),
                            "value": P._risk_value(c), "role": f"{c.get('role')} · {c.get('effect') or 'none'}",
                            "evidence": ", ".join(c.get("evidence_ids") or []) or "—"} for c in r.get("components") or []],
            "explanation": list(r.get("explanation") or []),
            "evidence": [(e.get("id"), e.get("source"), e.get("statement")) for e in (r.get("evidence") or [])[:40]],
            "disclaimers": list(r.get("disclaimers") or [])}


def _attack(att: dict | None) -> dict | None:
    if not att:
        return None
    from app.reports.pdf import BAND_TEXT
    inputs = att.get("inputs") or {}
    hyps = []
    for h in att.get("source_type") or []:
        band = BAND_TEXT.get(h.get("band"), _s(h.get("band")))
        if h.get("band") == "not_assessed" and h.get("reason"):
            band = f"NOT ASSESSED: {h['reason']}"
        why = (h.get("rationale") or "") + ((" Missing: " + "; ".join(h["missing_data"])) if h.get("missing_data") else "")
        hyps.append({"label": h.get("label"), "band": band, "evidence": ", ".join(h.get("evidence_ids") or []) or "—",
                     "why": why[:420]})
    maps = []
    for m in att.get("mappings") or []:
        ev = ", ".join(m.get("evidence_ids") or [])
        if m.get("supporting_evidence_ids"):
            ev += " (support: " + ", ".join(m["supporting_evidence_ids"]) + ")"
        note = (m.get("rationale") or "") + (f" Limitation: {m['limitations']}" if m.get("limitations") else "")
        maps.append({"technique": f"{m.get('technique_id')} {m.get('name')}", "technique_id": m.get("technique_id"),
                     "tactics": ", ".join(m.get("tactics") or []),
                     "basis": f"{str(m.get('basis', '')).upper()} · {m.get('confidence')}", "evidence": ev,
                     "note": note[:420]})
    return {"mapping": f"{att.get('mapping_id', '?')} (version {att.get('version', '?')}, {P.short_time(att.get('created_at'))})",
            "catalog": (f"MITRE ATT&CK Enterprise {att.get('attack_version')} · {att.get('catalog_version')} · "
                        + ("IDs verified against official data" if att.get("catalog_verified")
                           else "IDs NOT verified against official data")),
            "engine": att.get("engine_version"),
            "inputs": (f"intel run {inputs.get('intel_run_id') or 'none'}"
                       + (" (SIMULATED provider data)" if inputs.get("intel_simulated") else "")
                       + f"; ML assessment {inputs.get('ml_assessment_id') or 'none'}"),
            "empty": att.get("empty_state"), "mappings": maps, "hypotheses": hyps,
            "evidence": [(e.get("id"), e.get("category"), e.get("source_field"), e.get("statement"))
                         for e in (att.get("evidence") or [])[:40]],
            "note": att.get("note") or "", "disclaimer": att.get("disclaimer") or ""}


def _generic_values(generic: dict) -> str:
    return ", ".join(f"{g.get('value')} ({g.get('type')})" for g in (generic.get("indicators") or [])[:6])


def _correlation(corr: dict | None) -> dict | None:
    if corr is None:
        return None
    related = []
    for r in [r for r in (corr.get("related") or []) if r.get("indicators")][:15]:
        a = r.get("analysis") or {}
        related.append({"id": f"{_s(a.get('id'))[:8]} · {P.short_time(a.get('created_at'))}",
                        "linked": "yes" if r.get("qualifies") else "no (below threshold)", "score": r.get("score"),
                        "indicators": "; ".join(f"{i.get('type')} {i.get('value')} ({i.get('tier')})"
                                                for i in r.get("indicators", [])[:6])[:400]})
    generic = corr.get("generic_only_overlaps") or {}
    return {"snapshot": P.short_time(corr.get("snapshot_at")), "status": corr.get("status", "unknown"),
            "campaigns": [(c.get("label", "?"), f"{c.get('confidence', '?')} confidence ({c.get('confidence_score')}), "
                           f"{c.get('member_count', 0)} members, id {c.get('id')}, version {c.get('version')}")
                          for c in corr.get("campaigns") or []],
            "related": related,
            "generic": (f"{generic['count']} other analyses share only generic indicators ({_generic_values(generic)}); "
                        "these never link analyses.") if generic.get("count") else None,
            "rule": corr.get("rule") or "", "disclaimer": corr.get("disclaimer") or ""}


def render_report_html(kwargs: dict, *, iocs: dict, geo: dict | None, custody: dict,
                       generated_at: str | None = None) -> str:
    """kwargs: exactly the build_report_pdf inputs from report_inputs()."""
    generated_at = generated_at or datetime.now(timezone.utc).isoformat()
    row, det, forensics = kwargs["analysis_row"], kwargs["detection"] or {}, kwargs["forensics"] or {}
    auth, enr, integ = kwargs["auth"] or {}, kwargs["enrichment"] or {}, kwargs["integrity"] or {}
    sender = row.get("sender") or {}
    cc = row.get("parser_crosscheck")
    ctx = {
        "report_id": kwargs["report_id"], "generated": P.short_time(generated_at), "view_notes": kwargs["view_notes"],
        "case": kwargs["case_dict"] or {}, "verdict": det.get("verdict", "unknown"), "score": det.get("score", 0),
        "integrity": {"sha256": row.get("sha256", "unavailable"), "size": row.get("size_bytes", "unavailable"),
                      "status": integ.get("result", "unavailable"), "detail": integ.get("detail", ""),
                      "text": INTEGRITY_TEXT.get(integ.get("result", "unavailable"), "")},
        "meta": [("From", f"{sender.get('display_name') or 'unavailable'} <{sender.get('email') or 'unavailable'}> "
                          f"(domain: {sender.get('domain') or 'unavailable'})"),
                 ("Subject", row.get("subject") or "not present"), ("Date header", row.get("date") or "not present"),
                 ("Message-ID", row.get("message_id") or "not present"),
                 ("Reply-To", ", ".join(a["email"] for a in row.get("reply_to", [])) or "none"),
                 ("Return-Path", row.get("return_path") or "not present"),
                 ("To", ", ".join(a["email"] for a in row.get("to", [])) or "unavailable"),
                 ("Cc", ", ".join(a["email"] for a in row.get("cc", [])) or "none")],
        "findings": [{"rule": f.get("rule_id", "?"), "severity": f.get("severity", "?"),
                      "points": "+" + _s(f.get("contribution", 0)),
                      "type": {"fact": "OBSERVED FACT", "heuristic": "HEURISTIC"}.get(f.get("knowledge"),
                                                                                       _s(f.get("knowledge")).upper()),
                      "evidence": f.get("evidence", ""), "rationale": f.get("rationale", "")}
                     for f in det.get("findings") or []],
        "auth": [{"proto": p.upper(), "status": (auth.get(p) or {}).get("status", "unavailable"),
                  "note": AUTH_NOTE.get((auth.get(p) or {}).get("status", "unavailable"),
                                        (auth.get(p) or {}).get("status", "unavailable")),
                  "claims": ", ".join((auth.get(p) or {}).get("claims") or []) or "none",
                  "reason": (auth.get(p) or {}).get("reason"),
                  "policy": ((auth.get(p) or {}).get("detail") or {}).get("published_policy")}
                 for p in ("spf", "dkim", "dmarc")],
        "alignment": (auth.get("alignment") or {}),
        "anomalies": [(i.get("rule_id"), i.get("severity"), i.get("evidence"), i.get("rationale"))
                      for i in forensics.get("inconsistencies") or []],
        "crosscheck": {"redacted": row.get("retention_state") == "redacted", "data": cc,
                       # the tag already names the status; print only the explanatory remainder
                       "status_text": (P.CROSSCHECK_STATUS_TEXT.get((cc or {}).get("status"), "").split(" — ", 1) + [""])[1]
                       if cc else None},
        "hops": [{"index": h.get("index"), "from": f"{h.get('from_host') or '?'} ({h.get('from_ip') or 'no IP'}, "
                                                    f"{h.get('from_ip_category') or '?'})",
                  "by": h.get("by_host") or "?", "trusted": "yes" if h.get("trusted") else "NO",
                  "confidence": _s(h.get("confidence")), "notes": "; ".join(h.get("confidence_reasons", [])[:2])[:70]}
                 for h in forensics.get("relay_chain") or []],
        "boundary": forensics.get("trusted_boundary_index"), "forgery_note": forensics.get("forgery_note", ""),
        "infra": [("Earliest candidate IP", forensics.get("earliest_candidate_ip") or "none identified"),
                  ("Verified originating IP", forensics.get("verified_originating_ip") or "not verified"),
                  ("All candidates", ", ".join(forensics.get("candidate_ips") or []) or "none"),
                  ("Confidence rules", " | ".join(forensics.get("confidence_rules") or []))],
        "enrichment": [(r.get("provider"), _s((r.get("ioc") or {}).get("value"))[:40], r.get("status"),
                        f"{r.get('latency_ms')} ms", _s(r.get("provenance"))[:70]) for r in (enr.get("results") or [])[:20]],
        "degraded": "; ".join((enr.get("degraded") or [])[:5]),
        "iocs": iocs, "geo": geo, "custody": custody,
        "intel": _intel(kwargs.get("intel")), "correlation": _correlation(kwargs.get("correlation")),
        "attack": _attack(kwargs.get("attack")), "assessment": _assessment(kwargs.get("assessment")),
        "risk": _risk(kwargs.get("risk")), "limitations": LIMITATIONS,
        "unknowns": [(u.get("field"), u.get("reason")) for u in det.get("unknowns") or []],
        "forensics_disclaimer": forensics.get("disclaimer", ""),
    }
    return _ENV.get_template("report.html.j2").render(**ctx)
