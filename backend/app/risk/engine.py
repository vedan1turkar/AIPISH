"""Explainable combined risk assessment (P5h) — a pure, deterministic combiner.

Design and properties: docs/risk/README.md. In short:
- ML threat index p = 1 - P(legitimate) is the primary score when available (it already contains the rule
  features, so rule points are never added on top — no double counting);
- rules act through floors (hard evidence, conflict, rule-suspicious) and become primary only without ML;
- consented threat intel can only raise (capped); clean / no-record results contribute nothing;
- campaign and ATT&CK context never change the score;
- missing primaries never imply legitimate (floor "low"; both missing -> indeterminate).

The result is a risk INDEX, not a probability of fraud. Inputs are read, never modified.
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field

from app.risk.config import CONFIG_VERSION, ENGINE_VERSION, INDETERMINATE, LEVELS, RiskConfig, get_config

DISCLAIMERS = [
    "Risk index (0-100), not a probability of fraud: it combines existing signals by documented rules.",
    "The ML models were trained on old, partly synthetic and source-confounded data; their outputs are not "
    "calibrated probabilities for modern real-world mail.",
    "Absence of threat-intelligence records is not evidence of safety.",
    "Additional result: the 18-rule verdict and the ML classification are shown unchanged beside it.",
]
MALICIOUS = "malicious_or_flagged"
TERMINAL_INTEL = frozenset({"malicious_or_flagged", "reported_clean_no_flags", "record_found", "no_record"})
ML_STATUS = {"ok": "available", "unavailable": "unavailable", "not_applicable": "unavailable",
             "error": "error", "timeout": "error"}
HARD_FLOOR_TEXT = {
    "H1_risky_attachment": "Risky attachment type (executable, macro-enabled or container format).",
    "H2_verified_auth_fail_identity": "Locally re-verified authentication failure together with a "
                                      "sender-identity mismatch.",
    "H3_payment_or_credential_with_identity": "Payment-change or credential request together with a "
                                              "sender-identity signal (business-email-compromise pattern).",
}


@dataclass
class Inputs:
    detection: dict | None = None            # {"score", "verdict", "findings"} | {"error"} | None
    ml: dict | None = None                   # {"status", "label", "confidence", "probabilities", ...}
    intel_run: dict | None = None            # threat-intel run dict (P5a) or None
    campaigns: list[dict] = field(default_factory=list)   # [{"campaign_id", "label", "confidence"}]
    attack: dict | None = None               # {"mapping_id", "version", "techniques", "hypotheses"}


def _floor_int(x: float) -> int:
    return int(math.floor(x + 1e-9))


def ml_to_score(p: float, cfg: RiskConfig) -> float:
    """Monotone piecewise-linear map of the ML threat index onto the band edges."""
    pts = [(0.0, 0.0), (cfg.t_low, cfg.edge_low), (cfg.t_med, cfg.edge_medium), (cfg.t_high, cfg.edge_high),
           (cfg.t_crit, cfg.edge_critical), (1.0, 100.0)]
    p = min(1.0, max(0.0, p))
    for (x0, y0), (x1, y1) in zip(pts, pts[1:]):
        if p <= x1:
            return y0 + (y1 - y0) * ((p - x0) / (x1 - x0) if x1 > x0 else 1.0)
    return 100.0


def level_for(score: int | None, cfg: RiskConfig) -> str:
    if score is None:
        return INDETERMINATE
    if score >= cfg.edge_critical:
        return "critical"
    if score >= cfg.edge_high:
        return "high"
    if score >= cfg.edge_medium:
        return "medium"
    if score >= cfg.edge_low:
        return "low"
    return "minimal"


class _Ev:
    def __init__(self) -> None:
        self.items: list[dict] = []
        self._by_ref: dict[str, str] = {}

    def add(self, source: str, ref: str, statement: str) -> str:
        key = f"{source}:{ref}"
        if key in self._by_ref:
            return self._by_ref[key]
        eid = f"K{len(self.items) + 1}"
        self.items.append({"id": eid, "source": source, "ref": ref, "statement": statement})
        self._by_ref[key] = eid
        return eid


def _rules_view(det: dict | None) -> tuple[bool, dict]:
    if not det or "error" in det or not isinstance(det.get("score"), (int, float)):
        return False, {}
    fired = {f["rule_id"]: f for f in det.get("findings") or [] if f.get("rule_id")}
    return True, {"score": int(det["score"]), "verdict": det.get("verdict"), "fired": fired}


def _ml_view(ml: dict | None) -> tuple[str, dict]:
    if not ml:
        return "not_run", {}
    status = ML_STATUS.get(str(ml.get("status")), "error")
    probs = ml.get("probabilities") or {}
    if status == "available" and isinstance(probs.get("legitimate"), (int, float)):
        p = round(1.0 - float(probs["legitimate"]), 4)
        return "available", {"p": max(0.0, min(1.0, p)), "label": ml.get("label"),
                             "confidence": ml.get("confidence"), "probabilities": probs}
    return ("error" if status == "available" else status), {"reason": ml.get("reason")}


def _intel_view(run: dict | None, cfg: RiskConfig) -> tuple[str, dict]:
    if not run:
        return "not_run", {"reason": "No threat-intel run for this analysis."}
    consent = (run.get("consent") or {}).get("granted")
    if not consent:
        return "declined", {"reason": "Consent was not granted; nothing was looked up.", "run_id": run.get("run_id")}
    flagged: dict[str, set[str]] = {}
    terminal = 0
    for ind in run.get("indicators") or []:
        for r in ind.get("results") or []:
            st = r.get("status")
            if st in TERMINAL_INTEL:
                terminal += 1
            if st == MALICIOUS:
                flagged.setdefault(str(r.get("provider")), set()).add(str(r.get("indicator") or ind.get("indicator")))
    view = {"run_id": run.get("run_id"), "version": run.get("version"), "simulated": bool(run.get("simulated")),
            "offline": bool(run.get("offline")), "flagged": {k: sorted(v) for k, v in sorted(flagged.items())},
            "terminal_results": terminal}
    if terminal == 0:
        view["reason"] = ("No provider returned a usable result (offline, not configured, errors or limits). "
                          "Nothing is inferred.")
        return "unavailable", view
    return "available", view


def compute(inp: Inputs, cfg: RiskConfig | None = None) -> dict:
    cfg = cfg or get_config()
    ev = _Ev()
    rules_ok, rv = _rules_view(inp.detection)
    ml_status, mv = _ml_view(inp.ml)
    ml_ok = ml_status == "available"
    intel_status, iv = _intel_view(inp.intel_run, cfg)
    floors: list[tuple[int, str]] = []          # (floor score, reason key)
    explanation: list[str] = []
    flags: set[str] = set()
    components: list[dict] = []

    # ── rules ──────────────────────────────────────────────────────────────
    fired = rv.get("fired", {})
    rule_eids = {rid: ev.add("rule", rid, f"Rule {rid}: {f.get('title') or rid} (+{f.get('contribution', 0)})")
                 for rid, f in sorted(fired.items())}
    cues = [{"rule_id": r, "fired": r in fired, "evidence_id": rule_eids.get(r)} for r in cfg.cue_rules]
    # ── ML ─────────────────────────────────────────────────────────────────
    p = mv.get("p")
    ml_eid = None
    if ml_ok:
        src = inp.ml or {}
        ml_eid = ev.add("ml", str(src.get("source_id") or "ml"),
                        f"ML ensemble: class {mv['label']} (top-class confidence {mv['confidence']}); "
                        f"threat index 1 - P(legitimate) = {p:.4f}")
    ml_threat = ml_ok and p >= cfg.ml_side_threshold
    rule_verdict = rv.get("verdict")

    # agreement / conflict
    if rules_ok and ml_ok:
        rule_threat = rule_verdict != "minimal"
        if rule_verdict == "phishing_fraud_likely" and not ml_threat:
            agreement, conflict = "conflict", "rules_high_ml_legitimate"
        elif rule_verdict == "minimal" and ml_threat:
            agreement, conflict = "conflict", "ml_threat_rules_minimal"
        elif rule_verdict == "suspicious" and not ml_threat:
            agreement, conflict = "partial", None
        else:
            agreement, conflict = ("agree" if rule_threat == ml_threat else "partial"), None
    else:
        agreement, conflict = "not_applicable", None

    # ── base ───────────────────────────────────────────────────────────────
    if ml_ok:
        base: float | None = ml_to_score(p, cfg)
        explanation.append(f"Primary signal: ML ensemble threat index {p:.2f} (class {mv['label']}), mapped to "
                           f"{_floor_int(base)}/100. Rule points are not added on top because the ML model "
                           f"already uses the rule results as features.")
    elif rules_ok:
        base = float(rv["score"])
        explanation.append(f"ML result not available ({ml_status}); the rule score {rv['score']}/100 is used as "
                           f"the primary signal.")
    else:
        base = None

    if base is not None and not (rules_ok and ml_ok):
        floors.append((cfg.missing_primary_floor, "missing_primary"))
        flags.add("components_missing")
    if rules_ok and ml_ok and rule_verdict == "suspicious":
        floors.append((cfg.suspicious_floor, "rules_suspicious"))
    if conflict:
        flags.update({"conflicting_signals", "analyst_review_recommended"})
        floors.append((cfg.conflict_floor, "conflict"))
        if conflict == "rules_high_ml_legitimate":
            explanation.append(f"Conflicting signals: the rule engine says {rule_verdict} ({rv['score']}/100) but "
                               f"the ML ensemble leans legitimate (threat index {p:.2f}). Raised to at least medium; "
                               f"analyst review recommended.")
        else:
            explanation.append(f"Conflicting signals: the ML ensemble leans threat (index {p:.2f}, class "
                               f"{mv['label']}) but the rule engine found little ({rv['score']}/100). At least "
                               f"medium; analyst review recommended.")

    # ── hard-evidence floors (from displayed rule findings) ────────────────
    hard: list[dict] = []
    if rules_ok:
        identity = sorted(r for r in fired if r in cfg.identity_rules)
        if "risky_attachment_type" in fired:
            hard.append({"id": "H1_risky_attachment", "rules": ["risky_attachment_type"]})
        if "auth_verified_fail" in fired and identity:
            hard.append({"id": "H2_verified_auth_fail_identity", "rules": ["auth_verified_fail", *identity]})
        lure = sorted(r for r in fired if r in cfg.lure_rules)
        sender_sig = sorted(set(identity) | ({"auth_verified_fail", "auth_conflict"} & set(fired)))
        if lure and sender_sig:
            hard.append({"id": "H3_payment_or_credential_with_identity", "rules": [*lure, *sender_sig]})
    for h in hard:
        h["evidence_ids"] = [rule_eids[r] for r in h["rules"] if r in rule_eids]
        h["floor"] = cfg.hard_floor
        h["reason"] = HARD_FLOOR_TEXT[h["id"]]
        floors.append((cfg.hard_floor, h["id"]))
    if hard:
        flags.add("hard_evidence_floor")
        explanation.append("Hard evidence sets a floor of high that the ML result cannot lower: "
                           + " ".join(h["reason"] for h in hard))

    # ── threat intel (corroboration only) ──────────────────────────────────
    intel_points = 0
    intel_eids: list[str] = []
    if intel_status == "available":
        strong = [pv for pv in iv["flagged"] if pv in cfg.strong_intel_providers]
        soft = [pv for pv in iv["flagged"] if pv not in cfg.strong_intel_providers]
        intel_points = min(cfg.intel_cap, cfg.intel_strong_points * len(strong) + cfg.intel_soft_points * len(soft))
        for prov, inds in iv["flagged"].items():
            intel_eids.append(ev.add("intel", f"{iv['run_id']}/{prov}",
                                     f"{prov} flagged {len(inds)} indicator(s) in run v{iv['version']}"
                                     + (" (SIMULATED data)" if iv["simulated"] else "")))
        if strong:
            floors.append((cfg.intel_strong_floor, "intel_strong"))
        if iv["flagged"]:
            flags.add("intel_flagged")
            explanation.append(f"Threat intelligence corroborates: {', '.join(iv['flagged'])} flagged indicators "
                               f"(+{intel_points}, capped at {cfg.intel_cap})"
                               + (" — SIMULATED provider data." if iv["simulated"] else "."))
        else:
            explanation.append("Threat intelligence returned no flags. This contributes nothing and is not "
                               "evidence of safety.")
        if iv["simulated"]:
            flags.add("intel_simulated")

    # ── combine ────────────────────────────────────────────────────────────
    if base is None:
        score: int | None = None
        explanation.insert(0, "Indeterminate: neither the rule engine nor the ML ensemble produced a result. "
                              "This is not an indication of safety.")
    else:
        floor_val = max([f for f, _ in floors], default=0)
        score = min(100, _floor_int(max(base, floor_val) + intel_points))
    level = level_for(score, cfg)

    # confidence
    if score is None or conflict or not (rules_ok and ml_ok):
        confidence = "low"
    elif isinstance(mv.get("confidence"), (int, float)) and mv["confidence"] >= cfg.high_confidence_ml:
        confidence = "high"
    else:
        confidence = "medium"
    if rules_ok and not ml_ok:
        flags.add("rules_only")
    if ml_ok and not rules_ok:
        flags.add("ml_only")

    # ── components ─────────────────────────────────────────────────────────
    if rules_ok:
        components.append({
            "name": "rules", "label": "18-rule engine (as displayed)", "status": "available",
            "value": {"score": rv["score"], "verdict": rule_verdict, "fired": sorted(fired)},
            "role": "floor" if ml_ok else "primary",
            "effect": ("primary score" if not ml_ok else
                       "conflict floor (medium)" if conflict == "rules_high_ml_legitimate" else
                       "low floor (rule verdict suspicious)" if rule_verdict == "suspicious" else
                       "no direct points (already inside the ML features)"),
            "evidence_ids": [rule_eids[r] for r in sorted(fired)],
            "cues": cues,
            "reason": (f"Rule verdict {rule_verdict} ({rv['score']}/100)."
                       + (" Used through floors and conflict checks only." if ml_ok else " Used as primary."))})
    else:
        components.append({"name": "rules", "label": "18-rule engine (as displayed)",
                           "status": "error" if inp.detection else "not_run", "value": None, "role": "unavailable",
                           "effect": None, "evidence_ids": [], "cues": cues,
                           "reason": "Rule engine result is missing or failed; never treated as safe."})
    components.append({
        "name": "ml", "label": "ML ensemble (threat index = 1 - P(legitimate))", "status": ml_status,
        "value": ({"threat_index": p, "label": mv["label"], "confidence": mv["confidence"],
                   "probabilities": mv["probabilities"]} if ml_ok else None),
        "role": "primary" if ml_ok else "unavailable",
        "effect": f"base {_floor_int(base)}/100" if ml_ok and base is not None else None,
        "evidence_ids": [ml_eid] if ml_eid else [],
        "reason": ("Primary signal (band thresholds derived on the validation split; not a calibrated "
                   "probability). The served model never predicts the 'suspicious' class; conflicts with the rules "
                   "are flagged instead." if ml_ok else
                   f"ML result {ml_status}: {mv.get('reason') or 'no classification stored for this analysis'}. "
                   "Never treated as legitimate; confidence reduced.")})
    components.append({
        "name": "hard_evidence", "label": "Hard-evidence floors", "status": "available" if rules_ok else "unavailable",
        "value": [h["id"] for h in hard], "role": "floor" if hard else ("floor" if rules_ok else "unavailable"),
        "effect": f"floor {cfg.hard_floor} (high)" if hard else "none",
        "evidence_ids": sorted({e for h in hard for e in h["evidence_ids"]}, key=lambda s: int(s[1:])),
        "floors": hard,
        "reason": ("; ".join(h["reason"] for h in hard) if hard else
                   "No decisive combination fired." if rules_ok else "Needs rule findings.")})
    intel_role = "corroboration" if intel_status == "available" else "unavailable"
    components.append({
        "name": "threat_intel", "label": "Threat intelligence (consented runs only)", "status": intel_status,
        "value": ({"run_id": iv.get("run_id"), "version": iv.get("version"), "flagged_providers": list(iv["flagged"]),
                   "simulated": iv.get("simulated")} if intel_status == "available" else None),
        "role": intel_role, "effect": f"+{intel_points}" if intel_points else "none",
        "evidence_ids": intel_eids,
        "reason": (iv.get("reason") or ("Flags raise the index; clean or no-record results contribute nothing "
                                         "and are not evidence of safety."))})
    camp_eids = [ev.add("campaign", str(c.get("campaign_id")),
                        f"Member of {c.get('label') or 'candidate campaign ' + str(c.get('campaign_id'))} "
                        f"({c.get('confidence') or 'n/a'} confidence)") for c in inp.campaigns]
    components.append({
        "name": "campaign", "label": "Candidate campaign membership", "status": "available",
        "value": [c.get("label") or c.get("campaign_id") for c in inp.campaigns], "role": "context", "effect": "none",
        "evidence_ids": camp_eids,
        "reason": ("Context only: campaigns are built from the same indicators, so they do not change the index."
                   if inp.campaigns else "Not a member of any candidate campaign (context only).")})
    att = inp.attack
    att_eids = []
    if att:
        for t in att.get("techniques") or []:
            att_eids.append(ev.add("attack", f"{att.get('mapping_id')}/{t}", f"ATT&CK technique {t} mapped"))
    components.append({
        "name": "attack", "label": "ATT&CK mapping and source-type hypotheses",
        "status": "available" if att else "not_run",
        "value": ({"techniques": att.get("techniques") or [], "hypotheses": att.get("hypotheses") or []}
                  if att else None),
        "role": "context" if att else "unavailable", "effect": "none", "evidence_ids": att_eids,
        "reason": "Context only: derived from the same rule findings and ML output, so no score effect."})

    if conflict is None and agreement == "agree" and rules_ok and ml_ok:
        explanation.append("Rules and ML agree.")
    missing = [c["name"] for c in components[:2] if c["status"] != "available"]
    if missing and base is not None:
        explanation.append(f"Missing: {', '.join(missing)} — confidence reduced; never read as legitimate.")
    if "analyst_review_recommended" in flags:
        explanation.append("Recommended: analyst review of both views before acting.")

    ml_src = inp.ml or {}
    return {
        "engine_version": ENGINE_VERSION, "config_version": CONFIG_VERSION,
        "combined_score": score, "level": level, "confidence": confidence,
        "agreement": agreement, "conflict": conflict, "flags": sorted(flags),
        "components": components, "evidence": ev.items, "explanation": explanation,
        "bands": cfg.as_dict(), "levels": list(LEVELS),
        "inputs": {
            "detection_score": rv.get("score"), "detection_verdict": rule_verdict,
            "ml_source": ({"kind": ml_src.get("source_kind"), "id": ml_src.get("source_id"),
                           "model_version": ml_src.get("model_version"), "status": ml_status}),
            "intel_run_id": iv.get("run_id"), "intel_simulated": bool(iv.get("simulated")),
            "attack_mapping_id": (att or {}).get("mapping_id"),
            "campaign_ids": [c.get("campaign_id") for c in inp.campaigns],
        },
        "disclaimers": DISCLAIMERS,
    }
