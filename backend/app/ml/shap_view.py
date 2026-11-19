"""Read-only interpretation of a stored SHAP component (P4.1).

Never recomputes SHAP; it only derives display facts from the stored
response so every consumer (LLM evidence pack, PDF, dashboard mirror in
frontend/src/components/assessment/model.ts) says the same thing:

- the net movement of the explained component's raw margin (output - base),
  which can point AWAY from the class the whole ensemble predicts, because
  other components (DistilRoBERTa) are not explained by SHAP;
- every displayed contribution including aggregated rows, the remainder of
  contributions not displayed, and whether base + sum == output.
"""
from __future__ import annotations

COMPONENT_NAMES = {"xgb": "XGBoost", "lr": "logistic regression", "transformer": "DistilRoBERTa"}
ADDITIVITY_TOL = 1e-3


def name_of(key: str) -> str:
    return COMPONENT_NAMES.get(key, key)


def _num(v) -> float | None:
    return float(v) if isinstance(v, (int, float)) and not isinstance(v, bool) else None


def component_view(key: str, comp: dict, explained_label: str | None, predicted_label: str | None,
                   ml: dict | None = None) -> dict:
    """`ml` (optional) is the stored ML result; its per-component probabilities make the
    divergence note quantitative instead of speculative."""
    base, out = _num(comp.get("base_value")), _num(comp.get("output_value"))
    rows = [{**r, "aggregated": False} for r in comp.get("top_contributions") or []] + \
           [{**r, "aggregated": True} for r in comp.get("aggregated") or []]
    rows = [r for r in rows if _num(r.get("shap_value")) is not None]
    shown = sum(float(r["shap_value"]) for r in rows)
    net = (out - base) if base is not None and out is not None else None
    remainder = (net - shown) if net is not None else None
    if net is None:
        direction = "unknown"
    elif abs(net) < ADDITIVITY_TOL:
        direction = "neutral"
    else:
        direction = "toward" if net > 0 else "away"
    label = explained_label or "the explained class"
    comp_name = name_of(key)
    if net is None:
        net_sentence = f"The net {comp_name} contribution could not be determined (base or output missing)."
    elif direction == "neutral":
        net_sentence = f"The net {comp_name} contribution to '{label}' is approximately zero."
    else:
        net_sentence = (f"Net {comp_name} contribution: its raw margin for '{label}' moved from {base:+.4f} "
                        f"to {out:+.4f} ({net:+.4f}), i.e. {'toward' if direction == 'toward' else 'away from'} "
                        f"'{label}' overall.")
    divergence = None
    if direction == "away" and predicted_label and predicted_label == explained_label:
        probs = {k: v.get(label) for k, v in ((ml or {}).get("components") or {}).items()
                 if isinstance(v, dict) and _num(v.get(label)) is not None}
        conf = _num((ml or {}).get("confidence"))
        detail = ""
        if probs:
            detail = (" The ensemble score is a weighted average of component probabilities: "
                      + ", ".join(f"{name_of(k)} gave '{label}' {float(v):.4f}" for k, v in probs.items())
                      + (f", giving the ensemble score {conf:.4f}." if conf is not None else "."))
        divergence = (f"For this email the {comp_name} raw margin for '{label}' ended below its baseline, i.e. "
                      f"its explained contribution moved away from '{label}', yet the whole ensemble still "
                      f"predicts '{label}'. A margin below baseline is not the same as {comp_name} rejecting "
                      f"'{label}': it is relative to the model's average output.{detail} The ensemble also "
                      "includes DistilRoBERTa, which SHAP does not explain, so these SHAP values do not "
                      "explain the ensemble prediction.")
    return {
        "component": key, "component_name": comp_name, "ensemble_weight": _num(comp.get("ensemble_weight")),
        "output_space": comp.get("output_space"), "base": base, "output": out, "net": net,
        "net_direction": direction, "net_sentence": net_sentence, "divergence_note": divergence,
        "rows": rows, "shown_sum": shown, "remainder": remainder,
        "has_remainder": remainder is not None and abs(remainder) >= ADDITIVITY_TOL,
        "additivity_ok": comp.get("additivity_ok"),
        "displayed_additivity_ok": (remainder is not None and abs(remainder) < ADDITIVITY_TOL),
    }


def row_text(r: dict) -> str:
    v = float(r["shap_value"])
    if r.get("aggregated"):
        detail = r.get("detail") or "aggregate"
        return (f"{r['feature']} {v:+.3f} (aggregate of {detail}; not an individually interpretable word or "
                "phrase)")
    return f"{r['feature']} {r.get('direction', '')} ({v:+.3f})"
