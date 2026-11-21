"""Offline evaluation of the P5h combined risk assessment (no retraining, no model changes).

Usage (local dataset and models are NOT in git):
    python scripts/evaluate_risk.py --data-dir ../data --model-dir ../models/aipish-email-v1 \
        --cache-dir /tmp/risk-cache [--derive]

- Uses the saved train/validation/test split from data/processed/emails.jsonl (validated against the manifest).
- ML: the served ensemble (same components, weights and legacy rule features as inference), batched.
- Rules: the CURRENT displayed rule engine run offline (run_rules_offline_current: no DNS/auth/enrichment),
  so auth-based rules and the H2 floor cannot fire here.
- Combined: app.risk.engine.compute with no threat-intel run (intel = not_run, as for most real uploads).
- --derive picks t_med / t_high on the VALIDATION split by the documented rule and prints them; the test
  split is never used for selection.
Writes docs/risk/evaluation_v1.json and docs/risk/evaluation_v1.md: metrics and record IDs only, never
email content.
"""
from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import sys
import time
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.ml import features as F  # noqa: E402
from app.ml.dataset.labels import LABELS  # noqa: E402
from app.ml.metrics import THREAT, binary_report, classification_report  # noqa: E402
from app.risk.config import LEVELS, get_config  # noqa: E402
from app.risk.engine import Inputs, compute  # noqa: E402

DOCS = Path(__file__).resolve().parents[2] / "docs" / "risk"
LEVEL_RANK = {lvl: i for i, lvl in enumerate(LEVELS)}


def load_cache(path: Path) -> dict:
    return json.loads(path.read_text()) if path.exists() else {}


def current_rules(records: list[dict], data_dir: Path, cache: Path) -> dict[str, dict]:
    out = load_cache(cache)
    wanted = {r["id"] for r in records} - set(out)
    if wanted:
        from app.ml.dataset.build import collect
        for rm in collect(data_dir / "raw", include_real=True):
            rid = f"{rm.source}-{hashlib.sha256(rm.raw).hexdigest()[:16]}"
            if rid in wanted:
                out[rid] = F.run_rules_offline_current(rm.raw)
        missing = wanted - set(out)
        if missing:
            raise SystemExit(f"{len(missing)} raw messages not found locally")
        cache.write_text(json.dumps(out))
    return out


def ml_probs(records: list[dict], legacy: dict[str, dict], model_dir: Path, cache: Path) -> dict[str, list[float]]:
    out = load_cache(cache)
    todo = [r for r in records if r["id"] not in out]
    if todo:
        from app.ml.inference import EmailClassifier
        from app.ml.train import _expand
        clf = EmailClassifier(model_dir)
        texts = [F.text_input(r) for r in todo]
        comps: dict[str, list[list[float]]] = {}
        if clf.weights.get("lr", 0) > 0:
            comps["lr"] = _expand(clf.lr.predict_proba(texts), list(clf.lr.classes_))
        if clf.weights.get("xgb", 0) > 0:
            comps["xgb"] = _expand(clf.xgb.predict_proba(clf.fz.transform(todo, [legacy[r["id"]] for r in todo])),
                                   clf.xgb_classes)
        if clf.transformer is not None:
            from app.ml import transformer as T
            model, tok = clf.transformer
            t0 = time.time()
            comps["transformer"] = T.predict_proba(model, tok, texts, clf.max_len, "cpu")
            print(f"transformer {len(texts)} texts in {time.time() - t0:.0f}s", flush=True)
        for i, r in enumerate(todo):
            out[r["id"]] = [round(sum(clf.weights[c] * comps[c][i][j] for c in comps), 4) for j in range(len(LABELS))]
        # parity check against the served single-record path on a few records
        for r in todo[:3]:
            single = clf.predict_record(r, legacy[r["id"]]).probabilities
            assert all(abs(single[lbl] - out[r["id"]][j]) < 2e-3 for j, lbl in enumerate(LABELS)), "batch != served"
        cache.write_text(json.dumps(out))
    return out


def ml_dict(probs: list[float]) -> dict:
    best = max(range(len(LABELS)), key=lambda j: probs[j])
    return {"status": "ok", "label": LABELS[best], "confidence": probs[best],
            "probabilities": dict(zip(LABELS, probs, strict=True)), "source_kind": "evaluation"}


def combined(recs, rules, probs, cfg):
    return {r["id"]: compute(Inputs(detection=rules[r["id"]], ml=ml_dict(probs[r["id"]])), cfg) for r in recs}


def at_least(level: str, minimum: str) -> bool:
    return level in LEVEL_RANK and LEVEL_RANK[level] >= LEVEL_RANK[minimum]


def binary(y: list[str], pred_threat: list[bool]) -> dict:
    rep = binary_report(y, ["phishing" if t else "legitimate" for t in pred_threat])
    th = rep["per_class"]["threat"]
    n_leg = sum(1 for t in y if t not in THREAT)
    fp = sum(1 for t, p in zip(y, pred_threat, strict=True) if p and t not in THREAT)
    return {"precision": th["precision"], "recall": th["recall"], "f1": th["f1"], "support_threat": th["support"],
            "support_legitimate": n_leg, "false_positives": fp,
            "fpr_legitimate": round(fp / n_leg, 4) if n_leg else None}


def per_class_detection(y: list[str], pred_threat: list[bool]) -> dict:
    out = {}
    for lbl in LABELS:
        idx = [i for i, t in enumerate(y) if t == lbl]
        if idx:
            out[lbl] = {"n": len(idx), "flagged_as_threat": sum(pred_threat[i] for i in idx),
                        "rate": round(sum(pred_threat[i] for i in idx) / len(idx), 4)}
    return out


def evaluate(recs, rules, probs, res) -> dict:
    y = [r["label"] for r in recs]
    preds = {
        "rules_suspicious_or_higher": [rules[r["id"]].get("verdict") in ("suspicious", "phishing_fraud_likely")
                                       for r in recs],
        "rules_phishing_fraud_likely": [rules[r["id"]].get("verdict") == "phishing_fraud_likely" for r in recs],
        "ml_argmax_threat": [ml_dict(probs[r["id"]])["label"] != "legitimate" for r in recs],
        "combined_medium_or_higher": [at_least(res[r["id"]]["level"], "medium") for r in recs],
        "combined_high_or_higher": [at_least(res[r["id"]]["level"], "high") for r in recs],
    }
    out = {name: {"threat_vs_legitimate": binary(y, p), "per_class_detection": per_class_detection(y, p)}
           for name, p in preds.items()}
    out["ml_argmax_threat"]["multiclass"] = {
        k: v for k, v in classification_report(y, [ml_dict(probs[r["id"]])["label"] for r in recs]).items()
        if k in ("accuracy", "macro_f1", "per_class")}
    levels = {"legitimate": Counter(), "threat": Counter()}
    for r in recs:
        levels["threat" if r["label"] in THREAT else "legitimate"][res[r["id"]]["level"]] += 1
    out["level_distribution"] = {k: {lvl: v.get(lvl, 0) for lvl in (*LEVELS, "indeterminate")}
                                 for k, v in levels.items()}
    conf = Counter(res[r["id"]]["conflict"] for r in recs if res[r["id"]]["conflict"])
    floors = Counter(f["id"] for r in recs for c in res[r["id"]]["components"] if c["name"] == "hard_evidence"
                     for f in c.get("floors", []))
    out["flags"] = {
        "conflict_total": sum(conf.values()), "conflict_by_kind": dict(conf),
        "conflict_rate": round(sum(conf.values()) / len(recs), 4),
        "conflict_true_label": {k: dict(Counter(("threat" if r["label"] in THREAT else "legitimate")
                                                for r in recs if res[r["id"]]["conflict"] == k)) for k in conf},
        "hard_floor_fired": dict(floors),
        "confidence": dict(Counter(res[r["id"]]["confidence"] for r in recs)),
    }
    dis = [r for r in recs if res[r["id"]]["conflict"]]
    out["disagreement_examples"] = [
        {"id": r["id"], "true_label": r["label"], "rule_verdict": rules[r["id"]].get("verdict"),
         "ml_label": ml_dict(probs[r["id"]])["label"], "combined_level": res[r["id"]]["level"],
         "conflict": res[r["id"]]["conflict"]} for r in sorted(dis, key=lambda r: r["id"])[:12]]
    return out


def derive(val, rules, probs) -> dict:
    """Documented selection rule on VALIDATION only."""
    base = get_config()
    y = [r["label"] for r in val]
    best = None
    for k in range(30, 51):
        t_med = k / 100
        cfg = dataclasses.replace(base, t_med=t_med, t_high=max(base.t_high, t_med + 0.01))
        res = combined(val, rules, probs, cfg)
        f1 = binary(y, [at_least(res[r["id"]]["level"], "medium") for r in val])["f1"]
        if best is None or f1 > best[0] + 1e-9:
            best = (f1, t_med)
    t_med = best[1]
    chosen_high = None
    for k in range(max(50, int(round(t_med * 100)) + 1), 96):
        t_high = k / 100
        cfg = dataclasses.replace(base, t_med=t_med, t_high=t_high)
        res = combined(val, rules, probs, cfg)
        fpr = binary(y, [at_least(res[r["id"]]["level"], "high") for r in val])["fpr_legitimate"]
        if fpr is not None and fpr <= 0.01:
            chosen_high = t_high
            break
    return {"t_med": t_med, "val_f1_at_t_med": best[0], "t_high": chosen_high or 0.95}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data-dir", type=Path, required=True)
    ap.add_argument("--model-dir", type=Path, required=True)
    ap.add_argument("--cache-dir", type=Path, required=True)
    ap.add_argument("--derive", action="store_true")
    a = ap.parse_args()
    a.cache_dir.mkdir(parents=True, exist_ok=True)
    from app.ml.train import rule_detections, validate_dataset
    version, records = validate_dataset(a.data_dir)
    legacy = rule_detections(records, a.data_dir, version["manifest_sha256"])
    val = [r for r in records if r["split"] == "validation"]
    test = [r for r in records if r["split"] == "test"]
    rules = current_rules(val + test, a.data_dir, a.cache_dir / "current_rules.json")
    probs = ml_probs(val + test, legacy, a.model_dir, a.cache_dir / "ml_probs.json")
    if a.derive:
        print(json.dumps(derive(val, rules, probs)))
        return
    cfg = get_config()
    result = {"dataset": {"manifest_sha256": version["manifest_sha256"], "validation": len(val), "test": len(test)},
              "engine": compute(Inputs(), cfg)["engine_version"], "config": cfg.as_dict(), "splits": {}}
    for name, recs in (("validation", val), ("test", test)):
        res = combined(recs, rules, probs, cfg)
        result["splits"][name] = {
            "all": evaluate(recs, rules, probs, res),
            "real_only": evaluate([r for r in recs if not r["is_synthetic"]], rules, probs, res)}
    DOCS.mkdir(parents=True, exist_ok=True)
    (DOCS / "evaluation_v1.json").write_text(json.dumps(result, indent=1, sort_keys=True) + "\n")
    (DOCS / "evaluation_v1.md").write_text(render(result))
    print("written", DOCS / "evaluation_v1.json")


def render(res: dict) -> str:
    lines = ["# Combined risk — offline evaluation v1 (generated)", "",
             "Generated by `backend/scripts/evaluate_risk.py`. Metrics and record IDs only; no email content.",
             f"Dataset manifest `{res['dataset']['manifest_sha256'][:12]}`; validation {res['dataset']['validation']}, "
             f"test {res['dataset']['test']}. Thresholds: `{json.dumps(res['config']['ml_thresholds'])}`.", "",
             "Caveats: old, partly synthetic, source-confounded data; rules run offline (no DNS/auth), so auth-based "
             "rules and the H2 floor cannot fire; no threat-intel runs; the index is not a probability.", ""]
    for split, block in res["splits"].items():
        for subset, ev in block.items():
            lines += [f"## {split} — {subset}", "",
                      "| Method | Precision | Recall | F1 | FP | FPR (legitimate) |", "|---|---:|---:|---:|---:|---:|"]
            for m in ("rules_suspicious_or_higher", "rules_phishing_fraud_likely", "ml_argmax_threat",
                      "combined_medium_or_higher", "combined_high_or_higher"):
                b = ev[m]["threat_vs_legitimate"]
                lines.append(f"| {m} | {b['precision']} | {b['recall']} | {b['f1']} | {b['false_positives']} | "
                             f"{b['fpr_legitimate']} |")
            lines += ["", "Level distribution (legitimate / threat): " + "; ".join(
                f"{lvl} {ev['level_distribution']['legitimate'][lvl]}/{ev['level_distribution']['threat'][lvl]}"
                for lvl in (*LEVELS, "indeterminate")), "",
                f"Conflicts: {ev['flags']['conflict_total']} ({ev['flags']['conflict_rate']:.2%}) "
                f"{json.dumps(ev['flags']['conflict_by_kind'])}; true labels "
                f"{json.dumps(ev['flags']['conflict_true_label'])}. Hard floors: "
                f"{json.dumps(ev['flags']['hard_floor_fired'])}. Confidence: {json.dumps(ev['flags']['confidence'])}.", ""]
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    main()
