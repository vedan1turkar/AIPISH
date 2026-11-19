"""Post-hoc evaluation of the saved aipish-email-v1 artifacts (no retraining).

Scores every component, the ensemble and the 18-rule baseline on train,
validation and test (train only for the overfitting check), audits leakage,
checks the documented parser-failure behaviour, and saves the tracked copies
of the model/tokenizer configuration.

Usage: python -m app.ml.evaluate
Writes docs/ml/final_evaluation_v1.json, docs/ml/FINAL_EVALUATION_v1.md,
docs/ml/model_config_v1.json, docs/ml/tokenizer_config_v1.json.
"""
from __future__ import annotations

import hashlib
import json
import math
import time
from collections import Counter
from pathlib import Path

from app.ml import features as F
from app.ml.dataset.labels import LABELS
from app.ml.dataset.split import SPLITS
from app.ml.metrics import binary_report, classification_report
from app.ml.train import (DATA_DIR, MODEL_NAME, MODEL_ROOT, REPORT_DIR, _expand, argmax_labels,
                          ensemble_probs, rule_detections, rules_binary_pred, subsets, validate_dataset)

MODELS = ("transformer", "xgb", "lr", "ensemble")
RULES = ("rules_suspicious_or_higher", "rules_phishing_fraud_likely")


def class_inventory(records: list[dict]) -> dict:
    inv = {}
    for s in SPLITS:
        rows = [r for r in records if r["split"] == s]
        inv[s] = {lbl: {"total": sum(r["label"] == lbl for r in rows),
                        "real": sum(r["label"] == lbl and not r["is_synthetic"] for r in rows),
                        "synthetic": sum(r["label"] == lbl and r["is_synthetic"] for r in rows)}
                  for lbl in LABELS}
    train = inv["train"]
    return {
        "counts": inv,
        "zero_sample_classes": [lbl for lbl in LABELS if all(inv[s][lbl]["total"] == 0 for s in SPLITS)],
        "synthetic_only_training_classes": [lbl for lbl in LABELS if train[lbl]["total"] > 0
                                            and train[lbl]["real"] == 0],
        "real_training_classes": [lbl for lbl in LABELS if train[lbl]["real"] > 0],
    }


def leakage_audit(records: list[dict], cfg: dict, manifest_sha: str) -> dict:
    by = {s: [r for r in records if r["split"] == s] for s in SPLITS}
    checks = {}
    for key in ("id", "norm_sha256", "near_dup_cluster", "group_id"):
        sets = {s: {r[key] for r in by[s]} for s in SPLITS}
        checks[f"{key}_overlap"] = {f"{a}&{b}": len(sets[a] & sets[b])
                                    for i, a in enumerate(SPLITS) for b in SPLITS[i + 1:]}
    thread = {s: {m for r in by[s] for m in ([r["message_id"]] if r["message_id"] else []) + r["thread_refs"]}
              for s in SPLITS}
    checks["thread_overlap"] = {f"{a}&{b}": len(thread[a] & thread[b])
                                for i, a in enumerate(SPLITS) for b in SPLITS[i + 1:]}
    src = (Path(__file__).parent / "train.py").read_text()
    main_src = src[src.index("def main("):]
    static = {
        "lr_fit_on_train_only": 'train_lr(texts["train"], ys["train"], cfg)' in main_src,
        "featurizer_fit_on_train_only": 'XgbFeaturizer(cfg).fit(split["train"], sdet["train"])' in main_src,
        "xgb_fit_on_train_val_for_early_stopping_only":
            'train_xgb(X["train"], ys["train"], X["validation"], ys["validation"], cfg)' in main_src,
        "transformer_fit_on_train_val_for_epoch_selection_only": 'fine_tune(texts["train"]' in main_src,
        "ensemble_weights_from_validation_only":
            'pick_ensemble_weights(probs["validation"], ys["validation"]' in main_src,
        "test_not_used_before_weights_fixed":
            main_src.index("pick_ensemble_weights(") < main_src.index('results[s] = evaluate_split'),
    }
    all_zero = all(v == 0 for c in checks.values() for v in c.values())
    return {"manifest_sha256_matches_model": cfg["dataset"]["manifest_sha256"] == manifest_sha,
            "split_sizes_match_model": cfg["dataset"]["by_split"] == {s: len(by[s]) for s in SPLITS},
            "overlaps": checks, "all_overlaps_zero": all_zero, "code_audit": static,
            "passed": all_zero and all(static.values())
            and cfg["dataset"]["manifest_sha256"] == manifest_sha}


def parser_failure_check(records: list[dict], dets: dict, clf) -> dict:
    failed = [rid for rid, d in dets.items() if "error" in d]
    out = {"count": len(failed), "cases": []}
    by_id = {r["id"]: r for r in records}
    for rid in failed:
        d, rec = dets[rid], by_id[rid]
        feats = F.rule_features(d)
        pred = clf.predict_record(rec, d)
        out["cases"].append({
            "id": rid, "split": rec["split"], "source": rec["source"], "label": rec["label"],
            "error_type": d["error"].split(":")[0],
            "rule_features_all_nan": all(math.isnan(v) for v in feats),
            "rule_engine_verdict": d.get("verdict"),
            "rules_baseline_binary_prediction": rules_binary_pred([d], strict=False)[0],
            "ml_status": pred.status, "ml_label": pred.label,
        })
    return out


def _fmt(v) -> str:
    return "–" if v is None else f"{v:.3f}"


def render(rep: dict) -> str:
    inv = rep["classes"]
    L = list(LABELS)
    o = ["# aipish-email-v1 — final P2b evaluation (post-hoc, saved artifacts)", "",
         "Generated by `python -m app.ml.evaluate`; do not edit by hand. Train-split rows exist only for the "
         "overfitting check (models were fitted on them).", "",
         f"- Model: `{rep['model']['version']}`; ensemble weights {rep['model']['ensemble_weights']}; "
         f"seed {rep['model']['seed']}",
         f"- Dataset manifest SHA-256: `{rep['model']['manifest_sha256']}`",
         f"- **Zero-sample classes:** {', '.join(inv['zero_sample_classes']) or 'none'} (never predicted).",
         f"- **Classes trained on synthetic data only:** {', '.join(inv['synthetic_only_training_classes'])}.",
         "", "## Sample counts (total / real / synthetic)", "",
         "| Split | " + " | ".join(L) + " |", "|---" * (len(L) + 1) + "|"]
    for s in SPLITS:
        o.append(f"| {s} | " + " | ".join(
            f"{inv['counts'][s][x]['total']} / {inv['counts'][s][x]['real']} / {inv['counts'][s][x]['synthetic']}"
            for x in L) + " |")
    for s in SPLITS:
        o += ["", f"## {s.capitalize()} split — five-class", "",
              "| Subset | Model | n | macro-P | macro-R | macro-F1 | weighted-F1 | " +
              " | ".join(f"F1 {x}" for x in L) + " |", "|---" * (7 + len(L)) + "|"]
        for sub, models in rep["results"][s].items():
            for m in MODELS:
                if m not in models:
                    continue
                mc = models[m]["multiclass"]
                o.append(f"| {sub} | {m} | {mc['n']} | {_fmt(mc['macro_precision'])} | "
                         f"{_fmt(mc['macro_recall'])} | {_fmt(mc['macro_f1'])} | {_fmt(mc['weighted_f1'])} | "
                         + " | ".join(_fmt(mc["per_class"][x]["f1"]) for x in L) + " |")
        o += ["", f"### {s.capitalize()} — threat vs legitimate (all models incl. 18-rule baseline)", "",
              "| Subset | Model | Precision | Recall | F1 |", "|---|---|---|---|---|"]
        for sub, models in rep["results"][s].items():
            for m in MODELS + RULES:
                if m in models:
                    t = models[m]["binary_threat"]["per_class"]["threat"]
                    o.append(f"| {sub} | {m} | {_fmt(t['precision'])} | {_fmt(t['recall'])} | {_fmt(t['f1'])} |")
        if s != "train":
            for m in MODELS:
                mc = rep["results"][s]["all"][m]["multiclass"]
                o += ["", f"Confusion matrix — {s}, {m} (rows = true, columns = predicted)", "",
                      "| true \\ pred | " + " | ".join(L) + " | support |", "|---" * (len(L) + 2) + "|"]
                for lbl, row in zip(L, mc["confusion_matrix"], strict=True):
                    o.append(f"| {lbl} | " + " | ".join(map(str, row)) + f" | {sum(row)} |")
    ov = rep["overfitting"]
    o += ["", "## Overfitting check (macro-F1, all messages)", "",
          "| Model | train | validation | test | train−val gap |", "|---|---|---|---|---|"]
    for m, v in ov["macro_f1"].items():
        o.append(f"| {m} | {_fmt(v['train'])} | {_fmt(v['validation'])} | {_fmt(v['test'])} | "
                 f"{_fmt(v['train'] - v['validation'])} |")
    o += ["", "DistilRoBERTa epochs: " + "; ".join(
        f"epoch {h['epoch']}: train loss {h['train_loss']}, val macro-F1 {h['val_macro_f1']}"
        for h in ov["transformer_history"]), ""]
    la = rep["leakage_audit"]
    o += ["## Leakage audit", "", f"Passed: **{la['passed']}**. Manifest hash matches model: "
          f"{la['manifest_sha256_matches_model']}; split sizes match: {la['split_sizes_match_model']}.", ""]
    for k, v in la["overlaps"].items():
        o.append(f"- {k}: {v}")
    for k, v in la["code_audit"].items():
        o.append(f"- {k}: {v}")
    pf = rep["parser_failures"]
    o += ["", "## Parser failure check", "", f"Rule-engine failures in corpus: {pf['count']}.", ""]
    for c in pf["cases"]:
        o.append(f"- `{c['id']}` ({c['split']}, {c['source']}, {c['label']}): {c['error_type']}; rule features "
                 f"all NaN = {c['rule_features_all_nan']}; rule verdict = {c['rule_engine_verdict']}; rules "
                 f"baseline counts it as `{c['rules_baseline_binary_prediction']}` (no verdict = miss); ML still "
                 f"classifies: status {c['ml_status']}, label {c['ml_label']}.")
    return "\n".join(o) + "\n"


def main() -> None:
    from app.ml import inference
    from app.ml import transformer as T

    t0 = time.time()
    model_dir = MODEL_ROOT / MODEL_NAME
    version, records = validate_dataset()
    dets = rule_detections(records, DATA_DIR, version["manifest_sha256"])
    clf = inference.EmailClassifier(model_dir)
    cfg = clf.config
    split = {s: [r for r in records if r["split"] == s] for s in SPLITS}
    results, macro = {}, {m: {} for m in MODELS}
    for s in SPLITS:
        recs, sd = split[s], [dets[r["id"]] for r in split[s]]
        texts = [F.text_input(r) for r in recs]
        probs = {"lr": _expand(clf.lr.predict_proba(texts), list(clf.lr.classes_)),
                 "xgb": _expand(clf.xgb.predict_proba(clf.fz.transform(recs, sd)), clf.xgb_classes)}
        model, tok = clf.transformer
        probs["transformer"] = T.predict_proba(model, tok, texts, clf.max_len, "cpu", batch_size=16)
        probs["ensemble"] = ensemble_probs(probs, clf.weights)
        preds = {m: argmax_labels(p) for m, p in probs.items()}
        preds[RULES[0]] = rules_binary_pred(sd, strict=False)
        preds[RULES[1]] = rules_binary_pred(sd, strict=True)
        y = [r["label"] for r in recs]
        results[s] = {}
        for sub, idx in subsets(recs).items():
            if not idx:
                continue
            yt = [y[i] for i in idx]
            results[s][sub] = {}
            for m, p in preds.items():
                pp = [p[i] for i in idx]
                e = {"binary_threat": binary_report(yt, pp)}
                if m in MODELS:
                    e["multiclass"] = classification_report(yt, pp)
                results[s][sub][m] = e
        for m in MODELS:
            macro[m][s] = results[s]["all"][m]["multiclass"]["macro_f1"]
        print(f"{s}: done ({time.time() - t0:.0f}s)", flush=True)

    manifest_sha = hashlib.sha256((DATA_DIR / "manifest" / "manifest.csv").read_bytes()).hexdigest()
    artifacts = {str(p.relative_to(model_dir)): hashlib.sha256(p.read_bytes()).hexdigest()
                 for p in sorted(model_dir.rglob("*")) if p.is_file()}
    report = {
        "model": {"version": clf.version, "ensemble_weights": clf.weights, "seed": cfg["config"]["seed"],
                  "manifest_sha256": cfg["dataset"]["manifest_sha256"], "artifact_sha256": artifacts},
        "classes": class_inventory(records),
        "results": results,
        "overfitting": {"macro_f1": macro, "transformer_history": cfg["transformer"]["history"],
                        "xgb_best_iteration": cfg["xgb"]["best_iteration"]},
        "leakage_audit": leakage_audit(records, cfg, manifest_sha),
        "parser_failures": parser_failure_check(records, dets, clf),
    }
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    (REPORT_DIR / "final_evaluation_v1.json").write_text(json.dumps(report, indent=2) + "\n")
    (REPORT_DIR / "FINAL_EVALUATION_v1.md").write_text(render(report))
    (REPORT_DIR / "model_config_v1.json").write_text(json.dumps(cfg, indent=2) + "\n")
    tdir = model_dir / "transformer"
    tok_cfg = {name: json.loads((tdir / name).read_text())
               for name in ("tokenizer_config.json", "special_tokens_map.json", "config.json")}
    (REPORT_DIR / "tokenizer_config_v1.json").write_text(json.dumps(tok_cfg, indent=2) + "\n")
    print(json.dumps({"macro_f1": macro, "leakage_passed": report["leakage_audit"]["passed"],
                      "parser_failures": report["parser_failures"]}, indent=1))


if __name__ == "__main__":
    main()
