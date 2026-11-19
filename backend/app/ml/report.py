"""Render docs/ml/evaluation_v1.json as Markdown tables (docs/ml/EVALUATION_v1.md).

Usage: python -m app.ml.report
"""
from __future__ import annotations

import json
from pathlib import Path

from app.ml.train import REPORT_DIR

MODELS = ("ensemble", "transformer", "xgb", "lr", "rules_suspicious_or_higher",
          "rules_phishing_fraud_likely")
SUBSETS = ("all", "real_only", "synthetic_only", "sender_disjoint")


def _f(v) -> str:
    return "–" if v is None else f"{v:.3f}"


def render(report: dict) -> str:
    m = report["model"]
    out = [f"# {m['model_name']} — evaluation", "",
           "Generated from `evaluation_v1.json` by `python -m app.ml.report`. Do not edit by hand.", "",
           f"- Dataset manifest SHA-256: `{m['dataset']['manifest_sha256']}`; split sizes "
           f"{m['dataset']['by_split']}",
           f"- Trained classes: {', '.join(m['trained_classes'])}; **untrained: "
           f"{', '.join(m['untrained_classes']) or 'none'}**",
           f"- Ensemble weights (picked on validation): {m['ensemble_weights']} "
           f"(validation macro-F1 {m['ensemble_val_macro_f1']})",
           f"- Seed {m['config']['seed']}; environment {m['environment']}", ""]
    for split in ("test", "validation"):
        res = report["results"][split]
        out += [f"## {split.capitalize()} split", "",
                f"Rule-engine errors on this split: {res.get('rule_engine_errors', 0)}.", "",
                "### Binary: threat (any non-legitimate class) vs legitimate", "",
                "| Subset | Model | n | Precision | Recall | F1 |", "|---|---|---|---|---|---|"]
        for sub in SUBSETS:
            for model in MODELS:
                e = res.get(sub, {}).get(model)
                if not e:
                    continue
                b = e["binary_threat"]
                t = b["per_class"]["threat"]
                out.append(f"| {sub} | {model} | {b['n']} | {_f(t['precision'])} | {_f(t['recall'])} "
                           f"| {_f(t['f1'])} |")
        out += ["", "### Five-class (ML models only; the rule engine has no 5-class output)", "",
                "| Subset | Model | macro-P | macro-R | macro-F1 | " + " | ".join(
                    f"F1 {lbl}" for lbl in res["all"]["ensemble"]["multiclass"]["labels"]) + " |",
                "|---" * 10 + "|"]
        for sub in SUBSETS:
            for model in MODELS:
                e = res.get(sub, {}).get(model)
                if not e or "multiclass" not in e:
                    continue
                mc = e["multiclass"]
                out.append(f"| {sub} | {model} | {_f(mc['macro_precision'])} | {_f(mc['macro_recall'])} "
                           f"| {_f(mc['macro_f1'])} | " + " | ".join(
                               _f(mc["per_class"][lbl]["f1"]) for lbl in mc["labels"]) + " |")
        cm = res["all"]["ensemble"]["multiclass"]
        out += ["", "### Ensemble confusion matrix (all; rows = true, columns = predicted)", "",
                "| true \\ pred | " + " | ".join(cm["labels"]) + " | support |", "|---" * 7 + "|"]
        for lbl, row in zip(cm["labels"], cm["confusion_matrix"], strict=True):
            out.append(f"| {lbl} | " + " | ".join(map(str, row)) + f" | {sum(row)} |")
        out.append("")
    return "\n".join(out)


def main() -> None:
    report = json.loads((REPORT_DIR / "evaluation_v1.json").read_text())
    Path(REPORT_DIR / "EVALUATION_v1.md").write_text(render(report) + "\n")
    print(f"wrote {REPORT_DIR / 'EVALUATION_v1.md'}")


if __name__ == "__main__":
    main()
