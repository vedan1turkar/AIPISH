"""Train and evaluate the AIPISH email classifiers on the P2a corpus (R1, R3).

Models (all trained on the TRAIN split only):
  lr           scikit-learn Pipeline: word + char TF-IDF -> LogisticRegression
  xgb          XGBoost over [18 structured features | 18 rule contributions + rule
               score | 100-d TruncatedSVD of the word TF-IDF]  (sklearn preprocessing)
  transformer  DistilRoBERTa fine-tuned for sequence classification
  ensemble     weighted average of the three; weights picked on VALIDATION
Baseline for comparison: the existing 18-rule engine (unchanged).

Validation is used only for model selection (best epoch, XGBoost early
stopping, ensemble weights). Test is touched once, for the final report.

Usage: python -m app.ml.train [--skip-transformer] [--epochs N] [--max-len N]
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import io
import json
import platform
import time
from collections import Counter
from pathlib import Path

from app.ml import features as F
from app.ml.featurizer import XgbFeaturizer, build_text_vectorizers  # noqa: F401 (pickle-stable home)
from app.ml.dataset.labels import LABEL_MAP, LABELS
from app.ml.dataset.split import SPLITS
from app.ml.metrics import binary_report, classification_report

REPO = Path(__file__).resolve().parents[3]
DATA_DIR = REPO / "data"
MODEL_ROOT = REPO / "models"
MODEL_NAME = "aipish-email-v1"
REPORT_DIR = REPO / "docs" / "ml"
SEED = 20261119

DEFAULT_CONFIG = {
    "seed": SEED,
    "lr": {"word_ngrams": [1, 2], "word_max_features": 50000, "char_ngrams": [3, 5],
           "char_max_features": 50000, "min_df": 2, "C": 4.0, "max_iter": 3000},
    "svd_components": 100,
    "xgb": {"n_estimators": 600, "max_depth": 6, "learning_rate": 0.08, "subsample": 0.8,
            "colsample_bytree": 0.8, "min_child_weight": 1.0, "reg_lambda": 1.0,
            "early_stopping_rounds": 40, "tree_method": "hist", "n_jobs": 4},
    "transformer": {"base_model": "distilroberta-base", "max_len": 256, "epochs": 3,
                    "batch_size": 16, "lr": 3e-5, "weight_decay": 0.01, "warmup_ratio": 0.06},
    "ensemble_grid_step": 0.25,
}


# ── dataset validation ────────────────────────────────────────────────────

class DatasetError(RuntimeError):
    pass


def validate_dataset(data_dir: Path = DATA_DIR) -> tuple[dict, list[dict]]:
    """Check manifest <-> stats <-> processed records before any training."""
    manifest_text = (data_dir / "manifest" / "manifest.csv").read_text()
    stats = json.loads((data_dir / "manifest" / "stats.json").read_text())
    digest = hashlib.sha256(manifest_text.encode()).hexdigest()
    if digest != stats["manifest_sha256"]:
        raise DatasetError("manifest.csv does not match stats.json (rebuild the dataset)")
    rows = {r["id"]: r for r in csv.DictReader(io.StringIO(manifest_text))}
    proc_path = data_dir / "processed" / "emails.jsonl"
    if not proc_path.exists():
        raise DatasetError(f"{proc_path} missing: run python -m app.ml.dataset.build")
    records = [json.loads(line) for line in proc_path.open()]
    if {r["id"] for r in records} != set(rows):
        raise DatasetError("processed records and manifest ids differ")
    for r in records:
        m = rows[r["id"]]
        if (r["label"], r["split"]) != (m["label"], m["split"]):
            raise DatasetError(f"{r['id']}: label/split differs from manifest")
        if r["label"] not in LABELS or LABEL_MAP[(r["source"], r["original_label"])][0] != r["label"]:
            raise DatasetError(f"{r['id']}: invalid label mapping")
        if r["split"] not in SPLITS:
            raise DatasetError(f"{r['id']}: invalid split")
    for key in ("group_id", "near_dup_cluster", "norm_sha256"):
        seen: dict[str, set] = {}
        for r in records:
            seen.setdefault(r[key], set()).add(r["split"])
        if any(len(v) > 1 for v in seen.values()):
            raise DatasetError(f"leakage: {key} spans splits")
    version = {"manifest_sha256": digest, "total": len(records),
               "by_split": {s: sum(r["split"] == s for r in records) for s in SPLITS}}
    return version, records


# ── rule-engine features (cached) ─────────────────────────────────────────

def rule_detections(records: list[dict], data_dir: Path, manifest_sha: str, log=print) -> dict[str, dict]:
    cache = data_dir / "processed" / "rule_detections.jsonl"
    if cache.exists():
        first = json.loads(cache.open().readline())
        if first.get("manifest_sha256") == manifest_sha:
            return {d["id"]: d["detection"] for d in map(json.loads, cache.open()) if "id" in d}
    from app.ml.dataset.build import collect
    wanted = {r["id"] for r in records}
    raws = {}
    for rm in collect(data_dir / "raw", include_real=True):
        rid = f"{rm.source}-{hashlib.sha256(rm.raw).hexdigest()[:16]}"
        if rid in wanted:
            raws[rid] = rm.raw
    missing = wanted - set(raws)
    if missing:
        raise DatasetError(f"{len(missing)} raw messages not found locally (re-run acquire)")
    t0, out = time.time(), {}
    for i, rid in enumerate(sorted(wanted)):
        out[rid] = F.run_rules_offline(raws[rid])
        if i % 2000 == 0:
            log(f"rules {i}/{len(wanted)}")
    with cache.open("w") as f:
        f.write(json.dumps({"manifest_sha256": manifest_sha}) + "\n")
        for rid in sorted(out):
            f.write(json.dumps({"id": rid, "detection": out[rid]}, sort_keys=True) + "\n")
    log(f"rules done in {time.time() - t0:.0f}s")
    return out


# ── classical models ──────────────────────────────────────────────────────

def _class_index(trained: list[str]) -> dict[str, int]:
    return {lbl: i for i, lbl in enumerate(trained)}


def _expand(probs, trained: list[str]) -> list[list[float]]:
    """Map model columns (trained classes only) onto the full 5-class layout."""
    pos = [LABELS.index(lbl) for lbl in trained]
    out = []
    for row in probs:
        full = [0.0] * len(LABELS)
        for j, p in zip(pos, row, strict=True):
            full[j] = float(p)
        out.append(full)
    return out


def balanced_weights(labels: list[str]) -> dict[str, float]:
    c = Counter(labels)
    return {lbl: len(labels) / (len(c) * n) for lbl, n in c.items()}


def train_lr(texts: list[str], labels: list[str], cfg: dict):
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import FeatureUnion, Pipeline
    word, char = build_text_vectorizers(cfg)
    pipe = Pipeline([
        ("tfidf", FeatureUnion([("word", word), ("char", char)])),
        ("clf", LogisticRegression(C=cfg["lr"]["C"], max_iter=cfg["lr"]["max_iter"],
                                   class_weight="balanced", random_state=cfg["seed"])),
    ])
    pipe.fit(texts, labels)
    return pipe


def train_xgb(train_X, train_y: list[str], val_X, val_y: list[str], cfg: dict):
    from xgboost import XGBClassifier
    trained = [lbl for lbl in LABELS if lbl in set(train_y)]
    idx = _class_index(trained)
    w = balanced_weights(train_y)
    xc = dict(cfg["xgb"])
    model = XGBClassifier(objective="multi:softprob", eval_metric="mlogloss",
                          random_state=cfg["seed"], **xc)
    keep = [i for i, y in enumerate(val_y) if y in idx]  # val rows of untrained classes cannot score
    model.fit(train_X, [idx[y] for y in train_y], sample_weight=[w[y] for y in train_y],
              eval_set=[(val_X[keep], [idx[val_y[i]] for i in keep])], verbose=False)
    return model, trained


# ── evaluation ────────────────────────────────────────────────────────────

def argmax_labels(probs: list[list[float]]) -> list[str]:
    return [LABELS[max(range(len(LABELS)), key=lambda j: p[j])] for p in probs]


def rules_binary_pred(detections: list[dict], strict: bool) -> list[str]:
    """Rule verdict as a binary threat call (the engine has no 5-class output)."""
    threat = {"phishing_fraud_likely"} if strict else {"phishing_fraud_likely", "suspicious"}
    # engine error -> no threat verdict was produced; counted as a miss (reported separately)
    return ["phishing" if d.get("verdict") in threat else "legitimate" for d in detections]


def subsets(recs: list[dict]) -> dict[str, list[int]]:
    return {
        "all": list(range(len(recs))),
        "real_only": [i for i, r in enumerate(recs) if not r["is_synthetic"]],
        "synthetic_only": [i for i, r in enumerate(recs) if r["is_synthetic"]],
        "sender_disjoint": [i for i, r in enumerate(recs) if not r["sender_seen_in_train"]],
    }


def evaluate_split(recs: list[dict], preds: dict[str, list[str]]) -> dict:
    y = [r["label"] for r in recs]
    out = {}
    for name, idx in subsets(recs).items():
        if not idx:
            continue
        yt = [y[i] for i in idx]
        out[name] = {}
        for model, p in preds.items():
            pp = [p[i] for i in idx]
            entry = {"binary_threat": binary_report(yt, pp)}
            if not model.startswith("rules"):
                entry["multiclass"] = classification_report(yt, pp)
            out[name][model] = entry
    return out


def ensemble_probs(components: dict[str, list[list[float]]], weights: dict[str, float]):
    names = [n for n, w in weights.items() if w > 0]
    n = len(next(iter(components.values())))
    return [[sum(weights[c] * components[c][i][j] for c in names) for j in range(len(LABELS))]
            for i in range(n)]


def pick_ensemble_weights(val_components: dict[str, list[list[float]]], val_y: list[str],
                          step: float) -> tuple[dict[str, float], float]:
    names = sorted(val_components)
    ticks = [round(i * step, 4) for i in range(int(round(1 / step)) + 1)]
    best = (-1.0, None)
    combos = []
    if len(names) == 1:
        combos = [{names[0]: 1.0}]
    else:
        def rec(prefix, remaining, k):
            if k == len(names) - 1:
                combos.append(dict(zip(names, prefix + [round(remaining, 4)], strict=True)))
                return
            for t in ticks:
                if t <= remaining + 1e-9:
                    rec(prefix + [t], remaining - t, k + 1)
        rec([], 1.0, 0)
    for wts in combos:
        f1 = classification_report(val_y, argmax_labels(ensemble_probs(val_components, wts)))["macro_f1"]
        if f1 > best[0] + 1e-12:
            best = (f1, wts)
    return best[1], best[0]


# ── main ──────────────────────────────────────────────────────────────────

def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--skip-transformer", action="store_true")
    ap.add_argument("--epochs", type=int)
    ap.add_argument("--max-len", type=int)
    ap.add_argument("--device", default="auto")
    args = ap.parse_args(argv)

    import joblib
    import numpy as np
    import sklearn
    import xgboost

    cfg = json.loads(json.dumps(DEFAULT_CONFIG))
    if args.epochs:
        cfg["transformer"]["epochs"] = args.epochs
    if args.max_len:
        cfg["transformer"]["max_len"] = args.max_len
    out_dir = MODEL_ROOT / MODEL_NAME
    out_dir.mkdir(parents=True, exist_ok=True)
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    log_lines: list[str] = []

    def log(msg: str) -> None:
        line = f"[{dt.datetime.now().strftime('%H:%M:%S')}] {msg}"
        print(line, flush=True)
        log_lines.append(line)

    version, records = validate_dataset()
    log(f"dataset ok: {version}")
    dets = rule_detections(records, DATA_DIR, version["manifest_sha256"], log)
    errs = Counter(d["error"].split(":")[0] for d in dets.values() if "error" in d)
    log(f"rule engine errors: {sum(errs.values())} {dict(errs)}")
    split = {s: [r for r in records if r["split"] == s] for s in SPLITS}
    sdet = {s: [dets[r["id"]] for r in split[s]] for s in SPLITS}
    texts = {s: [F.text_input(r) for r in split[s]] for s in SPLITS}
    ys = {s: [r["label"] for r in split[s]] for s in SPLITS}
    trained_classes = [lbl for lbl in LABELS if lbl in set(ys["train"])]
    log(f"train class counts: {dict(Counter(ys['train']))}")

    probs: dict[str, dict[str, list[list[float]]]] = {s: {} for s in ("validation", "test")}
    timings = {}

    t0 = time.time()
    lr = train_lr(texts["train"], ys["train"], cfg)
    timings["lr_train_s"] = round(time.time() - t0, 1)
    for s in probs:
        probs[s]["lr"] = _expand(lr.predict_proba(texts[s]), list(lr.classes_))
    joblib.dump(lr, out_dir / "lr_pipeline.joblib")
    log(f"lr trained in {timings['lr_train_s']}s")

    t0 = time.time()
    fz = XgbFeaturizer(cfg).fit(split["train"], sdet["train"])
    X = {s: fz.transform(split[s], sdet[s]) for s in SPLITS}
    xgb, xgb_classes = train_xgb(X["train"], ys["train"], X["validation"], ys["validation"], cfg)
    timings["xgb_train_s"] = round(time.time() - t0, 1)
    for s in probs:
        probs[s]["xgb"] = _expand(xgb.predict_proba(X[s]), xgb_classes)
    joblib.dump(fz, out_dir / "xgb_featurizer.joblib")
    xgb.save_model(out_dir / "xgb_model.json")
    log(f"xgb trained in {timings['xgb_train_s']}s (best_iteration={xgb.best_iteration})")

    transformer_info = None
    if not args.skip_transformer:
        from app.ml import transformer as T
        tc = cfg["transformer"]
        device = T.pick_device(args.device)
        counts = Counter(ys["train"])
        cw = [len(ys["train"]) / (len(counts) * counts[lbl]) if counts.get(lbl) else 0.0 for lbl in LABELS]
        y_idx = {lbl: i for i, lbl in enumerate(LABELS)}

        def sel(val_probs):
            return classification_report(ys["validation"], argmax_labels(val_probs))["macro_f1"]

        t0 = time.time()
        info = T.fine_tune(texts["train"], [y_idx[y] for y in ys["train"]], texts["validation"],
                           [y_idx[y] for y in ys["validation"]], out_dir / "transformer",
                           seed=cfg["seed"], max_len=tc["max_len"], epochs=tc["epochs"],
                           batch_size=tc["batch_size"], lr=tc["lr"], weight_decay=tc["weight_decay"],
                           warmup_ratio=tc["warmup_ratio"], class_weights=cw, device=device,
                           select_metric=sel, log=log)
        timings["transformer_train_s"] = round(time.time() - t0, 1)
        model, tok = T.load(out_dir / "transformer", device)
        for s in probs:
            probs[s]["transformer"] = T.predict_proba(model, tok, texts[s], tc["max_len"], device)
        from huggingface_hub import model_info
        try:
            base_rev = model_info(tc["base_model"]).sha
        except Exception:  # offline after first download
            base_rev = None
        transformer_info = {**info, "device": device, "base_model_revision": base_rev}
        log(f"transformer trained in {timings['transformer_train_s']}s; best epoch {info['best_epoch']}")

    weights, val_f1 = pick_ensemble_weights(probs["validation"], ys["validation"], cfg["ensemble_grid_step"])
    log(f"ensemble weights {weights} (val macro-F1 {val_f1})")
    for s in probs:
        probs[s]["ensemble"] = ensemble_probs(probs[s], weights)

    results = {}
    for s in ("validation", "test"):
        preds = {m: argmax_labels(p) for m, p in probs[s].items()}
        preds["rules_suspicious_or_higher"] = rules_binary_pred(sdet[s], strict=False)
        preds["rules_phishing_fraud_likely"] = rules_binary_pred(sdet[s], strict=True)
        results[s] = evaluate_split(split[s], preds)
        results[s]["rule_engine_errors"] = sum("error" in d for d in sdet[s])

    import torch
    import transformers
    config = {
        "model_name": MODEL_NAME,
        "created_utc": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "dataset": version,
        "labels": list(LABELS),
        "trained_classes": trained_classes,
        "untrained_classes": [lbl for lbl in LABELS if lbl not in trained_classes],
        "config": cfg,
        "components": sorted(probs["validation"]),
        "ensemble_weights": weights,
        "ensemble_val_macro_f1": val_f1,
        "xgb": {"classes": xgb_classes, "best_iteration": int(xgb.best_iteration),
                "feature_names": fz.names},
        "transformer": transformer_info,
        "timings": timings,
        "environment": {"python": platform.python_version(), "platform": platform.platform(),
                        "numpy": np.__version__, "scikit_learn": sklearn.__version__,
                        "xgboost": xgboost.__version__, "torch": torch.__version__,
                        "transformers": transformers.__version__},
    }
    (out_dir / "model_config.json").write_text(json.dumps(config, indent=2) + "\n")
    report = {"model": {k: config[k] for k in ("model_name", "created_utc", "dataset", "labels",
                                               "trained_classes", "untrained_classes", "config",
                                               "components", "ensemble_weights",
                                               "ensemble_val_macro_f1", "transformer", "timings",
                                               "environment")},
              "xgb_best_iteration": int(xgb.best_iteration), "results": results}
    (REPORT_DIR / "evaluation_v1.json").write_text(json.dumps(report, indent=2) + "\n")
    (REPORT_DIR / "training_log_v1.txt").write_text("\n".join(log_lines) + "\n")
    log("wrote model_config.json and docs/ml/evaluation_v1.json")


if __name__ == "__main__":
    main()
