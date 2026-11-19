"""SHAP explanations for the AIPISH classifier (R4).

Explained components:
  xgb  shap.TreeExplainer (exact TreeSHAP) over structured, rule and text-SVD
       features; values are in XGBoost's raw margin space for the explained class.
  lr   shap.LinearExplainer with an empty-document background (all-zero TF-IDF),
       so a term's value is its weight times its TF-IDF value in this message.
The DistilRoBERTa component is NOT explained (reported under `not_explained`).

Interpretation: SHAP values show how much each input moved *this model's*
output away from its baseline. They describe associations the model learned,
not causes, and say nothing about intent or ground truth.

Privacy: no raw text, addresses or URLs are returned. Text terms are shown only
when they are common corpus vocabulary (in >= MIN_TERM_DOC_FREQ training
emails, alphabetic, 3-30 chars); every other term and all character n-grams
are summed into aggregate rows. SVD text components are aggregated too.
"""
from __future__ import annotations

import math
import re

from app.ml import features as F
from app.ml.dataset.labels import LABELS

TOP_K = 10
MIN_TERM_DOC_FREQ = 25
_SAFE_TERM = re.compile(r"^(<url>|<email>|[a-z][a-z ]{1,28}[a-z])$")
DISCLAIMER = ("SHAP values quantify how much each feature moved this model's score for the explained "
              "class relative to a baseline. They show which inputs the model relied on, not why the "
              "email was written or whether it is malicious; they are not causal or legal evidence. "
              "The rule-engine findings remain the explainable evidence layer.")


class ExplainUnavailable(Exception):
    pass


def _shap():
    try:
        import shap
    except ImportError as exc:
        raise ExplainUnavailable("SHAP not installed; see requirements-ml.txt") from exc
    return shap


def _round(v: float) -> float:
    return round(float(v), 5)


def _rows(entries: list[dict], top_k: int) -> list[dict]:
    entries = [e for e in entries if e["shap_value"] != 0.0]
    entries.sort(key=lambda e: (-abs(e["shap_value"]), e["feature"]))
    for e in entries:
        e["direction"] = "toward" if e["shap_value"] > 0 else "away"
    return entries[:top_k]


def _structured_display(name: str, value: float):
    if math.isnan(value):
        return None
    return int(value) if float(value).is_integer() else round(float(value), 4)


def explain_xgb(clf, rec: dict, detection: dict, label: str, top_k: int) -> dict:
    shap = _shap()
    import numpy as np
    if label not in clf.xgb_classes:
        raise ExplainUnavailable(f"class {label!r} is not modelled by the XGBoost component")
    k = clf.xgb_classes.index(label)
    X = clf.fz.transform([rec], [detection])
    explainer = shap.TreeExplainer(clf.xgb)
    sv = np.asarray(explainer.shap_values(X))[0, :, k]
    base = float(np.ravel(explainer.expected_value)[k])
    margin = float(clf.xgb.predict(X, output_margin=True)[0][k])
    names = clf.fz.names
    n_struct, n_rule = len(F.STRUCTURED_NAMES), len(F.RULE_FEATURE_NAMES)
    entries, svd_sum = [], 0.0
    for i, (name, v) in enumerate(zip(names, sv, strict=True)):
        if i < n_struct:
            entries.append({"feature": name, "group": "structural",
                            "value": _structured_display(name, X[0, i]), "shap_value": _round(v)})
        elif i < n_struct + n_rule:
            entries.append({"feature": name, "group": "rule_engine",
                            "value": None if math.isnan(X[0, i]) else int(X[0, i]),
                            "shap_value": _round(v)})
        else:
            svd_sum += float(v)
    aggregated = [{"feature": "text_semantic_components", "group": "text",
                   "detail": f"{len(names) - n_struct - n_rule} TF-IDF SVD components, summed",
                   "shap_value": _round(svd_sum)}]
    return {
        "explainer": "shap.TreeExplainer",
        "output_space": "XGBoost raw margin (log-odds before softmax) for the explained class",
        "base_value": _round(base), "output_value": _round(margin),
        "additivity_ok": bool(abs(base + float(sv.sum()) - margin) < 1e-3),
        "top_contributions": _rows(entries, top_k), "aggregated": aggregated,
    }


def explain_lr(clf, rec: dict, label: str, top_k: int) -> dict:
    shap = _shap()
    import numpy as np
    import scipy.sparse as sp
    classes = list(clf.lr.classes_)
    if label not in classes:
        raise ExplainUnavailable(f"class {label!r} is not modelled by the LR component")
    k = classes.index(label)
    tfidf, model = clf.lr.named_steps["tfidf"], clf.lr.named_steps["clf"]
    X = tfidf.transform([F.text_input(rec)])
    explainer = shap.LinearExplainer(model, shap.maskers.Independent(sp.csr_matrix((1, X.shape[1]))))
    sv = np.asarray(explainer.shap_values(X))
    sv = sv[0, :, k] if sv.ndim == 3 else sv[0]
    base = float(np.ravel(explainer.expected_value)[k if np.size(explainer.expected_value) > 1 else 0])
    margin = float(model.decision_function(X)[0][k]) if len(classes) > 2 else float(model.decision_function(X)[0])

    word = tfidf.transformer_list[0][1]
    n_word = len(word.vocabulary_)
    n_train = clf.config["dataset"].get("by_split", {}).get("train")
    names = tfidf.get_feature_names_out()
    entries, hidden_sum, hidden_n, char_sum = [], 0.0, 0, 0.0
    for j in X.nonzero()[1]:
        v = float(sv[j])
        if j >= n_word:
            char_sum += v
            continue
        term = names[j].split("__", 1)[1]
        df = None
        if n_train:
            df = (1 + n_train) / math.exp(word.idf_[j] - 1) - 1
        if _SAFE_TERM.match(term) and df is not None and df >= MIN_TERM_DOC_FREQ:
            entries.append({"feature": f"term:{term}", "group": "text_term", "value": None,
                            "shap_value": _round(v)})
        else:
            hidden_sum += v
            hidden_n += 1
    aggregated = [
        {"feature": "rare_or_unsafe_terms", "group": "text",
         "detail": f"{hidden_n} word features withheld (rare in training data or not plain words), summed",
         "shap_value": _round(hidden_sum)},
        {"feature": "character_ngrams", "group": "text",
         "detail": "character 3-5-gram features, summed", "shap_value": _round(char_sum)},
    ]
    return {
        "explainer": "shap.LinearExplainer",
        "background": "empty document (all-zero TF-IDF vector)",
        "output_space": "LogisticRegression decision value (logit) for the explained class",
        "base_value": _round(base), "output_value": _round(margin),
        "additivity_ok": bool(abs(base + float(sv.sum()) - margin) < 1e-3),
        "top_contributions": _rows(entries, top_k), "aggregated": aggregated,
        "redaction": {"withheld_terms": hidden_n, "min_training_doc_freq": MIN_TERM_DOC_FREQ},
    }


def explain_record(clf, rec: dict, detection: dict, label: str, top_k: int = TOP_K) -> dict:
    shap = _shap()
    comps, not_explained = {}, []
    for name, weight in sorted(clf.weights.items()):
        if weight <= 0:
            continue
        try:
            if name == "xgb":
                comps[name] = explain_xgb(clf, rec, detection, label, top_k)
            elif name == "lr":
                comps[name] = explain_lr(clf, rec, label, top_k)
            else:
                not_explained.append({"component": name, "reason": "SHAP is not implemented for "
                                      "this component; its probability still counts in the ensemble"})
                continue
            comps[name]["ensemble_weight"] = weight
        except ExplainUnavailable as exc:
            not_explained.append({"component": name, "reason": str(exc)})
    if not comps:
        raise ExplainUnavailable("no explainable component for this prediction")
    return {"status": "ok", "method": "SHAP", "shap_version": shap.__version__,
            "explained_label": label, "model_version": clf.version, "components": comps,
            "not_explained": not_explained, "disclaimer": DISCLAIMER}


def explain_raw(raw: bytes, detection: dict | None = None, top_k: int = TOP_K) -> dict:
    """Classify + explain one message. Never fabricates: failures carry no contributions."""
    from app.ml import inference
    from app.ml.dataset.normalize import Excluded

    def fail(status: str, reason: str, **extra) -> dict:
        return {"status": status, "method": "SHAP", "reason": reason, "components": {},
                "not_explained": [], "disclaimer": DISCLAIMER, **extra}

    try:
        _shap()
    except ExplainUnavailable as exc:
        return fail("unavailable", str(exc))
    clf, reason = inference.get_classifier()
    if clf is None:
        return fail("unavailable", reason)
    try:
        rec = F.record_from_raw(raw)
    except Excluded as exc:
        return fail("not_applicable", f"message outside model scope: {exc.reason}",
                    model_version=clf.version)
    detection = detection if detection is not None else F.run_rules_offline(raw)
    try:
        pred = clf.predict_record(rec, detection)
        if pred.label not in LABELS:
            return fail("error", "no prediction to explain", model_version=clf.version)
        return explain_record(clf, rec, detection, pred.label, top_k)
    except ExplainUnavailable as exc:
        return fail("unavailable", str(exc), model_version=clf.version)
    except Exception as exc:
        return fail("error", f"explanation failed: {type(exc).__name__}", model_version=clf.version)
