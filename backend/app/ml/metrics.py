"""Evaluation metrics over the fixed five-class taxonomy (pure Python, no sklearn needed)."""
from __future__ import annotations

from app.ml.dataset.labels import LABELS

THREAT = frozenset(LABELS) - {"legitimate"}


def confusion(y_true: list[str], y_pred: list[str], labels: tuple[str, ...] = LABELS) -> list[list[int]]:
    """Rows = true label, columns = predicted label (in `labels` order)."""
    idx = {lbl: i for i, lbl in enumerate(labels)}
    m = [[0] * len(labels) for _ in labels]
    for t, p in zip(y_true, y_pred, strict=True):
        m[idx[t]][idx[p]] += 1
    return m


def classification_report(y_true: list[str], y_pred: list[str],
                          labels: tuple[str, ...] = LABELS) -> dict:
    """Per-class precision/recall/F1/support, macro over classes with support > 0.

    A class with zero support is reported with null metrics and excluded from
    the macro average (it cannot be evaluated), never counted as perfect.
    """
    cm = confusion(y_true, y_pred, labels)
    per = {}
    for i, lbl in enumerate(labels):
        tp = cm[i][i]
        support = sum(cm[i])
        predicted = sum(row[i] for row in cm)
        if support == 0:
            per[lbl] = {"precision": None, "recall": None, "f1": None, "support": 0,
                        "predicted": predicted}
            continue
        prec = tp / predicted if predicted else 0.0
        rec = tp / support
        f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
        per[lbl] = {"precision": round(prec, 4), "recall": round(rec, 4), "f1": round(f1, 4),
                    "support": support, "predicted": predicted}
    evaluated = [lbl for lbl in labels if per[lbl]["support"] > 0]
    n = len(y_true)

    def macro(key: str) -> float | None:
        return round(sum(per[lbl][key] for lbl in evaluated) / len(evaluated), 4) if evaluated else None

    return {
        "n": n,
        "accuracy": round(sum(cm[i][i] for i in range(len(labels))) / n, 4) if n else None,
        "macro_precision": macro("precision"),
        "macro_recall": macro("recall"),
        "macro_f1": macro("f1"),
        "evaluated_classes": evaluated,
        "per_class": per,
        "labels": list(labels),
        "confusion_matrix": cm,
    }


def binary_report(y_true: list[str], y_pred: list[str]) -> dict:
    """Threat (any non-legitimate class) vs legitimate."""
    t = ["threat" if y in THREAT else "legitimate" for y in y_true]
    p = ["threat" if y in THREAT else "legitimate" for y in y_pred]
    return classification_report(t, p, labels=("legitimate", "threat"))
