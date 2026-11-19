"""Load the trained AIPISH email classifier and run inference (FastAPI-safe).

Failure policy: if the ML stack, the model files, or a component cannot be
loaded or run, the result has status "unavailable" or "error", label None and
a reason. The classifier never falls back to "legitimate".

Model directory: $AIPISH_MODEL_DIR, else <repo>/models/aipish-email-v1.
Artifacts are produced locally by `python -m app.ml.train` and are trusted
local files (joblib uses pickle: never load model files from untrusted sources).
"""
from __future__ import annotations

import json
import threading
from dataclasses import dataclass, field
from pathlib import Path

from app.core.config import env
from app.ml import features as F
from app.ml.dataset.labels import LABELS

DEFAULT_MODEL_DIR = Path(__file__).resolve().parents[3] / "models" / "aipish-email-v1"
REQUIRED_FILES = ("model_config.json", "lr_pipeline.joblib", "xgb_featurizer.joblib", "xgb_model.json")


@dataclass
class MLResult:
    status: str                         # ok | unavailable | error | not_applicable
    label: str | None = None
    confidence: float | None = None
    probabilities: dict[str, float] = field(default_factory=dict)
    components: dict[str, dict[str, float]] = field(default_factory=dict)
    model_version: str | None = None
    untrained_classes: list[str] = field(default_factory=list)
    reason: str | None = None

    def to_dict(self) -> dict:
        return dict(self.__dict__)


def model_dir() -> Path:
    override = env("AIPISH_MODEL_DIR")
    return Path(override) if override else DEFAULT_MODEL_DIR


class EmailClassifier:
    def __init__(self, path: Path):
        self.path = path
        self.config = json.loads((path / "model_config.json").read_text())
        if tuple(self.config["labels"]) != LABELS:
            raise ValueError("model label order does not match app taxonomy")
        import joblib
        from xgboost import XGBClassifier
        self.weights: dict[str, float] = self.config["ensemble_weights"]
        self.lr = joblib.load(path / "lr_pipeline.joblib")
        self.fz = joblib.load(path / "xgb_featurizer.joblib")
        self.xgb = XGBClassifier()
        self.xgb.load_model(path / "xgb_model.json")
        self.xgb_classes = self.config["xgb"]["classes"]
        self.transformer = None
        if self.weights.get("transformer", 0) > 0:
            import torch
            # torch and xgboost each ship libomp on macOS; multi-threaded CPU torch then
            # deadlocks after xgboost is loaded (observed 2026-11-19). One thread is ample
            # for single-message inference; raise via AIPISH_TORCH_THREADS if verified safe.
            torch.set_num_threads(max(1, int(env("AIPISH_TORCH_THREADS", "1") or "1")))
            from app.ml import transformer as T
            self.max_len = self.config["config"]["transformer"]["max_len"]
            self.transformer = T.load(path / "transformer", "cpu")

    @property
    def version(self) -> str:
        return f"{self.config['model_name']}@{self.config['dataset']['manifest_sha256'][:12]}"

    def predict_record(self, rec: dict, detection: dict) -> MLResult:
        from app.ml.train import _expand
        text = F.text_input(rec)
        comps: dict[str, list[float]] = {}
        if self.weights.get("lr", 0) > 0:
            comps["lr"] = _expand(self.lr.predict_proba([text]), list(self.lr.classes_))[0]
        if self.weights.get("xgb", 0) > 0:
            comps["xgb"] = _expand(self.xgb.predict_proba(self.fz.transform([rec], [detection])),
                                   self.xgb_classes)[0]
        if self.transformer is not None:
            from app.ml import transformer as T
            model, tok = self.transformer
            comps["transformer"] = T.predict_proba(model, tok, [text], self.max_len, "cpu")[0]
        probs = [sum(self.weights[c] * comps[c][j] for c in comps) for j in range(len(LABELS))]
        best = max(range(len(LABELS)), key=lambda j: probs[j])
        return MLResult(
            status="ok", label=LABELS[best], confidence=round(probs[best], 4),
            probabilities={lbl: round(p, 4) for lbl, p in zip(LABELS, probs, strict=True)},
            components={c: {lbl: round(p, 4) for lbl, p in zip(LABELS, v, strict=True)}
                        for c, v in comps.items()},
            model_version=self.version, untrained_classes=self.config["untrained_classes"],
        )

    def predict_raw(self, raw: bytes, detection: dict | None = None) -> MLResult:
        from app.ml.dataset.normalize import Excluded
        try:
            rec = F.record_from_raw(raw)
        except Excluded as exc:
            return MLResult(status="not_applicable", model_version=self.version,
                            untrained_classes=self.config["untrained_classes"],
                            reason=f"message outside model scope: {exc.reason}")
        return self.predict_record(rec, detection if detection is not None else F.run_rules_offline(raw))


_lock = threading.Lock()
_cache: dict[str, object] = {}


def get_classifier() -> tuple[EmailClassifier | None, str | None]:
    """Load once per model dir; returns (classifier, None) or (None, reason)."""
    path = model_dir()
    key = str(path)
    with _lock:
        if key in _cache:
            return _cache[key]  # type: ignore[return-value]
        missing = [f for f in REQUIRED_FILES if not (path / f).is_file()]
        if missing:
            result = (None, f"model files missing in {path.name}: {', '.join(missing)}")
        else:
            try:
                result = (EmailClassifier(path), None)
            except ImportError as exc:
                result = (None, f"ML dependencies not installed ({exc.name}); see requirements-ml.txt")
            except Exception as exc:  # corrupt/incompatible artifacts
                result = (None, f"model failed to load: {type(exc).__name__}")
        _cache[key] = result
        return result


def reset_classifier_cache() -> None:
    with _lock:
        _cache.clear()


def classify_raw(raw: bytes, detection: dict | None = None) -> MLResult:
    clf, reason = get_classifier()
    if clf is None:
        return MLResult(status="unavailable", reason=reason, untrained_classes=[])
    try:
        return clf.predict_raw(raw, detection)
    except Exception as exc:
        return MLResult(status="error", model_version=clf.version,
                        reason=f"inference failed: {type(exc).__name__}")


def status() -> dict:
    clf, reason = get_classifier()
    if clf is None:
        return {"status": "unavailable", "reason": reason, "model_dir": model_dir().name}
    c = clf.config
    return {"status": "ok", "model_version": clf.version, "labels": c["labels"],
            "trained_classes": c["trained_classes"], "untrained_classes": c["untrained_classes"],
            "components": [k for k, w in clf.weights.items() if w > 0],
            "ensemble_weights": clf.weights, "created_utc": c["created_utc"]}
