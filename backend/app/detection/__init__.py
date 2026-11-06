"""Detection engine — standalone, explainable, deterministic.

Architecture:
- ``config``        : single source of truth for weights/thresholds/lexicons
- ``fs_model``      : pure feature extraction from a ParsedEmail
- ``rules/*``       : one rule (= indicator) per function; returns Evidence struct
- ``engine``        : aggregate → bounded 0-100 score → verdict band

Every finding carries severity, evidence, rationale, and its exact score
contribution, plus a knowledge tag:
- ``fact``      : deterministically provable from the message bytes
- ``heuristic`` : a judgment call on noisy data
Missing evidence is ``unknown`` — never treated as safe.
"""
from app.detection.config import DetectionConfig, get_config
from app.detection.engine import DetectionResult, run_detection
from app.detection.fs_model import FeatureModel, build_features

__all__ = [
    "DetectionConfig",
    "get_config",
    "DetectionResult",
    "run_detection",
    "FeatureModel",
    "build_features",
]
