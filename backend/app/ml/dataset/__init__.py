"""Labelled email corpus for R5: acquisition, normalisation, dedup, splits."""
from app.ml.dataset.labels import LABELS, LABEL_MAP, map_label

__all__ = ["LABELS", "LABEL_MAP", "map_label"]
