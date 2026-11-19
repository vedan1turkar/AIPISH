"""Fitted preprocessing objects that are pickled into model artifacts.

Kept in an importable module (never __main__) so artifacts saved by
`python -m app.ml.train` load in the API process.
"""
from __future__ import annotations

from app.ml import features as F


def build_text_vectorizers(cfg: dict):
    from sklearn.feature_extraction.text import TfidfVectorizer
    lc = cfg["lr"]
    word = TfidfVectorizer(ngram_range=tuple(lc["word_ngrams"]), max_features=lc["word_max_features"],
                           min_df=lc["min_df"], sublinear_tf=True, lowercase=True,
                           token_pattern=r"(?u)<url>|<email>|\b\w\w+\b")
    char = TfidfVectorizer(analyzer="char_wb", ngram_range=tuple(lc["char_ngrams"]),
                           max_features=lc["char_max_features"], min_df=lc["min_df"],
                           sublinear_tf=True, lowercase=True)
    return word, char


class XgbFeaturizer:
    """sklearn preprocessing for XGBoost: structured + rule features + TF-IDF SVD."""

    def __init__(self, cfg: dict):
        from sklearn.decomposition import TruncatedSVD
        self.word, _ = build_text_vectorizers(cfg)
        self.svd = TruncatedSVD(n_components=cfg["svd_components"], random_state=cfg["seed"])
        self.names = list(F.STRUCTURED_NAMES) + list(F.RULE_FEATURE_NAMES) + [
            f"svd_{i}" for i in range(cfg["svd_components"])]

    def fit(self, recs: list[dict], detections: list[dict]):
        self.svd.fit(self.word.fit_transform([F.text_input(r) for r in recs]))
        return self

    def transform(self, recs: list[dict], detections: list[dict]):
        import numpy as np
        dense = self.svd.transform(self.word.transform([F.text_input(r) for r in recs]))
        tab = np.array([F.structured_features(r) + F.rule_features(d)
                        for r, d in zip(recs, detections, strict=True)], dtype=np.float32)
        return np.hstack([tab, dense.astype(np.float32)])
