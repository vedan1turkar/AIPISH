# aipish-email-v1 — model card (R1, R3)

**Status: research prototype.** These are not production-grade accuracy claims. The test set has
1,709 messages from old public corpora (1999–2007), and the `impersonated`/`fraud` classes are
100% synthetic and template-based. Full numbers are in `EVALUATION_v1.md` and `evaluation_v1.json`.

## What it is

| Component | Library | Input | Role |
|---|---|---|---|
| `transformer` | DistilRoBERTa (`distilroberta-base`, HF revision `fb53ab88…`), fine-tuned | masked subject + body (max 256 tokens) | NLP classifier (R1) |
| `xgb` | XGBoost 3.4.1 + scikit-learn preprocessing | 18 structural features, the 18 rule contributions plus the rule score, and 100-d TruncatedSVD of word TF-IDF | tabular classifier (R3) |
| `lr` | scikit-learn `Pipeline` (word and char TF-IDF → LogisticRegression) | masked text | scikit-learn baseline (R3) |
| `ensemble` | weighted mean of the component probabilities | — | served prediction |

The validation-selected ensemble weights are **transformer 0.5, xgb 0.5, lr 0.0**. The LR model is still trained,
evaluated and shipped, but it adds no weight to the served prediction.
The existing **18-rule engine is unchanged**. It stays the explainable evidence layer, feeds XGBoost
as features, and is reported side by side with the ML output (`/api/v1/ml/classify`).

## Data and training

- **Dataset:** P2a corpus, manifest SHA-256 `d8d583a3…60ab7`. Train/validation/test are 7,899 / 1,681 / 1,709 messages.
- **Labels:** five classes. `suspicious` has **no training data**, so the model never predicts it. Its probability is always 0, and the API lists it in `untrained_classes`.
- **Training uses the train split only.** Validation is used for model selection only: best epoch, XGBoost early stopping (best iteration 56) and the ensemble weight grid. Test was used once, for the report.
- **Seed:** 20261119 for Python, NumPy, torch, scikit-learn and XGBoost.
- **Class imbalance:** handled with balanced class weights (LR, XGBoost) and a weighted cross-entropy loss (DistilRoBERTa).
- **DistilRoBERTa settings:** 3 epochs, batch 16, learning rate 3e-5, weight decay 0.01, warmup 6%, max length 256.
  - Trained on Apple M4 GPU (MPS) in 1,602 s.
  - Validation macro-F1 per epoch: 0.865 → 0.903 → 0.931.
  - The best epoch was 3.
- **Software:** Python 3.13.9, numpy 2.5.5, scikit-learn 1.9.1, xgboost 3.4.1, torch 2.15.0, transformers 4.57.6.
- **Reproduce:** `cd backend && python -m app.ml.dataset.build && python -m app.ml.train && python -m app.ml.report`.
- **Determinism:** LR and XGBoost are deterministic (covered by a unit test). DistilRoBERTa training on MPS is not bit-exact across runs.

## Test-set results (ensemble)

| Subset | n | 5-class macro-F1 | Threat-vs-legitimate F1 (P / R) |
|---|---|---|---|
| all | 1,709 | 0.965 | 0.948 (0.970 / 0.926) |
| real only (Nazario, SpamAssassin, Enron) | 1,607 | 0.954 | 0.936 (0.963 / 0.911) |
| synthetic only | 102 | 0.979 | 1.000 |
| sender-disjoint (sender never seen in train) | 1,514 | 0.954 | 0.922 (0.953 / 0.892) |

On the same test set the **18-rule engine** scores much lower on threat vs legitimate:

| Rule-engine threshold | F1 | Precision | Recall |
|---|---|---|---|
| verdict "suspicious" or higher | 0.507 | 0.644 | 0.418 |
| verdict "phishing_fraud_likely" only | 0.189 | 0.861 | 0.106 |

The rules were run offline (no live DNS, SPF/DKIM or enrichment), so they are weaker here than in the full upload pipeline.

## Known limitations (read before quoting any number)

1. **No `suspicious` class.** No approved data source covers it.
2. **Synthetic `impersonated`/`fraud`.** The test set holds only 4 unseen templates (102 messages). The 0.98–1.00 scores measure generalisation to new templates written by the same author, **not** to real BEC.
3. **Era and source confound.** Legitimate mail dates from 1999–2003 and phishing mostly from 2004–2007, and each class comes from one or two corpora. Part of the accuracy can come from corpus style rather than threat signals. Expect lower performance on modern mail.
4. **Most remaining errors are phishing missed as legitimate** (43 of 482 test phishing messages). 17 legitimate messages were flagged as phishing.
5. **Not explained here.** Per-email explanations (SHAP) are a separate task (P2c). The transformer is a black box.
6. **Rule-engine parse failure.** The existing `.eml` parser raised `AttributeError` on 1 of 11,289 corpus messages (a group-syntax address header, stdlib bug path). Its rule features are recorded as missing (NaN), never as "no rule fired". The parser itself was not modified (out of scope).

## Serving

- **Code:** `app/ml/inference.py`, endpoints `GET /api/v1/ml/status` and `POST /api/v1/ml/classify`.
- **Artifacts:** loaded once from `$AIPISH_MODEL_DIR` (default `<repo>/models/aipish-email-v1`, git-ignored, 366 MB). They are trusted local files; joblib uses pickle.
- **Speed:** CPU inference takes about 20–40 ms per message with one torch thread.
  - On macOS, torch and xgboost each ship `libomp`, and multi-threaded CPU torch deadlocks once xgboost is loaded. The default is therefore `AIPISH_TORCH_THREADS=1`.
- **Failure handling:** missing ML dependencies, missing or corrupt files or a label-order mismatch give `status: "unavailable"` with a reason and `label: null`. An inference exception gives `status: "error"`. A message the corpus rules would exclude, such as an empty body, gives `not_applicable`. **There is never a silent fallback to `legitimate`.**
- **Parity check (19 Nov 2026):** the served path on CPU reproduces the training-time test evaluation exactly, with an identical confusion matrix.
