# aipish-email-v1 — model card (R1, R3)

**Status: research prototype.** These are not production-grade accuracy claims. The test set has
1,709 messages from old public corpora (1999–2007), and the `impersonated`/`fraud` classes are
100% synthetic and template-based. Full numbers are in `FINAL_EVALUATION_v1.md` (final) and `EVALUATION_v1.md` (training run).

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
5. **Explanations cover only part of the ensemble (see below).** The transformer has 50% weight and is a black box. SHAP covers the XGBoost component only.
6. **Rule-engine parse failure.** The existing `.eml` parser raised `AttributeError` on 1 of 11,289 corpus messages (a group-syntax address header, stdlib bug path). Its rule features are recorded as missing (NaN), never as "no rule fired". The parser itself was not modified (out of scope).

## Serving

- **Code:** `app/ml/inference.py`, endpoints `GET /api/v1/ml/status` and `POST /api/v1/ml/classify`.
- **Artifacts:** loaded once from `$AIPISH_MODEL_DIR` (default `<repo>/models/aipish-email-v1`, git-ignored, 366 MB). They are trusted local files; joblib uses pickle.
- **Speed:** CPU inference takes about 20–40 ms per message with one torch thread.
  - On macOS, torch and xgboost each ship `libomp`, and multi-threaded CPU torch deadlocks once xgboost is loaded. The default is therefore `AIPISH_TORCH_THREADS=1`.
- **Failure handling:** missing ML dependencies, missing or corrupt files or a label-order mismatch give `status: "unavailable"` with a reason and `label: null`. An inference exception gives `status: "error"`. A message the corpus rules would exclude, such as an empty body, gives `not_applicable`. **There is never a silent fallback to `legitimate`.**
- **Parity check (19 Nov 2026):** the served path on CPU reproduces the training-time test evaluation exactly, with an identical confusion matrix.

## Final P2b evaluation (post-hoc on the saved artifacts, 19 Nov 2026)

Produced by `python -m app.ml.evaluate` with no retraining. Full tables, including every
confusion matrix and the train split, are in `FINAL_EVALUATION_v1.md` and `final_evaluation_v1.json`. Validation and test
numbers reproduce the training-time evaluation exactly.

### Samples per class (total, of which synthetic)

| Split | legitimate | suspicious | impersonated | phishing | fraud |
|---|---|---|---|---|---|
| train | 5,249 (0) | **0** | 146 (146) | 2,254 (0) | 250 (250) |
| validation | 1,125 (0) | **0** | 25 (25) | 482 (0) | 49 (49) |
| test | 1,125 (0) | **0** | 36 (36) | 482 (0) | 66 (66) |

- **Zero-sample class:** `suspicious`. It is not trained, not evaluated, and never predicted (probability 0).
- **Synthetic-only classes:** `impersonated` and `fraud` were trained and evaluated on synthetic templates only. Their scores measure generalisation to *unseen templates by the same generator*, not to real business email compromise.
- **Real-world classes:** only `legitimate` and `phishing` have real data. The **real-only rows below are the closest thing to real-world performance**, and even those come from 1999–2007 corpora.

### Test macro-F1 / weighted-F1

| Model | all (n=1,709) | real only (n=1,607) | synthetic only (n=102) |
|---|---|---|---|
| DistilRoBERTa | 0.969 / 0.961 | 0.951 / 0.960 | 1.000 / 1.000 |
| XGBoost (+ sklearn features) | 0.735 / 0.928 | 0.954 / 0.961 | 0.519 / 0.475 |
| sklearn TF-IDF + LR | 0.647 / 0.907 | 0.943 / 0.953 | 0.365 / 0.473 |
| **Ensemble (served)** | **0.965 / 0.963** | **0.954 / 0.962** | 0.979 / 0.981 |

Test threat-vs-legitimate F1 for the 18-rule baseline (offline):

| Threshold | F1 |
|---|---|
| "suspicious" or higher | 0.507 |
| "phishing_fraud_likely" only | 0.189 |

For comparison, the ensemble scores 0.948.

### Overfitting check (macro-F1: train → validation → test)

| Model | train | validation | test |
|---|---|---|---|
| DistilRoBERTa | 0.999 | 0.931 | 0.969 |
| XGBoost | 1.000 | 0.606 | 0.735 |
| LR | 1.000 | 0.456 | 0.647 |
| Ensemble | 1.000 | 0.952 | 0.965 |

DistilRoBERTa training loss fell from 0.263 to 0.0037 to 0.0010 over epochs 1–3, while validation macro-F1 rose from 0.865 to 0.903 to 0.931.

**How to read this:**

- **All models fit the training set almost perfectly.** They have the capacity to memorise it.
- **On real mail the gap is small.** Real-only macro-F1 for the ensemble is 1.000 on train, 0.977 on validation and 0.954 on test. This is mild overfitting, not a collapse.
- **The large gaps come entirely from the synthetic classes.** XGBoost and LR memorise the surface wording of the 17 training templates and fail on unseen ones: synthetic-only validation macro-F1 is 0.25 for XGBoost and 0.00 for LR. DistilRoBERTa generalises across templates (0.957 on validation, 1.000 on test), but validation and test hold only 4 templates each, so these numbers are fragile.
- **Test beats validation for some models.** This is template luck: the validation templates (`advfee_03`, `payroll_03`, `execimp_02`) happen to be harder. With so few templates, the order is not meaningful.
- **Validation numbers are optimistic.** Validation was used for three selections: the best epoch, XGBoost early stopping and the ensemble weight grid. Test is the unbiased estimate.

### Leakage verification (passed)

- **No overlap between splits:** 0 shared ids, exact-text hashes, near-duplicate clusters, groups or thread message-ids between train, validation and test.
- **Dataset version:** the model's manifest SHA-256 and split sizes match the current dataset.
- **Code audit (`app/ml/evaluate.py`, plus the unit test `test_never_trains_on_validation_or_test`):**
  - Every `.fit` uses the train split.
  - Validation is used only for XGBoost early stopping, DistilRoBERTa epoch selection and the ensemble weights.
  - Test predictions are produced only after the weights are fixed.

### Parser failure (verified)

There is one corpus message, `nazario-21735b6414179deb` (train split, phishing), on which the existing `.eml` parser raises `AttributeError`.

- **Rule features:** all 19 are NaN, i.e. missing, not "no rule fired".
- **Rule verdict:** `null`. The rule baseline counts it as a miss.
- **ML result:** the ML still classifies it, as `phishing` with confidence 0.994.
- **Live API check:** `POST /api/v1/ml/classify` returns `rules.verdict = null` and `rules.error = "AttributeError: …"`, with `ml.status = "ok"`.

### Saved configuration (tracked in git)

- `docs/ml/model_config_v1.json` — full model configuration, including:
  - seed 20261119;
  - hyperparameters;
  - ensemble weights;
  - dataset manifest hash;
  - DistilRoBERTa epoch history;
  - base-model revision;
  - library versions.
- `docs/ml/tokenizer_config_v1.json` — tokenizer, special-tokens and model configs.
- `final_evaluation_v1.json` — the SHA-256 of every artifact file in `models/aipish-email-v1/`. The artifacts themselves are git-ignored.

## Explanations (R4, SHAP) — `POST /api/v1/ml/explain`, `app/ml/explain.py`

- **What is explained.** Every component with a non-zero ensemble weight that has a SHAP explainer:
  - `xgb`: `shap.TreeExplainer`, exact TreeSHAP in XGBoost's raw-margin space for the predicted class.
  - `lr`: `shap.LinearExplainer` with an empty-document background. The served v1 ensemble gives LR weight 0, so it is not explained there.
  - The transformer is listed under `not_explained` with the reason. Its 50% share of the prediction is **not covered**, and the response does not pretend otherwise.
- **Response structure:**
  - `status`: `ok`, `unavailable`, `not_applicable` or `error`.
  - `explained_label` and `model_version`.
  - Per component: `explainer`, `output_space`, `base_value`, `output_value` and `additivity_ok`. The last checks that base plus the sum of SHAP values equals the model output.
  - Also per component: `top_contributions`, up to 10, each with `feature`, `group` (structural, rule_engine or text_term), the feature `value`, `shap_value` and `direction` (toward or away from the class).
  - Also per component: `aggregated` rows (text SVD components, withheld terms, character n-grams).
  - At the top level: `not_explained` and `disclaimer`.
- **Not causal.** SHAP values show which inputs this model relied on, relative to a baseline. They are associations learned from the P2a corpus, not causes or evidence of intent. Example: `has_html = 0` pushes away from `phishing`, which reflects the era and source confound (Enron and SpamAssassin mail is mostly plain text), not a real-world rule.
- **Privacy:**
  - No subject or body text, addresses or URLs are returned.
  - Text terms appear only if they are plain words found in at least 25 training emails. Rarer terms, which could include names, IDs and codes, and all character n-grams are summed into aggregate rows, with a count of withheld terms.
  - Explanations are computed on request and not stored.
- **Failures never produce made-up contributions.**
  - SHAP not installed, model missing or corrupt: `unavailable`.
  - A message the corpus would exclude: `not_applicable`.
  - An exception during SHAP: `error`.
  - All of these return an empty `components`. If one component fails, it is reported in `not_explained` and the others are still returned.
- **18-rule evidence.** The response's `rules` block carries the unchanged rule findings next to the explanation.
- **Speed:** about 0.04–0.3 s per email on CPU (19 Nov 2026, M4).
