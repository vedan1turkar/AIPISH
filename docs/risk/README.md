# Combined risk assessment (P5h)

The combined risk assessment is an **additional, separately labelled result**. It sits beside the 18-rule
verdict and the ML classification; it does not replace them and never changes their stored values.

> It is a **risk index (0–100)**, not a probability of fraud. The ML models behind it were trained on old,
> partly synthetic and source-confounded data, so their outputs are not calibrated probabilities for modern
> real-world mail. Absence of threat-intelligence records is never evidence of safety.

Code: `backend/app/risk/engine.py` (pure, deterministic combiner), `backend/app/risk/service.py`
(inputs, append-only versions), `backend/app/risk/config.py` (bands and thresholds, versioned).

## 1. Why rules and ML are not simply added

The served XGBoost component of the ML ensemble uses **the 18 per-rule contributions and the rule total as
features** (`app/ml/features.py: rule_features`, computed on the legacy pre-P5d.1 header comparison for
train/serve parity). The ML output therefore already contains the rule signal. Adding a rule score to an ML
score would count the same evidence twice.

The design consequently uses:

| Signal | Role | Why |
|---|---|---|
| ML ensemble threat index `p = 1 − P(legitimate)` | **Primary** score when available | It already integrates text, structure and the rule features. |
| Rule engine (score, verdict, findings) as displayed | **Floors and conflict detection** only when ML is available; **primary** when ML is unavailable | Avoids double counting while letting decisive, byte-provable evidence act. |
| Hard-evidence combinations | **Floors** (cannot be diluted by ML "legitimate") | Each is decisive on its own and is not a probability. |
| Threat intelligence (consented runs only) | **Corroboration**: may raise, never lowers | Independent of rules and ML (neither sees provider data), so a small capped addition is not double counting. |
| Campaign membership, ATT&CK, source-type hypotheses | **Context only** (no score effect) | They are derived from the same indicators, rule findings and ML output; any bump would double count. |

## 2. Output

```
combined_score   0-100 integer, or null when indeterminate
level            minimal | low | medium | high | critical | indeterminate
confidence       low | medium | high
agreement        agree | partial | conflict | not_applicable
flags            conflicting_signals, hard_evidence_floor, components_missing, intel_flagged,
                 intel_simulated, rules_only, ml_only, analyst_review_recommended
components[]     name, label, status (available | unavailable | not_run | declined | error),
                 value, role (primary | floor | corroboration | context | unavailable),
                 effect (points or floor applied), evidence_ids, reason
evidence[]       K1, K2, … : source, reference (rule id / assessment id / run id / campaign id),
                 statement (titles and counts only, never message content)
explanation      plain-language sentences, in order of effect
inputs           detection score/verdict, ml_source (kind, id, model_version), intel_run_id,
                 attack_mapping_id, campaign ids
engine_version, config_version, disclaimers
```

## 3. Bands

| Level | Combined score |
|---|---|
| minimal | 0–9 |
| low | 10–24 |
| medium | 25–59 |
| high | 60–84 |
| critical | 85–100 |
| indeterminate | no score: neither rules nor ML produced a result |

The medium and high edges coincide with the rule engine's own `suspicious` (25) and
`phishing_fraud_likely` (60) bands, so a rules-only result reads the same way as the rule verdict.

### Mapping the ML index to the score

`p` is mapped to the score by a monotone piecewise-linear function through four thresholds
`t_low < t_med < t_high < t_crit`, which map to the band edges 10, 25, 60 and 85. The thresholds come from
the **validation split** (never the test split):

- `t_med`: maximises threat-vs-legitimate F1 of `level ≥ medium` on validation, searched over
  0.30–0.50 in steps of 0.01. The upper limit of 0.50 is a design constraint that keeps the combiner monotone
  (see §5).
- `t_high`: the smallest value in [max(t_med, 0.50), 0.95] whose validation false-positive rate for
  `level ≥ high` is ≤ 1 %.
- `t_low = 0.10` and `t_crit = 0.90` (fixed, not tuned).

The chosen values and their effect on the test split are reported in §7.

## 4. Components and rules

### (a) Rules: score and verdict as displayed (post-P5d.1)

- **ML available:** rules act only through floors.
  - Verdict `suspicious` sets a floor of 10 (low), so a rule-suspicious message is never shown as minimal.
  - Verdict `phishing_fraud_likely` while ML is on the legitimate side (`p < 0.5`) is a **conflict** and
    sets a floor of 25 (medium).
- **ML unavailable / error / not run / not applicable:** the rule score is the primary score, with a
  floor of 10. With ML missing nothing is ever called minimal.

### (b) ML ensemble

- The value is `p = 1 − P(legitimate)` and the predicted class is shown alongside it.
- The served ensemble never predicts `suspicious`: that class has no training data. The conflict flag
  and the medium floor below are the honest substitute for it.
- **Source:**
  - The most recent successful ML result for the analysis, from either an AI assessment version or the
    P5h upload-time classification.
  - The source kind, id and model version are recorded in `inputs.ml_source`.
- **Missing result:** if no successful result exists, the latest attempt's status is shown
  (`unavailable`, `error`, `not_applicable`), or `not_run`.

### (c) Hard-evidence floors

All three floors are set at 60 (high). Each is decisive on its own, so ML "legitimate" and absent intel
cannot lower them.

| Id | Condition (rule findings as displayed) | Rationale |
|---|---|---|
| `H1_risky_attachment` | `risky_attachment_type` fired | Executable, macro or container formats are the dominant malware vector. |
| `H2_verified_auth_fail_identity` | `auth_verified_fail` **and** one of `sender_reply_to_mismatch`, `lookalike_domain`, `auth_dmarc_misaligned` | A locally re-verified authentication failure plus a sender-identity mismatch is spoofing evidence. |
| `H3_payment_or_credential_with_identity` | `payment_diversion` or `credential_request` **and** one of `sender_reply_to_mismatch`, `lookalike_domain`, `auth_dmarc_misaligned`, `auth_verified_fail`, `auth_conflict` | The BEC / credential-phishing pattern: a money or credential ask combined with a sender-identity signal. |

### (d) Threat intelligence

Intel counts only when a run with **consent granted** exists. The latest run is used, and its id is
recorded.

| Provider status | Effect |
|---|---|
| `malicious_or_flagged` from VirusTotal or AbuseIPDB ("strong") | +10 per provider (distinct), floor 25 (medium) |
| `malicious_or_flagged` from Tor exit list, IPinfo privacy flags, Shodan tags ("anonymity/exposure") | +5 per provider (distinct) |
| `record_found`, `reported_clean_no_flags`, `no_record` | **Nothing.** Never lowers risk, never "clean". |
| no run, consent refused, offline, provider errors, rate limits, missing credentials | Component `not_run` / `declined` / `unavailable`; nothing |

- The total intel addition is capped at **+15**.
- SIMULATED runs count, but they set the `intel_simulated` flag, are labelled, and never raise confidence.

### (e) Context

Context comes from two places:

- campaign membership (P5c);
- ATT&CK techniques and source-type hypotheses (P5d).

These are shown with their evidence and have **no score effect**.

Content cues are listed from the existing lexicon rule findings (`urgency_language`, `credential_request`,
`payment_diversion`, `all_caps_pressure`). This is a per-cue breakdown derived from existing outputs (R1);
no new NLP is involved.

### Formula

```
base   = g(p)                        if ML available
       = rule_score                  if only rules available
       = indeterminate               if neither
floor  = max(hard-evidence floors, conflict floor, rule-suspicious floor,
             missing-primary floor (10), strong-intel floor)
score  = min(100, round(max(base, floor) + intel_addition))
level  = band(score)
```

### Confidence

| Confidence | When |
|---|---|
| **high** | Rules and ML both available, no conflict, and the ML top-class confidence ≥ 0.80. |
| **medium** | Rules and ML both available with no conflict, otherwise. |
| **low** | A conflict, only one primary available, or indeterminate. |

SIMULATED intel never raises confidence.

### Agreement

- **agree:** both on the same side. The rule side is "threat" when the verdict is not minimal; the ML side
  is "threat" when `p ≥ 0.5`.
- **partial:** rules suspicious while ML is legitimate.
- **conflict:** rules `phishing_fraud_likely` while ML is legitimate, or rules minimal while ML is threat.
- **not_applicable:** a primary is missing.

A conflict always yields at least medium, sets `conflicting_signals` and `analyst_review_recommended`, and
shows both views.

## 5. Properties (enforced by tests)

1. **No double counting.** Rule points are never added to the ML-based score (§1).
2. **Monotonic.** Raising any single risk input never lowers the combined score or level:
   - the rule score or a fired rule;
   - the ML threat index `p`;
   - an intel flag.

   For example, the "rules minimal vs ML threat" conflict floor disappears when the rule score rises. That
   can never lower the result, because the ML threat side means `p ≥ 0.5` and `g(0.5) ≥ 25` (enforced by
   `t_med ≤ 0.5`).
3. **Unavailable never implies legitimate.** A missing primary is listed as such, confidence drops to
   low, the floor is low (10), and the level is never below what the available components support. If
   both primaries are missing, the result is `indeterminate`.
4. **Floors hold.** Hard-evidence floors are not reduced by ML "legitimate" or by absent intel.
5. **Conflict ⇒ ≥ medium.** A conflict also flags the result and recommends review.
6. **No-record never lowers.** Clean or no-record intel results never change the score.
7. **Deterministic and versioned.** The same inputs always give the same output. `engine_version` and
   `config_version` are stored with every version.
8. **Additive.** Rule score, verdict and ML outputs are read, never written.

## 6. Pipeline

- **Upload-time ML (P5h).**
  - The cheap ML classification (not SHAP, not Mistral) runs automatically at upload when the models are
    available (`AIPISH_ML_AT_UPLOAD`, default `1`).
  - It is bounded by `AIPISH_ML_UPLOAD_TIMEOUT_SECONDS` (default 20) and failure-isolated.
  - The result is stored in `ml_classification`, including `unavailable` and `error` states. This is
    needed because `hash_only` analyses cannot be re-classified later.
  - The SHAP and Mistral opt-in is unchanged.
- **Versions.** Risk results are append-only in `risk_assessment`. A version is added only when the
  result changes (fingerprint), so recomputes and backfills are idempotent.
- **Recomputation points:**
  - upload (failure-isolated);
  - after a threat-intel run;
  - after an AI assessment run;
  - `POST /analyses/{id}/risk/recompute` (analyst+, audited);
  - `python -m app.cli backfill-risk`.
- **What is not touched.** Mistral prompts do not receive the combined score.

## 7. Evaluation (offline, no retraining)

The study is generated by `backend/scripts/evaluate_risk.py`. Full tables (validation and test, all and
real-only, per-class detection, confidence, disagreement IDs) are in `docs/risk/evaluation_v1.md` and
`docs/risk/evaluation_v1.json`. They contain metrics and record IDs only, never email content; the dataset
and models are local and not committed.

**Setup.**

- **Data:** the saved split (manifest `d8d583a30ffc`): validation 1,681, **test 1,709**.
- **ML:** the served ensemble, with the same components, weights and legacy rule features as inference. A
  batch-vs-served parity check is built into the script.
- **Rules:** the **current displayed engine** (post-P5d.1), run offline. Without DNS or authentication, the
  auth-based rules and the H2 floor cannot fire.
- **Threat intel:** no runs (`not_run`, as for most uploads).
- **Thresholds** (validation only, by the rule in §3): `t_med = 0.36` (validation F1 0.9723) and
  `t_high = 0.50` (the smallest value with validation FPR ≤ 1 % at high+). `t_low = 0.10` and
  `t_crit = 0.90` are fixed.

**Test split, threat vs legitimate** (584 threat, 1,125 legitimate):

| Method | Precision | Recall | F1 | False positives | FPR (legitimate) |
|---|---:|---:|---:|---:|---:|
| Rules: suspicious or higher | 0.6538 | 0.3493 | 0.4554 | 108 | 9.60 % |
| Rules: phishing_fraud_likely | 0.8085 | 0.0651 | 0.1204 | 9 | 0.80 % |
| ML only (argmax ≠ legitimate) | 0.9695 | 0.9264 | 0.9475 | 17 | 1.51 % |
| **Combined: medium or higher** | 0.9423 | 0.9503 | 0.9463 | 34 | 3.02 % |
| **Combined: high or higher** | 0.9695 | 0.9264 | 0.9475 | 17 | 1.51 % |

**Test split, real messages only** (482 threat, 1,125 legitimate):

| Method | Precision | Recall | F1 | FPR |
|---|---:|---:|---:|---:|
| Rules: suspicious or higher | 0.6237 | 0.3714 | 0.4655 | 9.60 % |
| Rules: phishing_fraud_likely | 0.8085 | 0.0788 | 0.1437 | 0.80 % |
| ML only | 0.9627 | 0.9108 | 0.9360 | 1.51 % |
| Combined: medium or higher | 0.9302 | 0.9398 | 0.9350 | 3.02 % |
| Combined: high or higher | 0.9627 | 0.9108 | 0.9360 | 1.51 % |

**Levels on test** (legitimate / threat):

| Level | Legitimate | Threat |
|---|---:|---:|
| minimal | 987 | 20 |
| low | 104 | 9 |
| medium | 17 | 14 |
| high | 7 | 57 |
| critical | 10 | 484 |

**Flags on test.**

- **Conflicts:** 371 (21.7 %).
  - `ml_threat_rules_minimal`: 362 cases, of which 346 are true threats. The rule engine misses most
    phishing in this corpus.
  - `rules_high_ml_legitimate`: 9 cases, all of them legitimate mail. These are rule false positives, and
    the medium floor turns them into medium-level false positives.
- **Hard floor:** H3 fired on 10 messages.

**Acceptance against §6 of the task.**

- **Not materially worse than ML alone:**
  - Combined high+ is identical to ML alone (F1 0.9475).
  - Combined medium+ is 0.0012 F1 lower, gains 2.4 points of recall, and doubles the false-positive rate
    (1.51 % → 3.02 %). That is the cost of the review-level band and the conflict floor.
- **Lower false-positive rate than rules alone:**
  - At the comparable review threshold, combined medium+ is 3.02 % against 9.60 % for rules suspicious+.
  - At the strict threshold, rules `phishing_fraud_likely` has the lower FPR (0.80 % against 1.51 %), but
    it detects only 6.5 % of threats against 92.6 %.
  - So the combined result has the lower FPR at every recall the rules can reach. It does **not** have a
    lower FPR than the strict rule band in absolute terms.

**Caveats.**

- The data are old, partly synthetic and source-confounded. The synthetic subset scores perfectly.
- Thresholds tuned on this validation split are not guaranteed for modern mail.
- The rules here are run offline. With live authentication, H2 and the auth rules can also fire.
- There is no threat-intel data in the study.
- The index is not a probability.

## 8. What it is not

- Not a probability of fraud, and not a calibrated likelihood for any real mailbox.
- Not a replacement for the rule verdict or the ML class. Both remain visible and unchanged.
- Not evidence of safety when low or minimal. Missing components and absent intel are listed, never assumed
  clean.
- Not attribution: campaign and ATT&CK context never identify a person.

## 9. Limitations

- The conflict flag fires on about a fifth of mail in this corpus, mostly because the rules miss phishing
  that ML catches. It lowers confidence, by design, rather than claiming agreement.
- When rules say `phishing_fraud_likely` and ML says legitimate, the medium floor adds false positives (9 of
  1,125 legitimate messages on test).
- Upload-time ML runs in-process with a timeout. A timed-out classification keeps running in the
  background worker until it finishes, and its result is not stored.
- Campaign membership changes as other analyses arrive. The stored context updates on the next recompute or
  backfill.
- The thresholds are fixed per `config_version`. Changing them requires a new version and a backfill.
