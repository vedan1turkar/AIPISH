# Changelog

## P5d.1 — Return-Path / sender domain comparison fix (header forensics)

### Root cause
`forensics/headers.py::_dom()` took `rpartition("@")[2]` of the raw `Return-Path` header text, so
`<bounce@example.com>` became `example.com>`. Because almost every Return-Path is written in angle
brackets, the comparison with the From domain failed for nearly every message that had a Return-Path
header.

Each such message received a medium `returnpath_mismatch`. That bridged into
`header_inconsistency_forensics` and added **+20 rule points**.

### Fixed: same bug class everywhere
A new helper, `backend/app/ingestion/addresses.py`, parses addresses with `email.utils.parseaddr` /
`getaddresses` and normalises domains: lower-case, invisible characters and trailing dots stripped,
IDNA → punycode. The null reverse-path `<>` yields no domain. These call sites now use it:

| Location | Before | Now |
|---|---|---|
| `forensics/headers.py` Return-Path vs From | raw `rpartition`, kept `>` | `address_domain()` |
| `forensics/headers.py` Reply-To vs From | lower-case only | normalised (IDNA, dots) |
| `forensics/headers.py` Message-ID vs From | `rstrip(">")`, lower-case | `message_id_domain()` (same semantics) |
| `detection/fs_model.py` sender vs Reply-To rule and brand check | lower-case and `www.` only | normalised (`www.` handling kept) |
| `auth/__init__.py` Return-Path / From domains for SPF alignment | regex: display-name forms failed, no dot/IDNA handling | `address_domain()` / `normalize_mail_domain()`; org-domain alignment semantics unchanged |
| `enrichment/iocs.py` Return-Path IOC | regex: display-name forms failed | `address_domain()` |
| `correlation/extract.py` Return-Path / Reply-To domains | manual strip | `address_domain()` |

**Not changed:** the Sender header is not compared anywhere (test added). `intel/service.py` already
stripped brackets correctly.

### Version
New analyses record `forensics.header_comparison_version = 2`. Analyses stored before the fix have no
value (`null`) and are **not rewritten**; re-analysing an old email may give a different rule score.
The ATT&CK guard from P5d is kept for those stored analyses and is a no-op on fixed data.

### ML parity
- The XGBoost model's features include the per-rule contributions and the rule score from
  `ml.features.run_rules_offline()`. That function therefore keeps the pre-fix comparison
  (`legacy_domain_compare=True`).
- The legacy functions are preserved unchanged as `forensics.headers._legacy_dom` and
  `detection.fs_model._legacy_norm_domain`, and documented as intentionally preserved to match training.
- The upload pipeline and everything shown to people use the fixed comparison. The `/ml/classify` and
  `/ml/explain` responses now *display* the fixed rule result (`run_rules_offline_current`) while
  feeding the model the legacy features.
- **Proof:**
  - ML inference on all 16 committed fixtures and 200 dataset emails, at baseline `32cdeed` and after:
    **0 differences at 4 decimals**. BEC is still impersonated 0.4355.
  - `test_ml_rule_features_identical_to_pre_fix_baseline` compares the rule-feature vectors of every
    fixture with a snapshot generated at `32cdeed`.
  - No model files were changed and nothing was retrained.

### Impact study
Method:
- The offline upload pipeline (forensics → auth with `live=False` → detection; no enrichment, ML or LLM)
  was run on a throwaway DB, at baseline `32cdeed` (git worktree) and with the fix.
- The sample was deterministic and stratified, up to 500 per label from the local labelled dataset.
  Impersonated and fraud are synthetic in this dataset and contain no Return-Path headers.

| Label | n | Score changed | Mean Δ (all) | Δ when changed | "likely" verdicts before → after | Flagged (suspicious+) before → after | False RP-mismatch removed | Real RP mismatch kept |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| legitimate | 500 | 52 (10.4 %) | −2.08 | −20 (median −20) | 65 → 65 | 204 → 200 | 54 | 192 |
| phishing | 500 | 361 (72.2 %) | −14.40 | −19.9 (median −20) | 152 → 109 | 318 → 272 | 372 | 125 |
| impersonated | 207 | 0 | 0 | — | 0 → 0 | 0 → 0 | 0 | 0 |
| fraud | 365 | 0 | 0 | — | 0 → 0 | 75 → 75 | 0 | 0 |

Verdict changes: legitimate 4 × suspicious → minimal; phishing 43 × phishing_fraud_likely → suspicious
and 46 × suspicious → minimal. No score went up anywhere, and no new inconsistency appeared.

Fixtures whose score or verdict changed (each lost the false `returnpath_mismatch`, and with it the
20-point `header_inconsistency_forensics`):

| Fixture | Before | After |
|---|---|---|
| `demo/attack/synthetic_macro_attachment.eml` | 65 phishing_fraud_likely | 45 suspicious |
| `demo/attack/synthetic_tor_origin.eml` | 80 phishing_fraud_likely | 60 phishing_fraud_likely |
| `demo/campaign/freemail_only.eml` | 35 suspicious | 15 minimal |
| `demo/campaign/unrelated.eml` | 35 suspicious | 15 minimal |

Six other fixtures lost the false inconsistency without a score change, because another medium
inconsistency (e.g. a genuine Reply-To mismatch) still fires the same rule. `bec_wire_change.eml` stays
**100 / phishing_fraud_likely**, and no legitimate fixture got worse.

### Conclusion
- **Legitimate mail:** yes, the bug inflated scores. 10.4 % of the legitimate sample carried a false +20,
  and 4 of 500 moved from suspicious to minimal after the fix.
- **Phishing:** the bug inflated phishing scores even more, because phishing corpora almost always carry
  a Return-Path. The fix lowers rule-only recall on real phishing: "likely" 30.4 % → 21.8 %, flagged
  63.6 % → 54.4 %.
- **Next step:** those points were never genuine evidence. Rule weights were **not** retuned in this
  correction phase; a later phase should re-baseline rule weights and thresholds on the corrected
  signal. The ML model is unaffected because it keeps its training-time inputs.
