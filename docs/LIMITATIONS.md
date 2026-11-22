# Limitations and threats to validity

This page brings together the limitations recorded in the per-area documents. Each item links to its source.
Numbers come from those documents or from the runs recorded in [TESTING.md](TESTING.md); none are estimates.

AIPISH is an investigation aid. Its scores, classes, hypotheses and locations are **investigative indicators,
not proof**: not proof of what a message is, who sent it, where they are, or that a message is safe.

## 1. Dataset ([data/DATA_CARD.md](../data/DATA_CARD.md), [docs/ml/MODEL_CARD.md](ml/MODEL_CARD.md))

- **Era.** Legitimate mail spans 1998–2003 and phishing mostly 2004–2007 (DATA_CARD §9). Expect lower
  performance on modern mail.
- **Source and era confounding.** Each class comes from one or two corpora, so part of the accuracy can come
  from corpus style rather than threat signals. The model card gives an example: SHAP shows `has_html = 0`
  pushing away from `phishing`, which reflects plain-text Enron and SpamAssassin mail, not a real-world rule.
- **Synthetic classes.** `impersonated` and `fraud` are synthetic templates written by one author. The test set
  holds 4 unseen templates (102 messages); their 0.98–1.00 scores measure generalisation to new templates by
  the same author, **not** to real business email compromise.
- **No `suspicious` class.** No approved source exists, so it has 0 samples and the model never predicts it.
  The combined-risk conflict flag is the documented substitute.
- **Enron is assumed legitimate.** Enron has no labels; only custodians' sent folders are used and labelled
  `legitimate` by assumption, so forwarded spam can slip in. Nazario phishing is hand-labelled by one person.
- **Raw corpora are local only.** SpamAssassin and Enron content is never committed or redistributed.

## 2. ML ensemble ([docs/ml/FINAL_EVALUATION_v1.md](ml/FINAL_EVALUATION_v1.md))

- **Evaluation numbers (test split, 1,709 messages, ensemble).** Five-class macro-F1 0.965. Threat vs
  legitimate: precision 0.970, recall 0.926, F1 0.948. Real messages only (legitimate and phishing): ensemble
  macro-F1 0.954; threat vs legitimate F1 0.936.
- **Main error mode.** 43 of 482 test phishing messages were missed as legitimate; 17 legitimate messages were
  flagged as phishing.
- **These are not "validated" or "accurate" claims for real mail.** They hold for this split of old,
  partly synthetic, source-confounded data only.
- **Scores are uncalibrated.** The class score is the model's probability for that class, not a certainty.
- **SHAP explains the XGBoost component only.** DistilRoBERTa carries 50 % of the ensemble weight and is not
  explained, so SHAP values do not explain the ensemble prediction. SHAP values are associations, not causes.
- **No raw bytes, no ML on re-assessment.** With the default `CASE_EVIDENCE_STORE=hash_only`, a stored
  analysis keeps only its SHA-256, so a later AI assessment of it reports ML and SHAP as `unavailable`.
  Upload-time classification is stored at upload.

## 3. Rule engine ([docs/CHANGELOG.md](CHANGELOG.md) P5d.1, [docs/risk/README.md](risk/README.md))

- **Low recall on the corpora.** On the test split (offline, no DNS or authentication), rules
  `suspicious or higher` reach recall 0.349 at a 9.60 % false-positive rate; `phishing_fraud_likely` reaches
  recall 0.065.
- **P5d.1 fix lowered recall further.** Removing a false Return-Path mismatch reduced rule-only recall on a
  500-message real phishing sample from 30.4 % to 21.8 % ("likely") and from 63.6 % to 54.4 % (flagged).
  Rule weights were not re-baselined afterwards.
- **Legitimate mail is often flagged.** In that same P5d.1 study, 200 of 500 (40 %) legitimate messages were
  still `suspicious or higher`. This is a different sample and setup from the 9.60 % test-split figure, so
  the two numbers are not directly comparable; both are from offline runs without authentication.
- **Heuristic.** 18 deterministic rules with fixed weights; `lookalike_domain` needs a reference domain.

## 4. Local LLM (Mistral via Ollama) ([docs/llm/README.md](llm/README.md))

- **Latency.** Measured in this release on an Apple M4 (Docker backend → host Ollama, `mistral`): about 85–87 s
  for the full upload path (ML + SHAP + summary) and 46–56 s for the summary of a stored analysis.
- **Hallucination risk.** Output validation is pattern-based. It catches the failure types it was designed for
  (unknown entities, false passes, unwarranted "safe" verdicts), not every wrong statement.
- **Constrained recommendations.** Model advice is never shown directly; it is mapped to a closed set of fixed
  templates, and unrecognised advice is rejected, so some useful suggestions are rejected too.
- **Optional.** Without Ollama the assessment reports `unavailable`; nothing falls back silently.

## 5. Combined risk index ([docs/risk/README.md](risk/README.md))

- **An index, not a probability.** It is not a calibrated likelihood for any real mailbox.
- **Validation-derived thresholds** on old, partly synthetic data. On the test split, combined high+ matches ML
  alone (F1 0.9475); combined medium+ doubles the false-positive rate (1.51 % → 3.02 %).
- **No behavioural or sender-history signal.**
- **Low or minimal is not evidence of safety.** Missing components and absent intel are listed, never assumed
  clean.

## 6. Correlation and campaigns ([docs/correlation/README.md](correlation/README.md))

- **Weights and thresholds tuned on synthetic data only;** there are no real campaign labels.
- **Chaining.** Connected components join A and C when A–B and B–C link, even if A and C share nothing. Each
  link is listed in the reasons.
- **Shared hosting and carrier NAT** can still link unrelated mail; the stoplist covers known providers only.
- **No analyst overrides** (confirm, reject, rename).
- **Full recompute on every upload,** synchronously: 3.9 s for a rebuild at 1,500 analyses in this release's
  throwaway-DB run (see [TESTING.md](TESTING.md)).

## 7. MITRE ATT&CK and source type ([docs/attack/README.md](attack/README.md))

- **Single-message approximations.** Techniques are inferred from one email's evidence, with heuristic
  confidence; they are not observed adversary behaviour.
- **Source-type hypotheses** for infrastructure were tested with SIMULATED intel only; there is no
  sender-history baseline and no analyst override.

## 8. Geolocation ([docs/geo/README.md](geo/README.md))

- **Approximate.** IP location is a database estimate of network infrastructure, never a person's location.
- **Anycast.** Anycast addresses (for example 8.8.8.8 in the live run) resolve to one representative point.
- **VPN, proxy, hosting and Tor** distort results. IPinfo privacy flags are not returned on the free plan and are
  shown as "unavailable".
- **MaxMind GeoIP2 is not configured** (no licence or database). The Docker demo map uses SIMULATED points,
  labelled as such.

## 9. Threat intelligence ([docs/intel/README.md](intel/README.md), [LIVE_VERIFICATION.md](intel/LIVE_VERIFICATION.md))

- **Free/public tiers, non-commercial.** VirusTotal public API: 4 requests/minute.
- **Live verification scope.** One run on 2026-11-22 with four approved indicators (8.8.8.8, 1.1.1.1,
  example.com, the EICAR SHA-256) and the Tor exit list, 16 requests in total.
- **Not verified live:** 401/403/429/5xx/timeout and quota mappings; Shodan `not_permitted`; IPinfo privacy
  fields (paid plan); VirusTotal domain lookups through the service path; how a Tor exit appears in IPinfo;
  live upload-time ip-api enrichment. MISP and MaxMind are not configured.
- **Absence of reports is not proof of safety.** No-record and below-threshold results are labelled that way.
- **Opt-in, consent-gated** and informational only; intel never changes the rule verdict.

## 10. Security and privacy ([docs/auth/README.md](auth/README.md), [docs/audit/README.md](audit/README.md))

- **Local password authentication with JWT.** No OAuth 2.0/OIDC, no SSO, no MFA, no refresh tokens, no
  signing-key rotation.
- **Login throttling is in memory** (per process); it resets on restart and is not shared between workers.
- **Global roles** (viewer, analyst, admin): no per-case ownership or ACLs.
- **Data is stored unencrypted at rest** in the database.
- **Masking is presentation only.** Viewers see partially masked addresses and no bodies or display names, but
  **subjects are not masked**.
- **Upload type check** accepts a file whose name ends in `.eml` or whose content type is `message/rfc822`,
  `application/octet-stream` or empty; content is parsed defensively but not sniffed.

## 11. Audit log and custody ([docs/audit/README.md](audit/README.md))

- **Tamper-evident, not tamper-proof.** An attacker with database write access and the audit key can forge
  the chain; external checkpoints reduce that risk. There is no WORM storage and no external timestamping.
- **No audit-key rotation.** Changing `AIPISH_AUDIT_KEY` makes every existing event fail verification.
- **Append-only triggers can be bypassed** by a database superuser or table owner; the chain detects it.
- **SHA-256 detects change** to a stored file but does not make storage tamper-proof.

## 12. Retention ([docs/audit/README.md](audit/README.md))

- **No built-in scheduler.** Retention runs from `scripts/retention-run.sh` (cron) or the Compose `retention`
  profile. Policies are disabled by default (0 days).

## 13. Alerts ([docs/alerts/README.md](alerts/README.md))

- **Not real-time.** Alerts are raised when an analysis is processed; there is no mailbox ingestion
  (R36: no IMAP or Graph).
- **E-mail delivery** was verified only against a local fake SMTP sink; the demo never sends e-mail.

## 14. Deployment ([docs/deployment/README.md](deployment/README.md))

- **Single uvicorn worker.**
- **arm64 verified on a real run; amd64 images are built in CI only.**
- **No TLS certificates are shipped;** TLS termination is documented, not provided.
- **No SQLite → PostgreSQL data migration tool;** the documented path is to re-seed. See also
  [DEV_DB_UPGRADE.md](DEV_DB_UPGRADE.md).
- **Backend image size** is 2.26 GB with the ML stack (CPU-only PyTorch).

## 15. Scalability

- Correlation recomputes all campaigns synchronously on each upload (R35: no background workers).
- Analytics derive charts from at most the 2,000 most recent analyses (`MAX_WINDOW` in
  `backend/app/geo/analytics.py`); `/analytics/summary` took about 430 ms at 1,500 analyses on SQLite.
- Search uses SQL `LIKE`/`ILIKE` queries, not a full-text index (R52).

## 16. Testing gaps ([TESTING.md](TESTING.md))

- No browser end-to-end suite; the UI was checked by component tests and manual browser sweeps.
- The smoke test runs against the synthetic demo only.

## 17. Future work

- Re-baseline rule weights and thresholds on the corrected header comparison and on modern labelled mail.
- Real BEC and `suspicious` data, recent corpora, and calibration of the ML scores.
- Explanations for the transformer component.
- Mailbox ingestion (R36) with background workers (R35) and incremental correlation.
- OAuth 2.0/OIDC with MFA (R53), per-case ACLs, encryption at rest, subject masking for viewers.
- External timestamping or WORM storage for audit checkpoints; audit-key rotation.
- Live verification of provider error paths; MISP and MaxMind when access exists.
