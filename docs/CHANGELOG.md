# Changelog

## P5z — final hardening, wording audit, regression and documentation pack (v1.0-pbl)

- **Wording fixes:**
  - PDF section 9 custody sentence replaced. The old sentence ("application-level integrity checks … not a
    tamper-resistant cryptographic chain of custody … hash-chained / WORM storage not implemented") predated
    the P5e hash chain. The new shared `CUSTODY_LIMITATION` (`app/audit/__init__.py`) says SHA-256 detects change
    to stored evidence, the audit log is a tamper-evident HMAC hash chain and not tamper-proof, and no WORM
    storage is used. The HTML report now lists the same sentence.
  - Analyse page: "the raw file is retained" was false under the default `hash_only` policy. It now says only
    the SHA-256 and size are kept and which indicators can leave the host.
  - Search verdict filter: removed `low_risk` and `clean` (the engine never produces them) and added `minimal`.
  - `docs/deployment/README.md`: stale "only three migration steps" corrected (there are ten).
  - `PROJECT_REPORT.md` (2026-10-11) marked as historical and superseded.
- **Matrix:** every row cross-checked. R25 IMP-U → VER (browser sweep); R4, R7, R27, R31, R33, R37, R38 and R52
  corrected without a status change. Totals: 38 VER, 7 IMP-U, 8 PART, 0 STUB, 4 MISS, 3 BLK.
- **New scripts and checks:**
  - `scripts/matrix_counts.py`: recomputes the totals and generates the table in `docs/REQUIREMENTS_SUMMARY.md`.
  - `scripts/check_docs.py`: checks links, paths and environment variables.
  - `backend/scripts/gen_doc_tables.py`: generates the route, role, table and migration tables in
    `docs/ARCHITECTURE.md`.
  - `scripts/smoke.py`: end-to-end smoke test against the Compose demo (36 checks).
  - The checks run in CI (security job) and in `tests/unit/test_docs_consistency.py`.
- **Env template:** `.env.example` now lists `AIPISH_ML_AT_UPLOAD`, `AIPISH_ML_UPLOAD_TIMEOUT_SECONDS`,
  `AIPISH_TORCH_THREADS`, `OLLAMA_*`, `LLM_TIMEOUT_SECONDS`, `LLM_NUM_CTX` and `LLM_SEED`, which were documented
  or read by the code but missing.
- **Tests added:**
  - custody wording in the PDF and HTML (`test_assessment_report.py`);
  - documentation consistency (3 tests);
  - Search verdict options (`Correlation.test.tsx`).
  - No existing test was changed or weakened.
- **Docs:**
  - `README.md` rewritten.
  - New: `docs/ARCHITECTURE.md`, `docs/REQUIREMENTS_SUMMARY.md`, `docs/DEMO_SCRIPT.md`, `docs/LIMITATIONS.md`,
    `docs/TESTING.md`, `docs/PROJECT_SUMMARY.md`, `docs/DEV_DB_UPGRADE.md` and `THIRD_PARTY_NOTICES.md`.
- **Unchanged:** detection, ML, rules, risk scoring, alerts, intel providers and authentication behaviour. The
  BEC demo still gives rules 100 / `phishing_fraud_likely`, ML impersonated 0.4355 and combined HIGH 80.

## P5a-live — live threat-intelligence provider verification and response-shape fixes

- **Live verification (first real provider calls, 2026-11-22, free tiers):**
  - VirusTotal (IP, hash, domain shape), AbuseIPDB, Shodan, IPinfo and the Tor bulk list.
  - Approved indicators only: `8.8.8.8`, `1.1.1.1`, `example.com`, and the EICAR SHA-256 hash (lookup only).
  - 16 requests, all GET with an empty body. No 401/403/429 or quota errors.
  - Also verified: cache hits, the VirusTotal limiter, missing credentials, and the consent-disabled and offline
    paths, which make no requests.
  - Secret scan of the databases, logs, reports, fixtures and the diff: no key found.
  - See `docs/intel/LIVE_VERIFICATION.md`.
- **Fixes, from real response shapes:**
  - **VirusTotal threshold:** a result is flagged only when at least `INTEL_VT_FLAG_MIN_ENGINES` engines (default
    3) report it malicious. Fewer detections give `record_found` with a "below the flag threshold" message. 8.8.8.8
    and 1.1.1.1 each had 1 of 92 engines; the EICAR hash is still flagged at 65 of 67.
  - **IPinfo anycast:** the result carries `anycast` and a caveat, the geo service passes it on, and the Geo tab
    shows an "Anycast" row.
  - **ATT&CK source type:** only an explicit `true` IPinfo privacy flag counts. The string "unavailable" (no
    privacy block on the free plan) had made 8.8.8.8 "anonymised infrastructure: likely".
- **Request audit hook:** `INTEL_REQUEST_LOG` writes one redacted JSON line per provider request: method, host,
  path, parameter and header names, and body length. It never writes key values. Off by default.
- **Tests:**
  - Sanitised real-shape fixtures in `tests/fixtures/intel/live_shapes/`.
  - `test_intel_live_shapes.py` (11 tests) and a Geo anycast frontend test.
  - The opt-in live test now covers the 11 approved cases, with VirusTotal paced at 16 s per call. It is skipped
    in CI.
  - New synthetic fixture `eml/synthetic_public_hop_8888.eml`. Its legacy ML-feature snapshot entry was computed
    with commit 32cdeed's code.
- **Counts:**
  - Backend: 784 passed / 13 skipped (SQLite); 785 passed / 12 skipped (PostgreSQL).
  - Frontend: 204 passed.
  - The BEC demo is unchanged: rules 100 / `phishing_fraud_likely`; ML impersonated 0.4355.

## P5k-lite — mail-parser cross-check (R43) and Jinja2 HTML report (R55)

- **Parser cross-check (informational):**
  - mail-parser 4.10.0 (pinned in `requirements.txt` and `constraints.txt`) runs as a second parser over the
    same bytes at upload. It is bounded by `PARSER_CROSSCHECK_MAX_MB` and
    `PARSER_CROSSCHECK_TIMEOUT_SECONDS`, and failure-isolated.
  - It compares addresses, Return-Path, the Received chain, attachments (count, type, SHA-256 and size),
    MIME structure, duplicate single-instance headers, charsets, and Date/Message-ID/Subject (as a hash).
  - The result (status, differences with severity and `P` evidence ids, counts; no email content) is stored
    in `analysis.parser_crosscheck` (migration step 10).
  - It appears in the Headers tab, the PDF and the HTML report, and never feeds the rule score, ML, risk or
    alerts.
- **HTML report:**
  - `GET /api/v1/analyses/{id}/report.html` (viewer+) renders the forensic report with Jinja2 (autoescape,
    no `|safe`): one base template plus section partials.
  - It uses the same inputs, masking ("MASKED VIEW"), redaction notice and version pins as the PDF, through
    the shared `report_inputs()`.
  - The file is self-contained: no scripts and no external resources; dark console look on screen,
    print-friendly.
  - Response headers: restrictive CSP, `nosniff`, `Content-Disposition: attachment`. Each download is
    audited (`report_generated`, `format: html`).
  - HTML-only sections: 7D IOCs, 7E location table and 8B custody note.
- **PDF:** unchanged except for the new parser cross-check subsection in section 5. It remains ReportLab.
- **Frontend:** "Download HTML report" next to the PDF button (authenticated fetch to blob, same version
  pins) and a "Parser cross-check" panel in the Headers & relay tab.
- **Unchanged:** detection, rules, ML, risk scoring, alerts and intel providers. BEC is still 100 /
  `phishing_fraud_likely` and ML `impersonated` 0.4355.

## P5f — Risk-based alerts (in-app inbox, lifecycle, dedupe, optional e-mail)

- **Honesty:** alerts are raised when an analysis is processed (upload, intel run, AI assessment,
  recompute, campaign update). There is no real-time mailbox monitoring, because IMAP/Graph ingestion is
  not implemented.
- **Model:** `alert` and append-only `alert_event` tables (migration step 9). Alerts hold identifiers,
  labels and scores only: never subject, body, recipients, addresses or display names.
- **Rules:**
  - `high_risk_analysis`: combined level ≥ high by default; critical → critical.
  - `hard_evidence_floor`: a floor fired below the minimum level.
  - `review_conflict`: low, on by default.
  - `new_campaign`: medium+ confidence.
  - `campaign_growth`: debounced, one open alert.
  - All are configurable (`ALERTS_ENABLED`, `ALERT_*`).
- **Lifecycle:**
  - One open alert per type and subject: message SHA-256, or campaign.
  - Identical re-uploads only count occurrences.
  - A higher level escalates the open alert, and reopens it if it was acknowledged.
  - A lower level never auto-resolves.
  - After resolution, only a higher level opens a new alert.
  - Concurrency-safe acknowledge / resolve (note required) / reopen, with 409 on invalid or stale
    transitions. Every change writes alert history and an audit event with the actor.
- **Isolation:** the alert engine never alters uploads, assessments or risk results. Errors are audited as
  `alert_engine_error`. `backfill-risk` creates no alerts unless `--alerts` is given.
- **API:**
  - `GET /alerts`, `/alerts/summary` and `/alerts/{id}` (viewer+);
  - `POST /alerts/{id}/acknowledge|resolve|reopen` (analyst+);
  - `GET /admin/alerts/config` (admin; secrets omitted).
- **Optional e-mail (OFF by default):**
  - stdlib smtplib, with STARTTLS/SSL certificate verification;
  - Jinja2 3.1.6 templates with autoescape (now an explicit dependency);
  - background thread with a timeout and one retry, rate limit, one e-mail per state change, recorded
    delivery status, audited;
  - header-injection safe;
  - content limited to ids, labels, scores, a link and a disclaimer.
  - The demo forces e-mail off.
- **Retention:** delete mode removes an analysis's alerts and their history. Redact mode keeps them and
  marks the analysis as redacted.
- **Frontend:**
  - top-bar new-alert badge;
  - Alerts page (filters, pagination, detail with pinned risk version, history, actions, admin
    configuration);
  - Overview "Open alerts" panel;
  - analysis open-alert strip.
- **Unchanged:** detection, rules, ML, risk scoring and intel providers. BEC is still 100 /
  `phishing_fraud_likely` and ML `impersonated` 0.4355.

## P5h — Explainable combined risk assessment

- **Combined risk index (0–100), an additional result:**
  - Levels minimal / low / medium / high / critical / indeterminate, with confidence, agreement and flags.
  - Each component is listed with its status, value, role, effect and evidence ids.
  - Engine: `app/risk/engine.py`. It is pure and deterministic, and versioned by `engine_version` and
    `config_version`.
  - The rule score, verdict and ML outputs are never changed.
- **Design:**
  - The ML threat index is the primary signal. Rule points are never added on top, because the XGBoost
    features already contain the rule scores.
  - Rules act through floors:
    - hard evidence H1 risky attachment, H2 verified auth failure + identity, H3 payment/credential +
      identity (all high);
    - rule-suspicious → low;
    - conflict → medium;
    - rules are the primary signal when ML is missing.
  - Consented threat intel can only raise, capped at +15. Clean or no-record results contribute nothing.
  - Campaign and ATT&CK context have no score effect.
  - Missing components never imply legitimate: the floor is low, and with both missing the result is
    indeterminate.
  - Thresholds come from the validation split (`t_med 0.36`, `t_high 0.50`).
  - Design and properties: `docs/risk/README.md`.
- **Offline evaluation** (`backend/scripts/evaluate_risk.py`, results in `docs/risk/evaluation_v1.*`), test
  split of 1,709:
  - combined high+ F1 0.9475, identical to ML alone;
  - combined medium+ F1 0.9463 with FPR 3.02 %, against 9.60 % for rules suspicious+.
  - The strict rule band has a lower FPR (0.80 %) but 6.5 % recall.
- **Upload-time ML:**
  - The cheap ensemble classification now runs at every upload when models are available. It is bounded
    (`AIPISH_ML_UPLOAD_TIMEOUT_SECONDS`), failure-isolated, can be switched off with
    `AIPISH_ML_AT_UPLOAD=0`, and is stored in the new `ml_classification` table.
  - The SHAP and Mistral opt-in is unchanged.
- **Persistence:** append-only `risk_assessment` versions (fingerprinted, idempotent) in migration step 8.
  They are computed at upload, after intel runs, after AI assessments, on demand, and by
  `python -m app.cli backfill-risk`.
- **API:**
  - `GET /analyses/{id}/risk[?version=]` and `GET /analyses/{id}/risk/history` (viewer+, masked per P5e);
  - `POST /analyses/{id}/risk/recompute` (analyst+, audited as `risk_recomputed`);
  - additive `combined_level`, `combined_score` and `combined_confidence` in the analyses list and search,
    and `combined_levels` in analytics;
  - `risk_id` pins the PDF section.
- **PDF:** new section 8A, version-pinned (`risk_id` is recorded in `report_generated`), escaped and
  masked-view compatible.
- **Frontend:**
  - a combined-risk cell in the verdict strip, separate from the rule and ML cells (3×2 below 2xl);
  - a Risk tab with components, evidence, conflict banner, version picker, recompute and disclaimers;
  - a combined level in History, Overview and Search;
  - a combined-level chart in Analytics.
- **Unchanged:** the 18 rules and their scores, the ML models, ensemble weights, SHAP, LLM prompts, and the
  existing PDF sections. BEC is still 100 / `phishing_fraud_likely` and ML `impersonated` 0.4355.

## P5e — Tamper-evident audit log, retention enforcement and personal-data masking

- **Audit chain:**
  - `audit_event` gains `seq`, `prev_hash` and `event_hash` (an HMAC-SHA256 chain keyed by
    `AIPISH_AUDIT_KEY`), plus `target_type`, `target_id`, `outcome` and `source_ip`.
  - Appends are serialised through the `audit_chain_head` row.
  - Legacy events are chained once, without changing their content, behind a `chain_genesis` marker.
  - `UPDATE`, `DELETE` and `TRUNCATE` triggers on SQLite and PostgreSQL. A database superuser can bypass
    them, and the chain then detects the change.
  - The guarantee is stated as "tamper-evident (HMAC hash chain), not tamper-proof".
- **Key handling:** production fails closed on a missing or weak key, and so do Compose and the
  pre-flight. In dev the key is generated into the gitignored `.env` without being printed.
  `demo-up.sh` generates it.
- **Coverage:**
  - Uploads, views (de-duplicated per 15 minutes), searches (query truncated to 64 characters).
  - Case membership, AI assessment runs, ML runs.
  - Audit verify, checkpoint and export; retention, holds and erasure.
  - Details are sanitised: no bodies, subjects, recipients, passwords, tokens or keys.
- **API and CLI:**
  - `GET /audit/events`, `/audit/export` (CSV or JSON, capped at 10,000, audited), `/audit/verify` and
    `/audit/checkpoint`;
  - `GET /analyses/{id}/custody`;
  - admin retention, legal-hold and erasure endpoints;
  - CLI `audit-verify` (exit 1 when broken), `audit-checkpoint` and `retention-run [--apply]`.
- **Retention:**
  - Configured with `RETENTION_ANALYSIS_DAYS`, `RETENTION_EVIDENCE_DAYS`, `RETENTION_MODE`
    (redact | delete) and `RETENTION_GRACE_DAYS`. It is disabled by default, and runs are dry runs
    unless applied.
  - Legal holds exempt analyses from retention and erasure. Audit events are never purged.
  - There is no built-in scheduler: use `scripts/retention-run.sh` (cron) or the Compose `retention`
    profile.
- **Masking:** the new `pii:view` permission (analyst, admin). Viewers get masked addresses, restricted
  display names and no body through one response serializer. Their PDF is built from masked data and
  labelled "MASKED VIEW".
- **Frontend:** admin Audit and Retention pages, an analysis Custody tab, redacted, legal-hold and
  restricted tags, privacy banners, and a retention column in History and Case.
- **Schema:** migration steps 5 (`audit_and_retention_columns`), 6 (`audit_chain_genesis`) and 7
  (`audit_append_only_triggers`), and new tables `audit_chain_head` and `legal_hold`.
- **Unchanged:** detection, ML, rules, intel providers and scores. BEC is still 100 /
  `phishing_fraud_likely` and ML `impersonated` 0.4355.

## P5g — Infrastructure geolocation map and analytics

- **Geo endpoints:**
  - `GET /api/v1/analyses/{id}/geo` and `GET /api/v1/campaigns/{id}/geo` (viewer+) show only stored
    data (consented IPinfo, upload ip-api enrichment, SIMULATED demo observations), with no lookups.
  - Private IPs are never returned; IPs without coordinates are listed as "no location data".
  - Anonymity signals are reported only when a stored provider result backs them; stale and SIMULATED
    are flagged.
- **Analytics:** `GET /api/v1/analytics/summary` (viewer+) gives bounded, dialect-safe aggregates.
- **Health hardening:** anonymous `GET /api/v1/health` returns only `{"status"}`. Version and environment
  moved to the authenticated `GET /api/v1/system/info`, and the status bar uses `/health/ready` plus
  `/system/info`.
- **Schema:** a new `geo_observation` table (migration step 4), written only by the opt-in, offline demo
  seeding (`source="simulated-demo"`, RFC 5398 ASNs). `init-demo` also ingests the synthetic Tor-origin
  sample.
- **Frontend:** analysis "Geo" tab, campaign "Infrastructure locations" panel and an "Analytics" page.
  Leaflet with a bundled Natural Earth outline (no tiles) and Plotly basic, both lazy-loaded.
- **Unchanged:** detection, ML, rules, intel providers, scores and the PDF. BEC is still 100 /
  `phishing_fraud_likely` and ML `impersonated` 0.4355.

## P5i — PostgreSQL, Docker Compose, Nginx and CI

- **Database:**
  - PostgreSQL support via `DATABASE_URL` (psycopg 3.3.9); SQLite remains the dev/test default.
  - Versioned, idempotent migrations (`app/core/migrations.py`, `schema_migrations`, advisory lock on
    PostgreSQL), used by start-up and every CLI command.
  - New commands: `python -m app.cli migrate` and `python -m app.cli init-demo`.
- **Dialect fixes:**
  - Search is now case-insensitive on PostgreSQL too (`ILIKE`; unchanged on SQLite).
  - PostgreSQL connections are pinned to UTC; the API returns `+00:00` timestamps there. SQLite output is
    unchanged.
  - No other PostgreSQL-only failures: the full suite passes on both dialects.
- **Security:**
  - `GET /api/v1/health/ready` (anonymous, `{"status"}` only).
  - `X-Forwarded-For` is honoured only from `AIPISH_TRUSTED_PROXIES`.
  - `APP_ENV=production` fails closed on SQLite or a weak DB password.
  - `APP_ENV=demo` runs without live DNS or intel lookups.
- **Tests:**
  - The suite runs on a fresh temporary SQLite file by default (it no longer defaults to
    `backend/db/app.sqlite`).
  - Opt-in PostgreSQL test database (`TEST_DATABASE_URL`, test-named databases only).
- **Containers:** backend and web images, nginx reverse proxy, `deploy/docker-compose.yml`,
  `scripts/demo-up.sh` / `demo-reset.sh`.
- **CI:** GitHub Actions workflow, gitleaks allow-list of reviewed false positives, forbidden-file check.
- **Unchanged:** detection logic, scores, ML outputs, PDF content and the frontend UI. BEC is still
  100 / `phishing_fraud_likely` and ML `impersonated` 0.4355, verified through the container stack on
  PostgreSQL.

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
