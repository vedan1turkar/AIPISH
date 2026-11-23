# AIPISH requirements traceability matrix (R1–R60)

This matrix traces AIPISH against the PBL Review 0 document, Group G7. The P5 audit set its baseline at
`6bd00ca`. It was updated for **P5a: threat-intelligence provider integrations** (`ed1b913`), **P5b:
authentication, JWT and RBAC** (`52aa1c7`) and **P5c: cross-case correlation and candidate campaigns** (`887936d`) and **P5d: MITRE ATT&CK mapping and source-type
classification** and **P5i: PostgreSQL, Docker Compose, Nginx and CI** and **P5g: infrastructure geolocation map and analytics** and **P5e: tamper-evident audit log, retention
enforcement and personal-data masking** and **P5h: explainable combined risk assessment** and **P5f: risk-based alerts** and **P5k-lite: mail-parser cross-check and Jinja2 HTML report** and **P5a-live: live threat-intelligence provider verification** and **P5z: final hardening, wording audit and documentation pack**.

**ID provenance:**
- R1–R40 come from the original project matrix.
- R41–R60 were re-derived during the P5 audit from PBL §4.6, §5 and §8 and the recommended stack, and are
  marked `*`.

Recommended technologies are listed for traceability. They are not functional scope.

## Status legend

| Code | Meaning |
|---|---|
| **VER** | Implemented and verified (tests plus a real-app run). |
| **IMP-U** | Implemented, verification incomplete. For P5a providers this means **mocked-verified**: unit/integration tests plus a real-app run against a SIMULATED loopback stub. Since P5a-live, R44, R45, R46 and R49 are live-verified for the exercised paths only (see `docs/intel/LIVE_VERIFICATION.md`). |
| **PART** | Partially implemented. |
| **STUB** | Stub or mock only. |
| **MISS** | Missing. |
| **BLK** | Blocked by an external dependency. |

## Counts

| Status | Before P5a | After P5a | After P5b | After P5c | After P5d | After P5i | After P5g | After P5e | After P5h | After P5f | After P5k-lite | After P5a-live | After P5z |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| VER | 16 | 16 | 18 | 21 | 22 | 25 | 27 | 30 | 31 | 31 | 33 | 37 | 38 |
| IMP-U | 3 | 7 | 7 | 9 | 10 | 10 | 12 | 12 | 12 | 12 | 12 | 8 | 7 |
| PART | 16 | 18 | 18 | 14 | 14 | 13 | 11 | 8 | 7 | 8 | 8 | 8 | 8 |
| STUB | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| MISS | 21 | 16 | 14 | 13 | 11 | 9 | 7 | 7 | 7 | 6 | 4 | 4 | 4 |
| BLK | 3 | 3 | 3 | 3 | 3 | 3 | 3 | 3 | 3 | 3 | 3 | 3 | 3 |
| **Total** | 60 | 60 | 60 | 60 | 60 | 60 | 60 | 60 | 60 | 60 | 60 | 60 | 60 |

## Changes made in P5z

Every row was cross-checked against the cited code, tests and documents. Totals are now computed by
`scripts/matrix_counts.py`, which CI runs with `--check` (and `backend/tests/unit/test_docs_consistency.py`).

| ID | Before | After | Why |
|---|---|---|---|
| R25 | IMP-U | VER | Every result tab and page was exercised in a browser on the from-scratch Docker demo as viewer, analyst and admin (P5z sweep), on top of the component tests. The stale gap ("Geo shown only from live enrichment or IPinfo") was replaced by the open low-severity UI issues. |

Corrected without a status change:
- **R4:** gap reworded: SHAP explains the XGBoost component only, not DistilRoBERTa or the ensemble prediction.
- **R7:** evidence path corrected to `backend/scripts/evaluate_risk.py`.
- **R27:** HTML report and the smoke-test downloads added as evidence.
- **R31:** caveat made explicit: viewers still see subjects unmasked.
- **R33:** counts updated to this release's runs.
- **R37, R38:** from-scratch build with `scripts/smoke.py`, and the documentation checks in CI.
- **R52:** gap filled in: `/search` uses SQL `LIKE`/`ILIKE`; no full-text index.

## Changes made in P5a-live

These are the first live provider calls, made on free tiers on 2026-11-22. Only the approved indicators were
sent: `8.8.8.8`, `1.1.1.1`, `example.com`, the EICAR SHA-256 hash (lookup only) and the Tor bulk list. There were
16 requests. Details are in `docs/intel/LIVE_VERIFICATION.md`.

| ID | Before | After | Why |
|---|---|---|---|
| R44 | IMP-U | VER | VirusTotal was verified live for the paths exercised.<br>**Paths exercised:**<ul><li>IP and file-hash GETs through the service;</li><li>the domain shape through the adapter (the service refuses example.com as a documentation domain);</li><li>a cache hit;</li><li>the local 4/min limiter refusing a 5th call;</li><li>consent-disabled and offline paths with no request.</li></ul>**Fixed:** a single-engine detection on a benign IP (1/92) was flagged. There is now a threshold, `INTEL_VT_FLAG_MIN_ENGINES` (default 3), with a regression test on the real shape.<br>**Not verified live:** 401/403/429/quota/5xx, the daily cap and URL lookups. |
| R45 | IMP-U | VER | AbuseIPDB was verified live: 200 and `record_found` below the threshold (confidence 0, with 217/290 reports); the rate-limit headers were observed; cache hit; consent and offline paths.<br>**Not verified live:** error mappings and quota. |
| R46 | IMP-U | VER | Shodan was verified live: the free plan allows host lookups (`record_found`; ports, org, ASN, hostnames); the key stays in the query string and is never logged.<br>**Not verified live:** 404 → `no_record`, `not_permitted` and the error mappings. |
| R49 | IMP-U | VER | IPinfo was verified live: geo, ASN/org, and `anycast`; the free plan returns no privacy block, so the flags show as "unavailable"; with no token, `missing_credentials` and no request.<br>**Fixed:**<ul><li>anycast is now shown (adapter caveat, Geo row);</li><li>ATT&CK counted "unavailable" privacy flags as true.</li></ul>**Not verified live:** paid-plan privacy flags and the error mappings. |
| R14 | IMP-U | IMP-U | **Note:** the Geo tab was verified with a real consented IPinfo location (8.8.8.8, Mountain View, AS15169; no SIMULATED label, anycast caveat shown). Still IMP-U: live upload-time ip-api enrichment is unverified, and MaxMind is blocked (R48). |
| R57 | IMP-U | IMP-U | **Note:** the map was verified with one real IPinfo point at 1440 and 1920. It is still one anycast point on one run; multi-point real data is unverified. |
| R15 | PART | PART | **Note:**<ul><li>the Tor list was verified live (1,263 IPs; listed vs not listed);</li><li>IPinfo privacy flags are not returned on the free plan, and every consumer now treats them as unavailable rather than true;</li><li>AbuseIPDB usage type was observed live.</li></ul>Still no open-relay or botnet source. |
| R18 | IMP-U | IMP-U | **Note:** the threat-intel input is now live-verified for the exercised paths. With real data, combined risk stayed MINIMAL, there were no alerts, and source type and ATT&CK were sensible after the fix. Still IMP-U: the correlation weights are tuned on synthetic data only. |
| R33 | VER | VER | Counts updated: backend 784 / 13 skipped (SQLite: 12 opt-in live tests and 1 PostgreSQL-only test), 785 / 12 skipped (PostgreSQL); frontend 204. |

## Changes made in P5k-lite

| ID | Before | After | Why |
|---|---|---|---|
| R43 | MISS | VER | mail-parser 4.10.0 (pinned) runs as a second, independent parser over the same bytes at upload; normalised views (addresses, Return-Path, Received chain, attachments with SHA-256, MIME structure, duplicate single-instance headers, charsets, Date/Message-ID/Subject-as-hash) are compared and stored as an informational result (status, differences with severity and P-evidence ids; no email content) shown in the Headers tab, the PDF and the HTML report. Verified by tests on normal fixtures (agree) and crafted differentials (duplicate From, conflicting Return-Path, folded From, unclosed and reused boundaries, duplicate Date), failure isolation (import/parse/timeout/size), unchanged rule/risk/alert outputs, SQLite and PostgreSQL, and a Docker/nginx run. Limits: two parsers only; malformed Received headers that both keep verbatim are not flagged; never feeds any score. |
| R55 | MISS | VER | Jinja2 report templates: a self-contained HTML forensic report (`/analyses/{id}/report.html`, Jinja2 with autoescape, no scripts or external resources, restrictive CSP, same inputs, masking and version pins as the PDF, audited) plus the P5f alert e-mail templates. The PDF remains ReportLab. |
| R33 | VER | VER | Counts updated: backend 773 / 7 skipped (SQLite), 774 / 6 skipped (PostgreSQL); frontend 203 (the row had not been updated in P5f; it now reflects P5f and P5k-lite). |

## Changes made in P5f

| ID | Before | After | Why |
|---|---|---|---|
| R24 | MISS | PART | Event-driven, risk-based alerts are implemented and verified: five alert types from the combined risk index and campaign detection, one open alert per subject, occurrence counting for identical re-uploads, escalation and reopen rules, concurrency-safe acknowledge/resolve/reopen with history and audit, an in-app inbox with top-bar badge, and optional SMTP e-mail (OFF by default; Jinja2 templates; tested against a fake SMTP sink only). Verified on SQLite and PostgreSQL and in a Docker/nginx run. **Not real-time:** alerts are raised when an analysis is processed; mailbox monitoring needs ingestion (R36), which is missing. No real SMTP server was used. |
| R55 | MISS | MISS | Jinja2 is now used, but only for the alert e-mail templates; forensic report templates remain ReportLab, so the requirement (Jinja2 report templates) is still not met. |
| R33 | VER | VER | Counts updated (see the matrix row). |

## Changes made in P5h

| ID | Before | After | Why |
|---|---|---|---|
| R7 | PART | VER | Explainable combined risk index (`app/risk/`): ML threat index as the primary signal (no double counting, because the ML features already contain the rule scores), hard-evidence floors, conflict detection, consented-intel corroboration that can only raise, context without score effect; append-only versions; API, UI, PDF 8A. Verified by property tests (monotonicity, floors, unavailable-never-lower, indeterminate, conflict, no-record-never-lowers, determinism) on SQLite and PostgreSQL, an offline study on the 1,709-message test split (combined high+ F1 0.9475 = ML alone; medium+ FPR 3.02 % against 9.60 % for rules suspicious+), and a Docker/nginx/PostgreSQL run with models mounted and a models-absent run. Gaps: no behavioural or sender-history signal; thresholds derived on old, partly synthetic data; a risk index, not a probability. |
| R3 | PART | PART | The served ML now runs at every upload (stored, failure-isolated). It still never predicts `suspicious` (no data); the combined assessment flags rule/ML conflicts and raises them to at least medium as the documented substitute. Impersonated and fraud are still synthetic only. |
| R6 | PART | PART | BEC reasoning is now explicit: floor H3 (payment or credential ask plus a sender-identity signal) and the ML fraud/impersonated classes are shown together in the Risk tab. Still no real BEC data and no executive-impersonation check. |
| R1 | PART | PART | Per-cue breakdown (urgency, credential request, payment diversion, all-caps pressure) is surfaced from the existing lexicon rule findings in the Risk tab. No new NLP. |
| R33 | VER | VER | Counts updated: backend 723 / 7 skipped (SQLite), 724 / 6 skipped (PostgreSQL); frontend 190. |

## Changes made in P5e

| ID | Before | After | Why |
|---|---|---|---|
| R30 | PART | VER | Chain-of-custody support: per-analysis custody timeline (`/analyses/{id}/custody`, Custody tab) from a **tamper-evident** HMAC-SHA256 audit chain, plus the SHA-256 evidence facts with the honest note "SHA-256 detects change to the stored file; it does not make storage tamper-proof." Verified by tests (tamper modify/delete/reorder/insert/tail/wrong key) and a real Docker/PostgreSQL run in which a row edited with the trigger disabled was flagged at the exact seq in the UI, API and CLI. **Not** tamper-proof or WORM: a superuser can bypass the triggers, and someone holding both DB write access and the key could re-forge the chain; external checkpoints are manual. |
| R31 | PART | VER | Retention is enforced (`retention-run`, admin page, Compose profile; redact or delete; grace; legal holds; audit never purged), masking for roles without `pii:view` (API serializer, UI, PDF "MASKED VIEW") and redaction. Verified on SQLite and PostgreSQL and in a real Docker run (UI redact with confirmation, CLI delete with zero dependent or orphan rows, held erasure 409). Gaps: no built-in scheduler (cron or profile required); subjects are not masked for viewers; data is stored in clear. |
| R59 | PART | VER | Every listed action is audited with actor, target, outcome, source IP and timestamp (including AI assessment and ML runs, uploads, de-duplicated views, searches truncated to 64 characters, retention and holds); admin read API, filters, pagination, capped audited export, verify and checkpoint; Audit page. Tamper-evident, not tamper-proof (see R30). |
| R60 | PART | PART | Viewers now get masked personal data (addresses, display names, body) in the API, UI and PDF; retention redaction and erasure. Still no per-case ACLs and no at-rest encryption (stored in clear), and subjects are not masked. |
| R33 | VER | VER | Counts updated: backend 662 / 7 skipped (SQLite), 663 / 6 skipped (PostgreSQL); frontend 179. |

## Changes made in P5g

| ID | Before | After | Why |
|---|---|---|---|
| R14 | PART | IMP-U | Stored geolocation (upload ip-api enrichment, consented IPinfo results) now surfaced per IP with country/region/city, ASN/org/ISP, source, fetched_at, stale and SIMULATED flags (`/analyses/{id}/geo`, Geo tab). Verified with tests and a real browser/Docker run, but only on SIMULATED demo locations: real-data verification depends on live ip-api enrichment or consented live IPinfo results, which were not exercised (no live provider calls). MaxMind (R48) stays blocked. |
| R15 | PART | PART | Anonymity-signals panel shows Tor/VPN/proxy/relay/hosting only when a stored provider result backs them ("not available" otherwise, never "no"). Still no open-relay or botnet source; live provider data unverified. |
| R26 | PART | VER | Interactive Leaflet infrastructure map (analysis and campaign), synchronized IP table and side panel, keyboard-focusable markers, zoom/fit, optional relay-order line; plus the existing Cytoscape graphs. Verified by tests (Leaflet mocked), axe and a real browser run through nginx at 1920/1440/1280/1024. |
| R56 | MISS | VER | Analytics page: server-side, bounded, dialect-safe aggregates (`/analytics/summary`, tested on SQLite and PostgreSQL) rendered with lazily loaded, token-themed Plotly charts with text summaries and table fallbacks. Verified in the browser through nginx (zero CSP violations, zero external requests). Geo-derived charts show SIMULATED data in the demo, labelled. |
| R57 | MISS | IMP-U | Leaflet map with a bundled Natural Earth outline (no tiles, no external requests). The map itself is verified; points in every real run were SIMULATED demo data (see R14). |

## Changes made in P5i

| ID | Before | After | Why |
|---|---|---|---|
| R34 | PART | VER | PostgreSQL via `DATABASE_URL` (psycopg 3); versioned, idempotent migration runner (`schema_migrations`, advisory lock) used by app start-up and every CLI path; dialect fixes (case-insensitive search, UTC-pinned `timestamptz`). Full backend suite run on real PostgreSQL 17 (601 passed / 6 skipped, same as SQLite) and the Compose stack ran on it end to end. No SQLite→PostgreSQL data-migration tool (documented re-seed path). |
| R37 | MISS | VER | Backend and web images (non-root, read-only rootfs, health checks), nginx reverse proxy (SPA fallback, 300 s API timeout, upload limit with JSON 413, security headers incl. a verified CSP, no version disclosure, docs blocked), Compose with PostgreSQL, fail-closed secrets, trusted-proxy client IP, one-command demo. Verified by a real `docker compose` run on arm64 (macOS): login, upload, dashboard, ATT&CK, campaigns, PDF, AI assessment with host Ollama, 401/413/429 behaviour, headers, restart persistence, idempotent migrations, models-absent and production-mode refusals. amd64 images are built only in CI. |
| R38 | MISS | VER | GitHub Actions: backend on SQLite (with CPU ML stack) and on a PostgreSQL service, frontend typecheck/lint/tests/build, image builds + `nginx -t` + compose validation, gitleaks, forbidden-file check, actionlint. Pinned action SHAs, `contents: read`, no secrets. Clean-clone CI-equivalent run passed locally and the first remote run (44894449094) passed all five jobs. No CD (no image publishing or deployment target). |
| R33 | VER | VER | Counts updated (backend 601 passed / 6 skipped on SQLite and on PostgreSQL; frontend 154) and now run in CI. |

## P5d.1 correction (no status changes)

The header-forensics Return-Path comparison bug was fixed, along with the same bug class in the Reply-To,
Message-ID, auth-alignment, enrichment and correlation domain handling. R8 and R10 stay VER with updated
evidence. The ML feature path intentionally keeps the legacy comparison, so model inputs and outputs are
unchanged (proven to 4 decimals). The impact study is in `docs/CHANGELOG.md`.

## Changes made in P5d

| ID | Before | After | Why |
|---|---|---|---|
| R23 | MISS | VER | Deterministic ATT&CK mapper: 13 techniques pinned to Enterprise 20.1, with IDs, names and tactics verified against the official STIX data (committed snapshot plus test). 14 mapping rules (M06 has a verified and a claimed variant), each with observed/inferred basis, confidence, resolvable evidence ids, rationale and limitations. Append-only versions, recompute, backfill and PDF 7C. Verified by tests, browser, PDF and curl. |
| R21 | MISS | IMP-U | Four independent source-type hypotheses with likelihood bands, evidence, missing-data notes and `not_assessed: <reason>` when intel is absent. The infrastructure hypotheses were exercised only with SIMULATED intel (live providers unverified), and the bands are heuristic. |
| R15 | PART | PART | Tor, VPN and proxy flags and hosting signals now drive the "anonymised infrastructure" hypothesis and T1090.003. Still no open-relay or botnet source, and live provider data is unverified. |
| R40 | VER | VER | Attribution disclaimer on the ATT&CK tab, the source-type panel, PDF 7C and the API results. |

Pre-existing bug found (fixed in P5d.1, see `docs/CHANGELOG.md`): the header-forensics Return-Path comparison can keep a trailing `>` and flag identical domains. The ATT&CK engine guards against it; see `docs/attack/README.md`.

## Changes made in P5c

| ID | Before | After | Why |
|---|---|---|---|
| R18 | PART | IMP-U | Cross-case correlation is implemented and verified: persistent entities and observations, generic-indicator protection, link rules, candidate campaigns, per-analysis Related view and PDF 7B. Tests use synthetic data, and the real-app run used the synthetic demo campaign. Still IMP-U because the threat-intel half (P5a) is live-unverified and the weights are tuned on synthetic data only. |
| R19 | PART | VER | Persistent cross-email graph (entity ↔ analysis) with a campaign graph view (Cytoscape) and an entity neighbourhood API; evidence references on every edge. Verified by tests and in the browser. |
| R20 | PART | IMP-U | Campaign-level confidence (low / medium / high plus a numeric score) with structured, evidence-backed reasons. Deliberately not attribution to a person. Thresholds are heuristic, there are no analyst overrides, and validation is on synthetic data only. |
| R28 | PART | VER | Search across analyses, cases, indicators and campaigns (filters, pagination, injection-tested); add and remove analyses on a case with audit; case-level indicators; campaigns list and detail. Verified by tests, browser and curl. |
| R51 | MISS | VER | NetworkX connected components over qualifying links (`correlation/engine.py`) · `test_correlation.py`. |
| R50 | MISS | MISS | Unchanged and intentional: SQLite plus in-process NetworkX meets the current scale (about 1 s full recompute at 1,300 analyses). Neo4j would add an external service without a current need. |

Related rows (R26, R33, R35, R59) gained evidence but keep their status. Details: `docs/correlation/README.md`.

## Changes made in P5b

| ID | Before | After | Why |
|---|---|---|---|
| R32 | MISS | VER | RBAC (viewer / analyst / admin) enforced server-side by an app-wide dependency and a deny-by-default route → permission map. Verified by a route-inventory test (401 anonymous on every non-public route, 200-or-handled / 403 per role on every route), explicit role-matrix tests, a real-app curl run and a browser walk-through per role. No per-case ownership (see Gaps). |
| R54 | MISS | VER | HS256 JWT (PyJWT): sub/role/tv/jti/iat/exp/iss/aud, 60-min lifetime, `alg` pinned, `token_version` revocation, fail-closed secret check at startup. Tests cover expired, wrong signature, `alg=none`, HS512, wrong iss/aud, tampered claims, missing claims and revocation. The running backend rejected an expired token. |
| R53 | BLK | BLK | Unchanged. P5b is local password authentication with JWT, **not** an OAuth 2.0 / OIDC provider. |
| R59 | PART | PART | Login success/failure/lockout/throttle, logout, password change, user create/role/disable/enable/reset events; `actor_user_id` on every audit write, including analysis, intel, integrity and report events. No read API/UI yet (P5e); AI-assessment runs not audited. |
| R60 | PART | PART | All stored forensic data now requires authentication and a role. Still no per-case ACLs, and bodies are stored in clear. |

Related rows (R25, R33) gained evidence but keep their status. Details: `docs/auth/README.md`.

## Changes made in P5a

| ID | Before | After | Why |
|---|---|---|---|
| R15 | MISS | PART | Tor exit-list membership, IPinfo VPN/proxy/Tor/relay/hosting flags (when the plan returns them; otherwise "unavailable"), Shodan risk tags and AbuseIPDB usage type. Open relay and botnet detection are still missing. Mocked-verified only. |
| R18 | MISS | PART | Threat-intel reputation correlation implemented (VT, AbuseIPDB, Shodan, IPinfo, Tor). Correlation with past incidents, clusters and campaigns is still missing (P5b). Mocked-verified only. |
| R44 | MISS | IMP-U | VirusTotal adapter: GET-only IP, domain and hash reputation; 4/min limiter and daily cap. Mocked-verified; live unverified. |
| R45 | STUB | IMP-U | AbuseIPDB adapter replaces the stub: score, reports, country, ISP, usage type, last reported. Mocked-verified; live unverified. |
| R46 | MISS | IMP-U | Shodan host adapter: ports, org, ASN, hostnames, tags; 404 maps to no_record. Mocked-verified; live unverified. |
| R49 | MISS | IMP-U | IPinfo adapter: geo, ASN/org, privacy flags; fields the plan does not return are shown as unavailable. Mocked-verified; live unverified. |

Related rows (R14, R16, R33, R59, R60) gained evidence but keep their status.

## Matrix

| ID | Requirement | Status | Evidence (code · tests) | Gaps / external dependency |
|---|---|---|---|---|
| R1 | NLP of subject/body: urgency, impersonation, social engineering | PART | `ml/transformer.py`, lexicon rules in `detection/`; P5h per-cue list in the Risk tab (from existing rule findings) · `test_ml.py`, `test_detection.py`, `test_risk.py` | No per-cue NLP model output (lexicon cues only) |
| R2 | Phishing indicators: spoofing, deceptive domains, attachments, links, obfuscation | VER | `detection/` rules · `test_detection.py` | `lookalike_domain` needs a reference domain |
| R3 | ML classes: legitimate / suspicious / impersonated / phishing / fraud | PART | `ml/train.py`, `ml/inference.py`, `/ml/classify`; P5h upload-time classification (`ml_classification`) · `test_ml.py`, `test_risk.py` | `suspicious` has no data (combined-risk conflict flag is the documented substitute); impersonated and fraud are synthetic only |
| R4 | SHAP explanations | PART | `ml/explain.py`, `ml/shap_view.py` · `test_explain.py`, `test_p41.py` | Explains the XGBoost component only; DistilRoBERTa (50 % ensemble weight) and the ensemble prediction are not explained |
| R5 | Labelled dataset | VER | `ml/dataset/*`, `data/DATA_CARD.md` · `test_dataset.py` | Era and source confound |
| R6 | BEC detection | PART | `payment_diversion` / `credential_request` rules, ML fraud class, P4.2 policy; P5h hard-evidence floor H3 · `test_risk.py` | No real BEC data; no executive-impersonation check |
| R7 | Combined risk score | VER | `risk/engine.py`, `risk/service.py`, `/analyses/{id}/risk*`, Risk tab, PDF 8A; offline study `backend/scripts/evaluate_risk.py` · `test_risk.py` (SQLite + PostgreSQL), `Risk.test.tsx`, Docker run | No behavioural/sender-history signal; validation-derived thresholds on old, partly synthetic data; an index, not a probability |
| R8 | Header fields and alignment | VER | `forensics/headers.py`, `auth/`, `ingestion/addresses.py` (P5d.1 parsed + normalised address domains) · `test_forensics.py`, `test_auth.py`, `test_address_comparison.py` | Analyses stored before P5d.1 keep the old comparison (not rewritten) |
| R9 | SPF/DKIM/DMARC verification | IMP-U | `auth/__init__.py` live checks · DNS stubbed in tests | Never verified live |
| R10 | Routing anomalies / forged fields | VER | `forensics/headers.py` · `test_forensics.py`, `test_address_comparison.py` | P5d.1 removed a false Return-Path mismatch (trailing `>`); rule weights not yet re-baselined |
| R11 | Authorised vs suspicious infrastructure | IMP-U | SPF result plus relay trust | Depends on live SPF (R9) |
| R12 | Relay-chain reconstruction | VER | `run_header_forensics` · `test_forensics.py` | Heuristic trust boundary |
| R13 | Candidate IPs / earliest reliable node | VER | `forensics/headers.py` · `test_forensics.py` | — |
| R14 | Geolocation: country, region, city, ISP, ASN, hosting | IMP-U | `enrichment/engine.py:ipgeo_lookup`; P5a IPinfo geo/ASN/hosting flag and anycast; P5g `geo/service.py` + Geo tab · `test_intel.py`, `test_intel_live_shapes.py`, `test_geo.py`, `Geo.test.tsx` | MaxMind blocked (R48); real IPinfo location verified live (P5a-live, one IP); live ip-api upload enrichment unverified |
| R15 | VPN / Tor / proxy / hosting / botnet / open-relay flags | PART | `intel/providers.py`: TorExitList, IPinfo privacy, Shodan tags, AbuseIPDB usage type; P5d "anonymised infrastructure" hypothesis and T1090.003 · `test_intel.py`, `test_attack.py` | No open-relay or botnet source; IPinfo privacy flags are not returned on the free plan (shown as unavailable, never true); Tor list live-verified (P5a-live) |
| R16 | WHOIS/RDAP, DNS, MX, registrar | PART | `dns_lookup`, `rdap_lookup`; VT domain registrar/creation (P5a) · `test_enrichment.py`, `test_intel.py` | Live unverified |
| R17 | Origin vs infrastructure vs identity separation | VER | Disclaimers in UI, PDF, LLM evidence and the threat-intel disclaimer · `test_llm.py`, `test_p41.py`, `test_intel.py` | — |
| R18 | Correlation with threat intel, reputation, past incidents, campaigns | IMP-U | `intel/` (P5a); `correlation/` engine, Related tab, campaigns, PDF §7B (P5c) · `test_intel.py`, `test_correlation.py`, `Correlation.test.tsx` | Intel live-verified for the exercised paths only (P5a-live); correlation weights tuned on synthetic data only |
| R19 | Relationship graph | VER | Per-email trace graph; persistent cross-email entity graph, campaign graph and entity neighbourhood (P5c) · `model.test.ts`, `test_correlation.py`, `Correlation.test.tsx` | No graph database (R50) |
| R20 | Confidence-based attribution | IMP-U | Per-hop confidence; campaign confidence plus evidence-backed reasons (P5c) · `test_correlation.py` | Heuristic thresholds; no analyst overrides; never attribution to a person |
| R21 | Source-type classification | IMP-U | `attack/engine.py` hypotheses (spoofed domain, compromised account, anonymised infra, direct malicious infra) · `test_attack.py`, `Attack.test.tsx` | Infra hypotheses tested with SIMULATED intel only; heuristic bands; no sender-history baseline |
| R22 | Rule tests | VER | `test_detection.py` | — |
| R23 | MITRE ATT&CK mapping | VER | `attack/` (catalog pinned to Enterprise 20.1, verified), ATT&CK tab, PDF §7C · `test_attack.py`, `Attack.test.tsx` | Single-message view; heuristic confidence; no analyst overrides |
| R24 | Real-time alerts | PART | P5f `alerts/` engine, `/api/v1/alerts*`, Alerts page, top-bar badge, optional e-mail · `test_alerts.py` (SQLite + PostgreSQL), `Alerts.test.tsx`, Docker run | Event-driven only (raised when an analysis is processed); no real-time mailbox monitoring because ingestion (R36) is missing; e-mail verified against a local fake SMTP sink only |
| R25 | Analyst dashboard | VER | `ResultsDashboard.tsx` (13 tabs), Overview, History, Alerts, Campaigns, Analytics, Search, Users, Audit, Retention pages · `ThreatIntelPanel.test.tsx`, `AssessmentInteractions.test.tsx`, `Auth.test.tsx`, `Pages.test.tsx`; P5z browser sweep of every tab and page as viewer, analyst and admin on the Docker demo | The low-severity UI issues found in P5z were fixed in P5z.1 (docs/TESTING.md §6); no browser E2E suite |
| R26 | Interactive trace map / graphs | VER | Cytoscape trace and campaign graphs; P5g Leaflet infrastructure map (analysis + campaign) · `Geo.test.tsx`, browser run | Real-data map points depend on R14 |
| R27 | Structured forensic reports | VER | `reports/pdf.py` (incl. §7A), `reports/html.py` (HTML report) · `test_assessment_report.py`, `test_p41.py`, `test_intel.py`, `test_crosscheck_report.py`; PDF and HTML downloads in `scripts/smoke.py` | — |
| R28 | Searchable case management / campaigns | VER | `/investigations` plus add/remove/indicators, `/search`, `/campaigns` (P5c) · `test_investigations.py`, `test_correlation.py`, `Correlation.test.tsx` | No full-text index (R52); no case-to-campaign link |
| R29 | PDF tests incl. injection | VER | PDF escaping tests (also for provider strings in §7A) | — |
| R30 | Evidence preservation / chain-of-custody support | VER | SHA-256, optional raw retention, versioned assessments and intel runs; P5e HMAC hash-chained audit log, custody timeline and tab, checkpoints · `test_audit.py`, `Audit.test.tsx`, Docker tamper demo | Tamper-evident, not tamper-proof: no WORM or external timestamping; triggers bypassable by a superuser (detected by the chain); manual checkpoints |
| R31 | Retention, masking, redaction | VER | P5e `retention/service.py` (redact or delete, grace, legal holds, `retention-run`), `privacy/masking.py` (`pii:view`), masked PDF; `llm/redact.py` · `test_audit.py`, `Audit.test.tsx`, Docker run | No built-in scheduler (cron or Compose profile); viewers still see subjects unmasked (masking covers addresses, display names and bodies only); stored in clear |
| R32 | RBAC | VER | `security/permissions.py`, `security/deps.py` (app-wide `enforce_access`), `api/admin_router.py` · `test_access_control.py` (route inventory + role matrix), `Auth.test.tsx` | Roles are global: no per-case ownership/ACLs |
| R33 | Tests | VER | P5z release runs: backend 788 passed / 13 skipped on SQLite (12 opt-in live tests + 1 PostgreSQL-only trigger test) and 789 passed / 12 skipped on PostgreSQL; 753 / 15 and 754 / 14 without the ML stack; frontend 205 passed; documentation consistency tests; `scripts/smoke.py` (36 checks) against the Docker demo; all suites in CI (docs/TESTING.md) | No browser E2E suite |
| R34 | Main database (PostgreSQL) | VER | `core/db.py` (`DATABASE_URL`, psycopg 3), `core/migrations.py` (versioned, idempotent) · full suite on PostgreSQL 17, `test_deploy.py`, Compose run (P5i) | No SQLite→PostgreSQL data copy (re-seed path documented) |
| R35 | Background tasks / caching | MISS | In-process enrichment cache; DB intel cache (P5a) | No Celery/Redis; intel lookups and correlation recompute run synchronously |
| R36 | Email integration (IMAP/SMTP/Graph) | MISS | — | Test mailbox or Azure tenant |
| R37 | Deployment (Docker/Nginx) | VER | `backend/Dockerfile`, `frontend/Dockerfile`, `frontend/nginx/`, `deploy/docker-compose.yml`, `scripts/demo-up.sh` · real Compose run, `test_deploy.py`, `nginx -t` (P5i); P5z from-scratch build and `scripts/smoke.py` (36 checks) | No TLS certificates shipped (documented); single uvicorn worker; arm64 run verified, amd64 built in CI only |
| R38 | CI/CD | VER | `.github/workflows/ci.yml` (SQLite + PostgreSQL backend, frontend, images, compose, gitleaks, forbidden files, actionlint) (P5i); P5z documentation checks (`scripts/matrix_counts.py`, `scripts/check_docs.py`) | CI only: no CD / registry publishing |
| R39 | Frontend (React + Tailwind) | VER | Vite + React + Tailwind; tsc, ESLint and build pass | — |
| R40 | Attribution as investigative support | VER | Disclaimers in UI, PDF and evidence; correlation (P5c) and ATT&CK / source-type (P5d) disclaimers | — |
| R41* | Preprocessing / normalisation | VER | `ingestion/parser.py`, `enrichment/iocs.py`, `intel/validate.py` · `test_parser.py`, `test_intel.py` | — |
| R42* | Attachment metadata | VER | Parser SHA-256 and metadata · `test_parser.py` | — |
| R43* | mail-parser cross-check | VER | `ingestion/crosscheck.py` (mail-parser 4.10.0), `analysis.parser_crosscheck`, Headers-tab panel, PDF/HTML section 5 · `test_crosscheck_report.py` (SQLite + PostgreSQL), `Crosscheck.test.tsx`, Docker run | Informational only; two parsers; malformed Received kept verbatim by both is not flagged |
| R44* | VirusTotal | VER | `intel/providers.py:VirusTotal` · `test_intel.py`, `test_intel_live_shapes.py`, live run (P5a-live) | Live-verified for the exercised paths only (IP, hash, domain shape, cache, limiter); error mappings mocked-only; public API is non-commercial only |
| R45* | AbuseIPDB | VER | `intel/providers.py:AbuseIPDB` · `test_intel.py`, `test_intel_live_shapes.py`, live run (P5a-live) | Live-verified for the exercised paths only (`record_found` below the threshold, cache); error mappings mocked-only |
| R46* | Shodan | VER | `intel/providers.py:Shodan` · `test_intel.py`, `test_intel_live_shapes.py`, live run (P5a-live) | Live-verified for the exercised paths only (host lookup works on the free plan); `no_record`, `not_permitted` and error mappings mocked-only |
| R47* | MISP | BLK | Reported as "not configured" | No MISP instance |
| R48* | MaxMind GeoIP2 | BLK | `geoip2_lookup` stub; reported as "not configured" | No licence key or database |
| R49* | IPinfo | VER | `intel/providers.py:IPinfo` · `test_intel.py`, `test_intel_live_shapes.py`, live run (P5a-live) | Live-verified for the exercised paths only (geo, ASN, anycast, missing token); privacy flags need a paid plan (unavailable on free) |
| R50* | Neo4j | MISS | — (P5c uses SQLite plus NetworkX deliberately) | Not needed at current scale; service not installed |
| R51* | NetworkX | VER | `correlation/engine.py` (connected components) · `test_correlation.py` | — |
| R52* | Search (OpenSearch) | MISS | — (`/search` uses SQL `LIKE`/`ILIKE` over analyses, cases, indicators and campaigns) | Not built: no full-text index; not needed at the current scale |
| R53* | OAuth 2.0 | BLK | — (P5b is local password auth + JWT, not OAuth 2.0) | Provider not chosen |
| R54* | JWT authentication | VER | `security/tokens.py`, `api/auth_router.py` · `test_access_control.py` | No refresh tokens; no key rotation (key id) |
| R55* | Jinja2 report templates | VER | `reports/html.py` + `reports/templates/` (HTML report, autoescape) and `alerts/templates/` (e-mail) · `test_crosscheck_report.py`, `test_alerts.py` | The PDF remains ReportLab (by design) |
| R56* | Plotly analytics | VER | `geo/analytics.py`, `/analytics/summary`, `AnalyticsPage.tsx` (lazy Plotly) · `test_geo.py` (SQLite + PostgreSQL), `Geo.test.tsx`, browser run | Bounded window (2,000 latest analyses for derived charts) |
| R57* | Leaflet geolocation map | IMP-U | `components/geo/GeoMap.tsx` (no tiles; Natural Earth outline) · `Geo.test.tsx`, browser run | Verified with one real IPinfo point (P5a-live) and SIMULATED points; multi-point real data unverified |
| R58* | Local LLM forensic summaries | VER | `llm/*` · `test_llm.py`, `test_p41.py`, `test_p42.py` | — |
| R59* | Audit trails | VER | `audit_event` with actor, target, outcome and source IP on every event, an HMAC chain, `/audit/*` API, Audit page, CLI `audit-verify` and `audit-checkpoint` (P5e) · `test_audit.py`, `test_access_control.py`, `Audit.test.tsx` | Tamper-evident, not tamper-proof; no audit-key rotation; views de-duplicated per 15 minutes |
| R60* | Controlled personal-data handling | PART | LLM redaction, local-only Ollama; P5a consent, bare-indicator-only outbound requests, offline mode; P5b authentication + RBAC on all stored data, `no-store` caching; P5e viewer masking (API, UI, PDF), retention redaction and erasure | No per-case ACLs; stored in clear (no at-rest encryption); subjects not masked |
