# AIPISH requirements traceability matrix (R1–R60)

This matrix traces AIPISH against the PBL Review 0 document, Group G7. The P5 audit set its baseline at
`b6e4c67`. It was updated for **P5a: threat-intelligence provider integrations** (`624c49d`), **P5b:
authentication, JWT and RBAC** (`2e32b08`) and **P5c: cross-case correlation and candidate campaigns** (`9213bbf`) and **P5d: MITRE ATT&CK mapping and source-type
classification** and **P5i: PostgreSQL, Docker Compose, Nginx and CI**.

**ID provenance:**
- R1–R40 come from the original project matrix.
- R41–R60 were re-derived during the P5 audit from PBL §4.6, §5 and §8 and the recommended stack, and are
  marked `*`.

Recommended technologies are listed for traceability. They are not functional scope.

## Status legend

| Code | Meaning |
|---|---|
| **VER** | Implemented and verified (tests plus a real-app run). |
| **IMP-U** | Implemented, verification incomplete. For P5a providers this means **mocked-verified**: unit/integration tests plus a real-app run against a SIMULATED loopback stub. **Live provider connectivity is not verified.** |
| **PART** | Partially implemented. |
| **STUB** | Stub or mock only. |
| **MISS** | Missing. |
| **BLK** | Blocked by an external dependency. |

## Counts

| Status | Before P5a | After P5a | After P5b | After P5c | After P5d | After P5i |
|---|---:|---:|---:|---:|---:|---:|
| VER | 16 | 16 | 18 | 21 | 22 | 25 |
| IMP-U | 3 | 7 | 7 | 9 | 10 | 10 |
| PART | 16 | 18 | 18 | 14 | 14 | 13 |
| STUB | 1 | 0 | 0 | 0 | 0 | 0 |
| MISS | 21 | 16 | 14 | 13 | 11 | 9 |
| BLK | 3 | 3 | 3 | 3 | 3 | 3 |
| **Total** | 60 | 60 | 60 | 60 | 60 | 60 |

## Changes made in P5i

| ID | Before | After | Why |
|---|---|---|---|
| R34 | PART | VER | PostgreSQL via `DATABASE_URL` (psycopg 3); versioned, idempotent migration runner (`schema_migrations`, advisory lock) used by app start-up and every CLI path; dialect fixes (case-insensitive search, UTC-pinned `timestamptz`). Full backend suite run on real PostgreSQL 17 (601 passed / 6 skipped, same as SQLite) and the Compose stack ran on it end to end. No SQLite→PostgreSQL data-migration tool (documented re-seed path). |
| R37 | MISS | VER | Backend and web images (non-root, read-only rootfs, health checks), nginx reverse proxy (SPA fallback, 300 s API timeout, upload limit with JSON 413, security headers incl. a verified CSP, no version disclosure, docs blocked), Compose with PostgreSQL, fail-closed secrets, trusted-proxy client IP, one-command demo. Verified by a real `docker compose` run on arm64 (macOS): login, upload, dashboard, ATT&CK, campaigns, PDF, AI assessment with host Ollama, 401/413/429 behaviour, headers, restart persistence, idempotent migrations, models-absent and production-mode refusals. amd64 images are built only in CI. |
| R38 | MISS | VER | GitHub Actions: backend on SQLite (with CPU ML stack) and on a PostgreSQL service, frontend typecheck/lint/tests/build, image builds + `nginx -t` + compose validation, gitleaks, forbidden-file check, actionlint. Pinned action SHAs, `contents: read`, no secrets. Clean-clone CI-equivalent run passed locally; remote run status is recorded in `docs/deployment/README.md` and the P5i commit notes. No CD (no image publishing or deployment target). |
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
| R1 | NLP of subject/body: urgency, impersonation, social engineering | PART | `ml/transformer.py`, lexicon rules in `detection/` · `test_ml.py`, `test_detection.py` | No per-cue NLP output |
| R2 | Phishing indicators: spoofing, deceptive domains, attachments, links, obfuscation | VER | `detection/` rules · `test_detection.py` | `lookalike_domain` needs a reference domain |
| R3 | ML classes: legitimate / suspicious / impersonated / phishing / fraud | PART | `ml/train.py`, `ml/inference.py`, `/ml/classify` · `test_ml.py` | `suspicious` has no data; impersonated and fraud are synthetic only |
| R4 | SHAP explanations | PART | `ml/explain.py`, `ml/shap_view.py` · `test_explain.py`, `test_p41.py` | XGBoost half only |
| R5 | Labelled dataset | VER | `ml/dataset/*`, `data/DATA_CARD.md` · `test_dataset.py` | Era and source confound |
| R6 | BEC detection | PART | `payment_diversion` / `credential_request` rules, ML fraud class, P4.2 policy | No real BEC data; no executive-impersonation check |
| R7 | Combined risk score | PART | Rule score bridges forensics, auth and enrichment | ML not combined; no behavioural signal; threat intel deliberately informational in P5a |
| R8 | Header fields and alignment | VER | `forensics/headers.py`, `auth/`, `ingestion/addresses.py` (P5d.1 parsed + normalised address domains) · `test_forensics.py`, `test_auth.py`, `test_address_comparison.py` | Analyses stored before P5d.1 keep the old comparison (not rewritten) |
| R9 | SPF/DKIM/DMARC verification | IMP-U | `auth/__init__.py` live checks · DNS stubbed in tests | Never verified live |
| R10 | Routing anomalies / forged fields | VER | `forensics/headers.py` · `test_forensics.py`, `test_address_comparison.py` | P5d.1 removed a false Return-Path mismatch (trailing `>`); rule weights not yet re-baselined |
| R11 | Authorised vs suspicious infrastructure | IMP-U | SPF result plus relay trust | Depends on live SPF (R9) |
| R12 | Relay-chain reconstruction | VER | `run_header_forensics` · `test_forensics.py` | Heuristic trust boundary |
| R13 | Candidate IPs / earliest reliable node | VER | `forensics/headers.py` · `test_forensics.py` | — |
| R14 | Geolocation: country, region, city, ISP, ASN, hosting | PART | `enrichment/engine.py:ipgeo_lookup`; P5a IPinfo geo/ASN/hosting flag · `test_intel.py` | MaxMind blocked (R48); live unverified |
| R15 | VPN / Tor / proxy / hosting / botnet / open-relay flags | PART | `intel/providers.py`: TorExitList, IPinfo privacy, Shodan tags, AbuseIPDB usage type; P5d "anonymised infrastructure" hypothesis and T1090.003 · `test_intel.py`, `test_attack.py` | No open-relay or botnet source; IPinfo privacy may need a paid plan; live unverified |
| R16 | WHOIS/RDAP, DNS, MX, registrar | PART | `dns_lookup`, `rdap_lookup`; VT domain registrar/creation (P5a) · `test_enrichment.py`, `test_intel.py` | Live unverified |
| R17 | Origin vs infrastructure vs identity separation | VER | Disclaimers in UI, PDF, LLM evidence and the threat-intel disclaimer · `test_llm.py`, `test_p41.py`, `test_intel.py` | — |
| R18 | Correlation with threat intel, reputation, past incidents, campaigns | IMP-U | `intel/` (P5a); `correlation/` engine, Related tab, campaigns, PDF §7B (P5c) · `test_intel.py`, `test_correlation.py`, `Correlation.test.tsx` | Intel live-unverified; correlation weights tuned on synthetic data only |
| R19 | Relationship graph | VER | Per-email trace graph; persistent cross-email entity graph, campaign graph and entity neighbourhood (P5c) · `model.test.ts`, `test_correlation.py`, `Correlation.test.tsx` | No graph database (R50) |
| R20 | Confidence-based attribution | IMP-U | Per-hop confidence; campaign confidence plus evidence-backed reasons (P5c) · `test_correlation.py` | Heuristic thresholds; no analyst overrides; never attribution to a person |
| R21 | Source-type classification | IMP-U | `attack/engine.py` hypotheses (spoofed domain, compromised account, anonymised infra, direct malicious infra) · `test_attack.py`, `Attack.test.tsx` | Infra hypotheses tested with SIMULATED intel only; heuristic bands; no sender-history baseline |
| R22 | Rule tests | VER | `test_detection.py` | — |
| R23 | MITRE ATT&CK mapping | VER | `attack/` (catalog pinned to Enterprise 20.1, verified), ATT&CK tab, PDF §7C · `test_attack.py`, `Attack.test.tsx` | Single-message view; heuristic confidence; no analyst overrides |
| R24 | Real-time alerts | MISS | — | Needs ingestion (R36) |
| R25 | Analyst dashboard | IMP-U | `ResultsDashboard.tsx` tabs, including Threat intel; P5b login, role-aware actions, admin users page · `ThreatIntelPanel.test.tsx`, `AssessmentInteractions.test.tsx`, `Auth.test.tsx` | Geo shown only from live enrichment or IPinfo |
| R26 | Interactive trace map / graphs | PART | Cytoscape trace view; campaign graph (P5c) | No Leaflet map (R57) |
| R27 | Structured forensic reports | VER | `reports/pdf.py` (incl. §7A) · `test_assessment_report.py`, `test_p41.py`, `test_intel.py` | — |
| R28 | Searchable case management / campaigns | VER | `/investigations` plus add/remove/indicators, `/search`, `/campaigns` (P5c) · `test_investigations.py`, `test_correlation.py`, `Correlation.test.tsx` | No full-text index (R52); no case-to-campaign link |
| R29 | PDF tests incl. injection | VER | PDF escaping tests (also for provider strings in §7A) | — |
| R30 | Evidence preservation / chain-of-custody support | PART | SHA-256, optional raw retention, versioned assessments and intel runs | Not tamper-resistant |
| R31 | Retention, masking, redaction | PART | `CASE_EVIDENCE_RETENTION_DAYS`, `llm/redact.py` | Retention not enforced; body stored in clear |
| R32 | RBAC | VER | `security/permissions.py`, `security/deps.py` (app-wide `enforce_access`), `api/admin_router.py` · `test_access_control.py` (route inventory + role matrix), `Auth.test.tsx` | Roles are global: no per-case ownership/ACLs |
| R33 | Tests | VER | Backend 601 passed / 6 skipped on SQLite and on PostgreSQL (6 opt-in live tests); frontend 154 passed; all in CI (P5i) | No browser E2E suite |
| R34 | Main database (PostgreSQL) | VER | `core/db.py` (`DATABASE_URL`, psycopg 3), `core/migrations.py` (versioned, idempotent) · full suite on PostgreSQL 17, `test_deploy.py`, Compose run (P5i) | No SQLite→PostgreSQL data copy (re-seed path documented) |
| R35 | Background tasks / caching | MISS | In-process enrichment cache; DB intel cache (P5a) | No Celery/Redis; intel lookups and correlation recompute run synchronously |
| R36 | Email integration (IMAP/SMTP/Graph) | MISS | — | Test mailbox or Azure tenant |
| R37 | Deployment (Docker/Nginx) | VER | `backend/Dockerfile`, `frontend/Dockerfile`, `frontend/nginx/`, `deploy/docker-compose.yml`, `scripts/demo-up.sh` · real Compose run, `test_deploy.py`, `nginx -t` (P5i) | No TLS certificates shipped (documented); single uvicorn worker; arm64 run verified, amd64 built in CI only |
| R38 | CI/CD | VER | `.github/workflows/ci.yml` (SQLite + PostgreSQL backend, frontend, images, compose, gitleaks, forbidden files, actionlint) (P5i) | CI only: no CD / registry publishing |
| R39 | Frontend (React + Tailwind) | VER | Vite + React + Tailwind; tsc, ESLint and build pass | — |
| R40 | Attribution as investigative support | VER | Disclaimers in UI, PDF and evidence; correlation (P5c) and ATT&CK / source-type (P5d) disclaimers | — |
| R41* | Preprocessing / normalisation | VER | `ingestion/parser.py`, `enrichment/iocs.py`, `intel/validate.py` · `test_parser.py`, `test_intel.py` | — |
| R42* | Attachment metadata | VER | Parser SHA-256 and metadata · `test_parser.py` | — |
| R43* | mail-parser cross-check | MISS | — | — |
| R44* | VirusTotal | IMP-U | `intel/providers.py:VirusTotal` · `test_intel.py` | **Live unverified**; public API is non-commercial only |
| R45* | AbuseIPDB | IMP-U | `intel/providers.py:AbuseIPDB` · `test_intel.py` | **Live unverified** |
| R46* | Shodan | IMP-U | `intel/providers.py:Shodan` · `test_intel.py` | **Live unverified**; host lookups may need a paid plan (reported as not_permitted) |
| R47* | MISP | BLK | Reported as "not configured" | No MISP instance |
| R48* | MaxMind GeoIP2 | BLK | `geoip2_lookup` stub; reported as "not configured" | No licence key or database |
| R49* | IPinfo | IMP-U | `intel/providers.py:IPinfo` · `test_intel.py` | **Live unverified**; privacy flags depend on plan |
| R50* | Neo4j | MISS | — (P5c uses SQLite plus NetworkX deliberately) | Not needed at current scale; service not installed |
| R51* | NetworkX | VER | `correlation/engine.py` (connected components) · `test_correlation.py` | — |
| R52* | Search (OpenSearch) | MISS | — | — |
| R53* | OAuth 2.0 | BLK | — (P5b is local password auth + JWT, not OAuth 2.0) | Provider not chosen |
| R54* | JWT authentication | VER | `security/tokens.py`, `api/auth_router.py` · `test_access_control.py` | No refresh tokens; no key rotation (key id) |
| R55* | Jinja2 report templates | MISS | ReportLab only | Low value |
| R56* | Plotly analytics | MISS | — | — |
| R57* | Leaflet geolocation map | MISS | — | Needs geolocation data |
| R58* | Local LLM forensic summaries | VER | `llm/*` · `test_llm.py`, `test_p41.py`, `test_p42.py` | — |
| R59* | Audit trails | PART | `audit_event`; P5a `threat_intel_lookup`; P5b login/lockout/logout/password/user-admin events and `actor_user_id` on every write · `test_access_control.py` | No read API/UI (P5e); assessment runs not audited; not tamper-resistant |
| R60* | Controlled personal-data handling | PART | LLM redaction, local-only Ollama; P5a consent, bare-indicator-only outbound requests, offline mode; P5b authentication + RBAC on all stored data, `no-store` caching | No per-case ACLs; body stored in clear |
