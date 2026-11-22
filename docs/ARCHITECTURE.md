# AIPISH architecture

This page describes how AIPISH is built, derived from the code in this repository. The route, role, table
and migration tables below are **generated from the running code** by `backend/scripts/gen_doc_tables.py`;
`backend/tests/unit/test_docs_consistency.py` fails when they go stale.

## 1. Components

```
 Browser (React + Vite + Tailwind SPA)
    │  HTTPS in a real deployment (TLS terminated in front of Nginx; no certificates shipped)
    ▼
 Nginx (web image) ── serves the SPA, security headers + CSP, proxies /api/ ──┐
                                                                             ▼
 FastAPI backend (one uvicorn worker, read-only container FS)
    ├─ ingestion/      .eml parsing, SHA-256, mail-parser cross-check
    ├─ forensics/      Received chain, trust boundary, candidate origin IPs, header consistency
    ├─ auth/           SPF / DKIM / DMARC re-verification (dnspython, pyspf, dkimpy)
    ├─ enrichment/     DNS, RDAP, IP geo (ip-api) for extracted indicators
    ├─ detection/      18 weighted rules → score 0–100 + verdict
    ├─ ml/             DistilRoBERTa + XGBoost (+ LR, weight 0) ensemble; SHAP for XGBoost
    ├─ llm/            Mistral via local Ollama: constrained forensic summary
    ├─ intel/          VirusTotal, AbuseIPDB, Shodan, IPinfo, Tor exit list (consent-gated)
    ├─ correlation/    entity observations, NetworkX connected components → candidate campaigns
    ├─ attack/         MITRE ATT&CK Enterprise 20.1 mapping + source-type hypotheses
    ├─ risk/           combined risk index (rules + ML + hard evidence + intel + campaign + ATT&CK)
    ├─ alerts/         risk-based alerts, de-duplicated per subject; optional SMTP e-mail
    ├─ geo/            stored-data geolocation and analytics aggregates
    ├─ reports/        ReportLab PDF and Jinja2 HTML reports
    ├─ audit/          HMAC-SHA256 hash-chained audit log, checkpoints
    ├─ retention/      redact/delete policy, legal holds
    ├─ privacy/        role-based masking (pii:view)
    └─ security/       local users, scrypt password hashing (stdlib), JWT, deny-by-default route map
    │
    ▼
 PostgreSQL 17 (Compose) or SQLite (development and tests)

 Host (outside the containers): Ollama with the `mistral` model; trained models mounted read-only at /models
```

## 2. Data flow

**Upload** (`POST /api/v1/analyses`, `backend/app/api/router.py:upload_eml`), in this order:

1. Validate the file (`.eml` name or `message/rfc822` type, size ≤ `APP_UPLOAD_MAX_MB`), hash it (SHA-256).
2. Parse (stdlib `email`); run the informational **mail-parser cross-check** (never feeds any score).
3. **Header forensics**: relay chain, trust boundary, candidate and earliest origin IPs.
4. **Authentication**: SPF/DKIM/DMARC re-verified locally (live DNS unless offline); header claims are kept
   separate from verified results.
5. **Enrichment**: DNS, RDAP and IP geo for extracted indicators (skipped in `offline`/`demo`, or per
   `ENRICH_ENABLE_*`).
6. **Detection**: 18 rules produce the score and verdict (`phishing_fraud_likely`, `suspicious`, `minimal`).
7. **Store** the analysis and write an `analysis_uploaded` audit event. With the default
   `CASE_EVIDENCE_STORE=hash_only`, the raw bytes are **not** stored.
8. **Correlation**: record entity observations, recompute candidate campaigns (synchronous, failure-isolated).
9. **ATT&CK** mapping and source-type hypotheses.
10. **Upload-time ML** classification (cheap ensemble, bounded by `AIPISH_ML_UPLOAD_TIMEOUT_SECONDS`).
11. **Combined risk** index, then **alerts** for the analysis and for new or grown campaigns.

Steps 8–11 run after the response is built; a failure there is recorded and never fails the upload.

**On demand** (analyst):

- **AI assessment** (`POST /api/v1/llm/forensic-summary` with a file, or
  `/analyses/{id}/forensic-summary` for a stored analysis): ML + SHAP + Mistral summary, stored as a
  version. ML and SHAP need the raw bytes, so for a stored `hash_only` analysis they report `unavailable`.
- **Threat intel** (`POST /api/v1/analyses/{id}/threat-intel` with `{"consent": true}`): versioned run,
  cached per indicator; informational, never changes the rule verdict.
- **Recompute** ATT&CK or risk from stored inputs.

**Reports** (`GET /investigations/{case}/report/{analysis}` for PDF,
`GET /analyses/{id}/report.html`): built from stored data with pinned versions, masked for viewers, and
audited (`report_generated`).

## 3. Trust boundaries and what leaves the host

| Boundary | What crosses it | Control |
|---|---|---|
| Browser → Nginx | Uploaded `.eml`, API calls with a bearer token | CSP `default-src 'self'`, `connect-src 'self'`; `no-store` on API responses; 11 MB Nginx body limit |
| Nginx → backend | Proxied `/api/` requests | Internal Compose network only; the backend has no host port |
| Backend → PostgreSQL | All stored data | Internal network; password from `deploy/.env`; data unencrypted at rest |
| Backend → DNS resolvers | Domains (SPF/DKIM/DMARC records, MX/A) | Upload-time; off in `offline`/`demo` |
| Backend → RDAP, ip-api | Domains, IPs | Upload-time enrichment; `ENRICH_ENABLE_*`; off in `offline`/`demo` |
| Backend → VirusTotal, AbuseIPDB, Shodan, IPinfo, Tor list | Bare IPs, domains, attachment SHA-256 only | **Per-analysis consent**; credentials required; `INTEL_OFFLINE`; GET-only; no uploads, no URLs, no message content |
| Backend → Ollama (host) | Redacted evidence for the summary | Loopback or `OLLAMA_ALLOWED_HOSTS` only; local model |
| Backend → SMTP | Alert e-mail (optional, off by default; off in the demo) | `ALERT_EMAIL_ENABLED`; secrets from the environment |

Message bodies, subjects, addresses and headers are never sent to an external intel provider. The Docker demo
(`APP_ENV=demo`) makes no live DNS or intel lookups, and the SPA loads no external resources (checked by
`scripts/smoke.py`).

## 4. Roles and permissions

Generated from `backend/app/security/permissions.py` (`ROLE_PERMISSIONS`):

<!-- gen:roles:begin -->
| Role | Permissions added at this role |
|---|---|
| viewer | `alert:read`, `analysis:read`, `assessment:read`, `attack:read`, `case:read`, `correlation:read`, `intel:read`, `ml:status`, `report:download`, `risk:read`, `search:read` |
| analyst | `alert:manage`, `analysis:create`, `assessment:run`, `attack:recompute`, `case:write`, `custody:read`, `evidence:verify`, `intel:run`, `ml:run`, `pii:view`, `risk:recompute` |
| admin | `audit:manage`, `audit:read`, `config:status`, `correlation:rebuild`, `docs:read`, `retention:manage`, `users:manage` |

Roles are cumulative (analyst includes viewer, admin includes analyst) and global: there are no per-case ACLs.
<!-- gen:roles:end -->

### Route inventory

Generated from the FastAPI route inventory and `ROUTE_PERMISSIONS`:

<!-- gen:routes:begin -->
| Method | Path | Permission | Lowest role |
|---|---|---|---|
| GET | `/api/v1/admin/alerts/config` | `config:status` | admin |
| DELETE | `/api/v1/admin/analyses/{analysis_id}` | `retention:manage` | admin |
| GET | `/api/v1/admin/holds` | `retention:manage` | admin |
| POST | `/api/v1/admin/holds` | `retention:manage` | admin |
| POST | `/api/v1/admin/holds/{hold_id}/clear` | `retention:manage` | admin |
| POST | `/api/v1/admin/retention/run` | `retention:manage` | admin |
| GET | `/api/v1/admin/retention/status` | `retention:manage` | admin |
| GET | `/api/v1/admin/users` | `users:manage` | admin |
| POST | `/api/v1/admin/users` | `users:manage` | admin |
| PATCH | `/api/v1/admin/users/{user_id}` | `users:manage` | admin |
| POST | `/api/v1/admin/users/{user_id}/reset-password` | `users:manage` | admin |
| GET | `/api/v1/alerts` | `alert:read` | viewer |
| GET | `/api/v1/alerts/summary` | `alert:read` | viewer |
| GET | `/api/v1/alerts/{alert_id}` | `alert:read` | viewer |
| POST | `/api/v1/alerts/{alert_id}/acknowledge` | `alert:manage` | analyst |
| POST | `/api/v1/alerts/{alert_id}/reopen` | `alert:manage` | analyst |
| POST | `/api/v1/alerts/{alert_id}/resolve` | `alert:manage` | analyst |
| GET | `/api/v1/analyses` | `analysis:read` | viewer |
| POST | `/api/v1/analyses` | `analysis:create` | analyst |
| GET | `/api/v1/analyses/{analysis_id}` | `analysis:read` | viewer |
| GET | `/api/v1/analyses/{analysis_id}/assessment` | `assessment:read` | viewer |
| GET | `/api/v1/analyses/{analysis_id}/assessments` | `assessment:read` | viewer |
| GET | `/api/v1/analyses/{analysis_id}/assessments/{assessment_id}` | `assessment:read` | viewer |
| GET | `/api/v1/analyses/{analysis_id}/attack` | `attack:read` | viewer |
| GET | `/api/v1/analyses/{analysis_id}/attack/history` | `attack:read` | viewer |
| POST | `/api/v1/analyses/{analysis_id}/attack/recompute` | `attack:recompute` | analyst |
| GET | `/api/v1/analyses/{analysis_id}/correlation` | `correlation:read` | viewer |
| GET | `/api/v1/analyses/{analysis_id}/custody` | `custody:read` | analyst |
| POST | `/api/v1/analyses/{analysis_id}/forensic-summary` | `assessment:run` | analyst |
| GET | `/api/v1/analyses/{analysis_id}/geo` | `analysis:read` | viewer |
| GET | `/api/v1/analyses/{analysis_id}/report.html` | `report:download` | viewer |
| GET | `/api/v1/analyses/{analysis_id}/risk` | `risk:read` | viewer |
| GET | `/api/v1/analyses/{analysis_id}/risk/history` | `risk:read` | viewer |
| POST | `/api/v1/analyses/{analysis_id}/risk/recompute` | `risk:recompute` | analyst |
| GET | `/api/v1/analyses/{analysis_id}/threat-intel` | `intel:read` | viewer |
| POST | `/api/v1/analyses/{analysis_id}/threat-intel` | `intel:run` | analyst |
| GET | `/api/v1/analytics/summary` | `analysis:read` | viewer |
| GET | `/api/v1/audit/checkpoint` | `audit:read` | admin |
| POST | `/api/v1/audit/checkpoint` | `audit:manage` | admin |
| GET | `/api/v1/audit/events` | `audit:read` | admin |
| GET | `/api/v1/audit/export` | `audit:read` | admin |
| GET | `/api/v1/audit/verify` | `audit:read` | admin |
| POST | `/api/v1/auth/change-password` | `self` | any signed-in user |
| POST | `/api/v1/auth/login` | `public` | anonymous |
| POST | `/api/v1/auth/logout` | `self` | any signed-in user |
| GET | `/api/v1/auth/me` | `self` | any signed-in user |
| GET | `/api/v1/campaigns` | `correlation:read` | viewer |
| GET | `/api/v1/campaigns/{campaign_id}` | `correlation:read` | viewer |
| GET | `/api/v1/campaigns/{campaign_id}/geo` | `correlation:read` | viewer |
| POST | `/api/v1/correlation/rebuild` | `correlation:rebuild` | admin |
| GET | `/api/v1/graph/entities/{entity_type}/{value}` | `correlation:read` | viewer |
| GET | `/api/v1/health` | `public` | anonymous |
| GET | `/api/v1/health/ready` | `public` | anonymous |
| GET | `/api/v1/intel/status` | `config:status` | admin |
| GET | `/api/v1/investigations` | `case:read` | viewer |
| POST | `/api/v1/investigations/from-analysis/{analysis_id}` | `case:write` | analyst |
| GET | `/api/v1/investigations/{case_id}` | `case:read` | viewer |
| GET | `/api/v1/investigations/{case_id}/analyses` | `case:read` | viewer |
| POST | `/api/v1/investigations/{case_id}/analyses` | `case:write` | analyst |
| DELETE | `/api/v1/investigations/{case_id}/analyses/{analysis_id}` | `case:write` | analyst |
| POST | `/api/v1/investigations/{case_id}/evidence-integrity/{analysis_id}` | `evidence:verify` | analyst |
| GET | `/api/v1/investigations/{case_id}/indicators` | `case:read` | viewer |
| GET | `/api/v1/investigations/{case_id}/report/{analysis_id}` | `report:download` | viewer |
| POST | `/api/v1/llm/forensic-summary` | `assessment:run` | analyst |
| GET | `/api/v1/llm/status` | `config:status` | admin |
| POST | `/api/v1/ml/classify` | `ml:run` | analyst |
| POST | `/api/v1/ml/explain` | `ml:run` | analyst |
| GET | `/api/v1/ml/status` | `ml:status` | viewer |
| GET | `/api/v1/search` | `search:read` | viewer |
| GET | `/api/v1/system/info` | `analysis:read` | viewer |
| GET | `/docs` (dev/test only) | `docs:read` | admin |
| GET | `/openapi.json` (dev/test only) | `docs:read` | admin |
| GET | `/redoc` (dev/test only) | `docs:read` | admin |

73 routes. A route missing from the map is denied to everyone; `tests/unit/test_access_control.py` fails if one is added without a permission.
<!-- gen:routes:end -->

## 5. Database

<!-- gen:tables:begin -->
| Table | Columns |
|---|---:|
| `alert` | 23 |
| `alert_event` | 10 |
| `analysis` | 34 |
| `analysis_assessment` | 6 |
| `app_user` | 12 |
| `assessment_version` | 8 |
| `attack_mapping` | 11 |
| `audit_chain_head` | 3 |
| `audit_event` | 14 |
| `case_analysis_link` | 4 |
| `corr_campaign` | 12 |
| `corr_campaign_member` | 2 |
| `corr_entity` | 5 |
| `corr_observation` | 6 |
| `corr_state` | 4 |
| `geo_observation` | 14 |
| `intel_cache` | 9 |
| `investigation_case` | 5 |
| `legal_hold` | 9 |
| `ml_classification` | 7 |
| `risk_assessment` | 12 |
| `schema_migrations` | 3 |
| `threat_intel_run` | 9 |

23 tables (SQLAlchemy models in `backend/app/core/models.py`).
<!-- gen:tables:end -->

### Migrations

`backend/app/core/migrations.py` runs the steps not yet recorded in `schema_migrations`, in order, at app
start-up, before every CLI command and in the container entrypoint (`python -m app.cli migrate`). On
PostgreSQL an advisory lock serialises concurrent starts. Steps are idempotent and additive:

<!-- gen:migrations:begin -->
| Version | Step |
|---:|---|
| 1 | `baseline_tables` |
| 2 | `audit_event_actor_user_id` |
| 3 | `analysis_search_indexes` |
| 4 | `geo_observation_table` |
| 5 | `audit_and_retention_columns` |
| 6 | `audit_chain_genesis` |
| 7 | `audit_append_only_triggers` |
| 8 | `risk_assessment_tables` |
| 9 | `alert_tables` |
| 10 | `analysis_parser_crosscheck` |
<!-- gen:migrations:end -->

Upgrading an existing dev database: [DEV_DB_UPGRADE.md](DEV_DB_UPGRADE.md).

## 6. Audit chain

Details: [audit/README.md](audit/README.md).

- Every audit event carries actor, target, outcome, source IP and time, and is appended to an
  **HMAC-SHA256 hash chain** keyed by `AIPISH_AUDIT_KEY` (`seq`, `prev_hash`, `event_hash`; head in
  `audit_chain_head`).
- Triggers reject `UPDATE`/`DELETE` on `audit_event` (PostgreSQL and SQLite); a superuser or table owner can
  bypass them, which the chain detects.
- `GET /audit/verify` and `python -m app.cli audit-verify` report the first broken `seq` and a reason.
  Checkpoints (`POST /audit/checkpoint`) are meant to be copied outside the system.
- **Tamper-evident, not tamper-proof.** No WORM storage, no external timestamping, no key rotation.

## 7. Retention and masking

- Retention (`backend/app/retention/service.py`): `redact` (remove personal content, keep hashes, IOCs and
  scores) or `delete`, a grace period, and legal holds. Disabled by default; dry run unless applied; audit
  events are never purged. No built-in scheduler: `scripts/retention-run.sh` or the Compose `retention`
  profile.
- Masking (`backend/app/privacy/masking.py`): without `pii:view` (viewers), addresses are partially masked and
  display names and bodies are hidden in the API, UI, PDF and HTML. Subjects are not masked.

## 8. Deployment topology

`deploy/docker-compose.yml`:

| Service | Image | Exposed | Notes |
|---|---|---|---|
| `postgres` | `postgres:17.12-alpine` | none | Volume `pgdata` |
| `backend` | `aipish-backend` (Python 3.13, CPU PyTorch when `AIPISH_WITH_ML=1`) | none | Read-only root FS; volume `backend-var`; models mounted read-only from `AIPISH_MODELS_DIR`; reaches host Ollama via `host.docker.internal` |
| `web` | `aipish-web` (Nginx) | `${AIPISH_BIND_ADDRESS:-127.0.0.1}:${AIPISH_HTTP_PORT:-8080}` | Read-only root FS; SPA + reverse proxy |
| `retention` | `aipish-backend` | none | Profile `retention`: periodic `retention-run` |
| `postgres-test` | `postgres:17.12-alpine` | `127.0.0.1:55432` | Profile `test`: `make test-pg` |

The demo (`scripts/demo-up.sh`) runs as Compose project `aipish-demo` with `APP_ENV=demo`. Production setup,
TLS, backups and the environment-variable reference: [deployment/README.md](deployment/README.md).
CI (`.github/workflows/ci.yml`): backend on SQLite (with ML stack) and PostgreSQL 17 (without), frontend
checks, image builds, `nginx -t`, compose validation, gitleaks, forbidden-file check, actionlint, and the
documentation checks. See [TESTING.md](TESTING.md).
