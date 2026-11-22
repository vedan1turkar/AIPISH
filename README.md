# AIPISH: email threat forensics

AIPISH analyses a raw email (`.eml`) and shows an analyst the evidence: header and relay forensics,
SPF/DKIM/DMARC re-verification, 18 detection rules, an ML classification with SHAP, an optional local LLM
summary, consent-gated threat intelligence, cross-message campaigns, MITRE ATT&CK mapping, a combined risk
index, alerts, and PDF/HTML reports. It was built as non-commercial university coursework (PBL, Group G7).

**What it is not.** It is not a mail gateway or a mailbox monitor (there is no IMAP/Graph ingestion, so alerts
are not real-time). It does not identify attackers, people or physical locations. A low score, `minimal`, or
"no record" from a provider is not proof that a message is safe. The ML model was trained on old (1998–2007),
partly synthetic data; its scores are uncalibrated. See [docs/LIMITATIONS.md](docs/LIMITATIONS.md).

| Start here | |
|---|---|
| One-page summary | [docs/PROJECT_SUMMARY.md](docs/PROJECT_SUMMARY.md) |
| Architecture, data flow, routes and permissions | [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) |
| Requirements R1–R60 and status | [docs/REQUIREMENTS_SUMMARY.md](docs/REQUIREMENTS_SUMMARY.md), [docs/requirements-matrix.md](docs/requirements-matrix.md) |
| 12-minute demo walkthrough | [docs/DEMO_SCRIPT.md](docs/DEMO_SCRIPT.md) |
| Tests, CI and verification scope | [docs/TESTING.md](docs/TESTING.md) |
| Limitations and threats to validity | [docs/LIMITATIONS.md](docs/LIMITATIONS.md) |
| Licences, data provenance and provider terms | [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) |
| Change history | [docs/CHANGELOG.md](docs/CHANGELOG.md) |

## Features and status

Status codes come from the requirements matrix: **VER** implemented and verified (tests plus a real-app run),
**IMP-U** implemented with incomplete verification, **PART** partial, **MISS** missing, **BLK** blocked.

| Area | What it does | Status |
|---|---|---|
| Parsing and evidence | `.eml` parsing, SHA-256, attachment metadata (never stored), mail-parser cross-check | VER |
| Header forensics | Relay chain, trust boundary, candidate origin IPs, header consistency | VER |
| Authentication | SPF/DKIM/DMARC re-verified locally; header claims kept separate | IMP-U (not verified against live DNS) |
| Detection rules | 18 weighted rules → score 0–100 and verdict | VER (low recall on the corpora; see limitations) |
| ML classification | DistilRoBERTa + XGBoost ensemble, five classes | PART (`suspicious` has no data; two classes synthetic) |
| Explanations | SHAP for the XGBoost component only | PART |
| Local LLM summary | Mistral via Ollama, evidence-cited, constrained recommendations | VER |
| Combined risk | Explainable index with evidence; not a probability | VER |
| Threat intelligence | VirusTotal, AbuseIPDB, Shodan, IPinfo, Tor list; per-analysis consent | VER for the paths exercised live; MISP and MaxMind BLK |
| Correlation | Candidate campaigns from shared non-generic indicators (NetworkX) | Graph and campaigns VER; intel/campaign correlation (R18) IMP-U; heuristic weights |
| MITRE ATT&CK | Mapping to Enterprise 20.1, source-type hypotheses | VER (single-message approximations) |
| Geolocation and analytics | Leaflet map from stored data, Plotly analytics | Map IMP-U (one real point verified), analytics VER |
| Alerts | Risk-based, de-duplicated, acknowledge/resolve/reopen, optional e-mail | PART (event-driven, not real-time) |
| Reports and cases | ReportLab PDF, Jinja2 HTML, cases, search | VER |
| Access control | Local accounts, JWT, viewer/analyst/admin, deny-by-default routes | VER (no OAuth/SSO/MFA) |
| Audit, retention, masking | HMAC hash-chained audit log, retention with legal holds, viewer masking | VER (tamper-evident, not tamper-proof; subjects not masked) |
| Deployment and CI | Docker Compose + Nginx + PostgreSQL; GitHub Actions | VER |

## Architecture

```
Browser (React SPA) ──► Nginx (static files, CSP, /api proxy) ──► FastAPI backend ──► PostgreSQL
                                                                     │   (SQLite in development)
                                       host-only, optional:          ├──► Ollama + mistral (local LLM)
                                                                     ├──► models/ (mounted read-only)
                          external, consent or config gated:         └──► DNS/RDAP/ip-api, VirusTotal,
                                                                          AbuseIPDB, Shodan, IPinfo, Tor list

Upload: parse → cross-check → header forensics → SPF/DKIM/DMARC → enrichment → rules → store
        → correlation → ATT&CK → ML at upload → combined risk → alerts
On demand: AI assessment (ML + SHAP + Mistral), threat intel (consent), PDF/HTML reports
```

Details, trust boundaries and the generated route/permission tables: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Quick start: Docker demo (one command)

Requirements: Docker Desktop (or Docker Engine with Compose v2) and about 5 GB of disk. Optional: the trained
models in `models/aipish-email-v1/` (not in git) and Ollama with `mistral` on the host for the AI assessment.

```bash
git clone https://github.com/vedan1turkar/AIPISH.git
```

```bash
cd AIPISH && scripts/demo-up.sh
```

What to expect:

- The script creates `deploy/.env` with random secrets (mode 0600, gitignored, never printed), builds the
  images on first run (about 3–4 minutes on an Apple M4), starts PostgreSQL, the backend and Nginx as Compose
  project `aipish-demo`, and seeds **synthetic** data: 8 analyses, candidate campaign C-0001 and 7 alerts.
- With images present, a fresh start took 95–99 s in the release run (including the AI assessment of the
  BEC sample).
- Open **http://localhost:8080**. Credentials for `demo-admin`, `demo-analyst` and `demo-viewer` are in
  **`.demo/credentials`** (gitignored, mode 0600; the script prints only its path).
- The demo runs with `APP_ENV=demo`: no live DNS or threat-intel lookups, and no alert e-mail.
- Check it: `python3 scripts/smoke.py` (36 checks; creates and disables its own temporary accounts).
- Stop and delete the demo data: `scripts/demo-reset.sh`.

Production deployment, TLS, backups and the full environment-variable reference:
[docs/deployment/README.md](docs/deployment/README.md).

## Development setup

Tested with Python 3.13 and Node.js 24 (the versions used in CI and the images).

Backend:

```bash
cd backend && python3 -m venv .venv && source .venv/bin/activate
```

```bash
pip install -r requirements-dev.txt -c constraints.txt
```

```bash
pip install -r requirements-ml.txt -c constraints.txt   # optional ML stack (PyTorch, transformers, XGBoost, SHAP)
```

```bash
cp ../.env.example ../.env   # then set AIPISH_JWT_SECRET (≥ 32 random characters)
```

```bash
python -m app.cli seed-dev-users   # demo-admin/analyst/viewer; passwords go to backend/.dev_credentials (0600)
```

```bash
uvicorn app.main:app --port 8000 --reload
```

The backend refuses to start without a strong `AIPISH_JWT_SECRET` (outside `APP_ENV=test`). In `dev`, a missing
`AIPISH_AUDIT_KEY` is generated into `.env`. Only `/api/v1/health`, `/api/v1/health/ready` and
`/api/v1/auth/login` are public.

Frontend (Vite dev server on :5173, proxies `/api` to :8000):

```bash
cd frontend && npm ci && npm run dev
```

Configuration is by environment variables; templates: [.env.example](.env.example) (development) and
[deploy/env.example](deploy/env.example) (Compose). Secrets are never committed.

To upgrade an older local SQLite database: [docs/DEV_DB_UPGRADE.md](docs/DEV_DB_UPGRADE.md).

## Running tests

```bash
cd backend && python -m pytest -q -rs        # SQLite; network blocked; live tests skipped
```

```bash
make test-pg                                 # same suite on a throwaway PostgreSQL (Docker, port 55432)
```

```bash
cd frontend && npm run typecheck && npx eslint . && npm test && npm run build
```

```bash
python3 scripts/matrix_counts.py --check && python3 scripts/check_docs.py   # documentation checks
```

Suites, counts, skip reasons, CI jobs and what is mocked, simulated or live: [docs/TESTING.md](docs/TESTING.md).

## Technology

| Technology | Status | Where / why |
|---|---|---|
| React 18, Vite 5, Tailwind CSS 3 | Implemented | `frontend/` |
| FastAPI, Pydantic | Implemented | `backend/app/api/` |
| SQLAlchemy 2 | Implemented | `backend/app/core/` |
| SQLite / PostgreSQL 17 | Implemented | SQLite for development and tests; PostgreSQL in Compose and CI (psycopg 3) |
| DistilRoBERTa (transformers, PyTorch CPU) | Implemented | Transformer component of the ensemble; weights in `models/` (not in git) |
| XGBoost | Implemented | Feature-based component of the ensemble |
| scikit-learn | Implemented | Logistic-regression component (ensemble weight 0), metrics |
| SHAP | Partial | Explains the XGBoost component only |
| Ollama + Mistral | Implemented (optional) | Local forensic summary; host service |
| mail-parser | Implemented | Informational second parser (cross-check only) |
| dnspython, dkimpy, pyspf | Implemented | SPF/DKIM/DMARC re-verification; not verified against live DNS |
| VirusTotal, AbuseIPDB, Shodan, IPinfo, Tor exit list | Implemented | Consent-gated; live-verified for the approved indicators only ([docs/intel/LIVE_VERIFICATION.md](docs/intel/LIVE_VERIFICATION.md)) |
| MISP | Not configured | No MISP instance available (R47) |
| MaxMind GeoIP2 | Not configured | No licence or database (R48) |
| NetworkX | Implemented | Correlation (connected components) |
| Neo4j | Not used | Not needed at this scale; NetworkX in process (R50) |
| OpenSearch | Not used | SQL `LIKE`/`ILIKE` search (R52) |
| Redis, Celery | Not used | Work runs synchronously; no background workers (R35) |
| Leaflet | Implemented | Infrastructure map, bundled Natural Earth outline, no tiles |
| Cytoscape.js | Implemented | Trace and campaign graphs |
| Plotly (basic dist) | Implemented | Analytics page |
| ReportLab | Implemented | PDF reports |
| Jinja2 | Implemented | HTML report and alert e-mail templates |
| JWT (PyJWT), local accounts | Implemented | HS256 access tokens, scrypt password hashes; no refresh tokens |
| OAuth 2.0 / OIDC / SSO | Not implemented | No identity provider chosen (R53) |
| Docker, Docker Compose, Nginx | Implemented | `backend/Dockerfile`, `frontend/Dockerfile`, `deploy/docker-compose.yml` |
| GitHub Actions | Implemented | `.github/workflows/ci.yml` (CI only, no deployment) |
| MITRE ATT&CK | Implemented | Enterprise 20.1 catalogue, `backend/app/attack/` |

## Troubleshooting

| Symptom | Likely cause and fix |
|---|---|
| `Docker is not running` from `demo-up.sh` | Start Docker Desktop. |
| AI assessment shows UNAVAILABLE | Ollama not running or `mistral` not pulled; or models not mounted. Everything else still works. |
| Upload rejected with 413 | File larger than `APP_UPLOAD_MAX_MB` (10 MB). |
| Upload rejected with 415 | Not an `.eml` (name or `message/rfc822` type). |
| 429 at sign-in | Five failed attempts lock the account for 15 minutes (`AIPISH_LOGIN_*`; in memory). |
| Backend refuses to start | Missing or weak `AIPISH_JWT_SECRET` or (outside dev) `AIPISH_AUDIT_KEY`. |
| CORS error in development | Add the frontend origin to `APP_ALLOWED_ORIGINS`. |

## Licence

No licence is specified for this project. Third-party components keep their own licences:
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
