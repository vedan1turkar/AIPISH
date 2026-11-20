# Email Forensics Platform (MVP)

AI-powered email threat detection, header forensics, and forensic reporting.

## Quickstart (Local)

### Prerequisites

- Python 3.11+
- Node.js 20+ and npm

### Backend

```bash
cd backend
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
# P5b: the backend refuses to start without a strong JWT secret (outside APP_ENV=test).
echo "AIPISH_JWT_SECRET=$(python -c 'import secrets; print(secrets.token_urlsafe(48))')" >> ../.env
# Local dev users: demo-admin / demo-analyst / demo-viewer with random passwords
# written to backend/.dev_credentials (0600, gitignored). Only the path is printed.
python -m app.cli seed-dev-users
uvicorn app.main:app --port 8000 --reload
```

Health check (the only public endpoint besides login): `curl http://127.0.0.1:8000/api/v1/health`

Every other endpoint needs `Authorization: Bearer <token>` from `POST /api/v1/auth/login`. Roles,
the per-route permission table and the threat model are in [docs/auth/README.md](docs/auth/README.md).

### Frontend

```bash
cd frontend
npm install
npm run dev
```

Open http://localhost:5173.

## Configuration

Copy `.env.example` to `.env` at the repo root and adjust values.
All settings are environment variables prefixed with `APP_`; secrets (when
added later) must be set as environment variables and never committed.

## Evidence & Audit Policy (application-level)

- **Raw .eml bytes are NOT stored by default.** Only the SHA-256 and size are
  retained; the analysis record is treated as the sanitized metadata record.
- To retain the exact raw bytes, set `CASE_EVIDENCE_STORE=raw` (and optionally
  `CASE_EVIDENCE_STORE_KEY=<secret>` to require an `X-Evidence-Key` header on
  report downloads). Retention defaults to 90 days (`CASE_EVIDENCE_RETENTION_DAYS`).
  The raw-bytes path is opt-in and access-restricted; the integrity endpoint
  recomputes SHA-256 over the preserved bytes when retained.
- Audit events (`analysis_created`, `evidence_accessed`, `integrity_verified`,
  `report_generated`) are recorded in SQLite. This is **application-level
  integrity and audit logging — NOT a tamper-resistant cryptographic chain of
  custody.** True immutability would require hash-chained or WORM storage,
  which is not implemented in this MVP.

## Forensic PDF Reports

`GET /api/v1/investigations/{case_id}/report/{analysis_id}` (downloads a
styled ReportLab PDF with verdict, findings, authentication claims vs
verified results, relay chain, enrichment provenance, integrity status, and
limitations). Invocations are audited (`report_generated`).

## Environment Variables

| Variable | Default | Purpose |
|---|---|---|
| `APP_ENV` | `dev` | Environment profile |
| `APP_BIND_HOST` | `127.0.0.1` | Backend bind address |
| `APP_PORT` | `8000` | Backend port |
| `APP_ALLOWED_ORIGINS` | `http://localhost:5173` | CORS origins |
| `APP_DB_PATH` | `db/app.sqlite` | SQLite path |
| `APP_UPLOAD_MAX_MB` | `10` | Max .eml upload size |
| `APP_REQUEST_TIMEOUT_SECONDS` | `60` | Pipeline timeout |
| `APP_LOG_LEVEL` | `INFO` | Log level |
| `AIPISH_JWT_SECRET` | — (required outside `APP_ENV=test`) | HS256 signing secret, ≥ 32 random characters |
| `AIPISH_JWT_TTL_MINUTES` | `60` | Access-token lifetime (no refresh tokens) |
| `AIPISH_LOGIN_MAX_FAILURES_USER` / `_IP` | `5` / `20` | Failed logins before a lockout (in-memory) |
| `AIPISH_LOGIN_WINDOW_SECONDS` / `AIPISH_LOGIN_LOCKOUT_SECONDS` | `900` / `900` | Throttle window and lockout length |

## Test Commands

```bash
# Backend: full suite (101 tests)
cd backend
source .venv/bin/activate
python -m pytest tests -q

# Frontend: typecheck, lint, production build
cd frontend
npx tsc -b --noEmit
npx eslint 'src/**/*.{ts,tsx}'
npm run build

# End-to-end check against a running backend (14 scenario groups)
# start backend first, then:
python3 /tmp/e2e_verify.py
```

## API Endpoints

All routes are under `/api/v1`. All except `/health` and `/auth/login` require a bearer token and a
role; see [docs/auth/README.md](docs/auth/README.md) for the full per-route permission table.

| Method | Path | Purpose |
|---|---|---|
| GET | `/health` | Liveness + DB check (public) |
| POST | `/auth/login` | JSON `{"username","password"}` → bearer token (public) |
| GET | `/auth/me` | Current user and permissions |
| POST | `/auth/logout` | Revoke all of the current user's tokens |
| POST | `/auth/change-password` | Change own password (current password required) |
| GET/POST | `/admin/users` | Admin: list users / create user with a one-time temporary password |
| PATCH | `/admin/users/{id}` | Admin: change role, disable/enable (last active admin protected) |
| POST | `/admin/users/{id}/reset-password` | Admin: one-time temporary password, revokes sessions |
| POST | `/analyses` | Upload a raw `.eml` → full forensic analysis (multipart field `file`) |
| GET | `/analyses` | Recent analyses (history list) |
| GET | `/analyses/{id}` | One analysis: metadata, detection findings, forensics, auth, enrichment |
| POST | `/investigations/from-analysis/{id}` | Create an investigation case from an analysis |
| GET | `/investigations` | List investigation cases |
| GET | `/investigations/{id}` | One case incl. its analyses |
| POST | `/investigations/{case}/evidence-integrity/{analysis}` | Recompute SHA-256 of retained bytes |
| GET | `/investigations/{case}/report/{analysis}` | Download the forensic PDF (`?assessment_id=` / `?intel_run_id=` pin versions) |
| GET | `/intel/status` | Threat-intel providers: configured/enabled booleans only |
| POST | `/analyses/{id}/threat-intel` | Consent-gated threat-intel lookup (body `{"consent": bool}`); appends a versioned run |
| GET | `/analyses/{id}/threat-intel` | Latest (or `?run_id=`) stored threat-intel run |

Error responses always have the shape `{"error": {"code", "message", "request_id?"}}`.

## Optional API Keys & Enrichment

Out of the box the app runs with **DNS enrichment only** — no keys needed.
Credibility lookups are strictly opt-in and degrade gracefully to a visible
`skipped` status when unconfigured:

| Variable | Default | Effect when set |
|---|---|---|
| `ENRICH_ENABLE_DNS` | `1` | `0` disables DNS lookups |
| `ENRICH_ENABLE_RDAP` | `1` | `0` disables domain registration lookups |
| `ENRICH_ENABLE_IPGEO` | `1` | `0` disables IP infrastructure geo |
| `ENRICH_IPGEO_BASE` | ip-api.com | Alternative geo endpoint |
| `ENRICH_DNS_TIMEOUT` | `10` | Seconds per DNS query |
| `VIRUSTOTAL_API_KEY`, `ABUSEIPDB_API_KEY`, `SHODAN_API_KEY`, `IPINFO_TOKEN` | *(unset)* | Threat-intel providers (P5a). Used only after explicit per-analysis consent; without a key the provider reports `missing_credentials`. See [docs/intel/README.md](docs/intel/README.md) |
| `INTEL_OFFLINE` | `0` | `1` blocks every external threat-intel call (also implied by `APP_ENV=offline`) |
| `MAXMIND_GEOIP2_DB` | *(unset)* | Path to a GeoLite2 `.mmdb` — without it the provider reports `skipped` |
| `CASE_EVIDENCE_STORE` | `hash_only` | `raw` also retains exact message bytes for integrity re-verification |
| `CASE_EVIDENCE_STORE_KEY` | *(unset)* | When set with `raw`, report downloads require header `X-Evidence-Key` |
| `CASE_EVIDENCE_RETENTION_DAYS` | `90` | Documented retention window (cleanup manual) |
| `VITE_API_BASE` | *(empty)* | Frontend: set only when backend is NOT behind the Vite dev proxy (e.g. separate host) |

No secret is ever returned by the API; absent keys surface as explicit
`skipped` statuses in the enrichment panel rather than silent gaps.

## Troubleshooting

| Symptom | Likely cause & fix |
|---|---|
| `backend offline` pill in the UI | uvicorn not running — see backend startup above; check `curl http://127.0.0.1:8000/api/v1/health` |
| `RuntimeError: Form data requires "python-multipart"` | `pip install python-multipart` inside the venv (it's in requirements.txt) |
| `ModuleNotFoundError: reportlab` | `pip install reportlab` (or reinstall requirements) |
| 415 on upload from the UI | File must be a raw `.eml` (not `.msg`, not a MIME-forwarded attachment) |
| 413 on upload | File exceeds `APP_UPLOAD_MAX_MB` (default 10 MB) |
| Frontend loads but charts/graphs empty after upload | Backend reachable? Check the browser network tab — in dev, requests go to `/api/*` via the Vite proxy on 5173 → 8000 |
| CORS error in browser console | Add your frontend origin to `APP_ALLOWED_ORIGINS` and restart uvicorn |
| PDF download 401 | Raw-evidence mode needs `X-Evidence-Key` header matching `CASE_EVIDENCE_STORE_KEY` |
| Port 8000 already in use | `lsof -ti :8000 | xargs kill` then restart uvicorn |
| Tests fail with DNS errors offline | Set `ENRICH_ENABLE_ALL=0` or ensure network; enrichment tests mock providers |

## Demo Fixtures (synthetic)

`backend/tests/fixtures/demo/` contains three **synthetic** messages — no real
personal data, no real bank details, reserved/documentation domains only:

- `legitimate_invoice.eml` — benign colleague mail (should score ~0)
- `phishing_account_verify.eml` — brand-lookalike phishing with failing auth (score ~100)
- `bec_wire_change.eml` — executive impersonation + wire-b diversion wording (BEC rules fire)

## Persistence

SQLite via SQLAlchemy at `backend/db/app.sqlite` (created on first boot).
Configured by `APP_DB_PATH`; override with an absolute path if you want it
elsewhere. Sensitive data stays out of git via `.gitignore`.

## Known Limitations

- Local password auth + JWT with global roles (viewer/analyst/admin): no OAuth/SSO/MFA, no refresh
  tokens, no per-case ownership; login throttling is in-memory (see docs/auth/README.md).
- Audit log is application-level; not a tamper-resistant chain of custody.
- Raw-evidence retention cleanup is manual (config-documented, no daemon).
- IP geolocation resolves *network infrastructure*, never a person; skip it
  entirely for privacy-sensitive demos.
- Heuristic detection: scores are investigative indicators, not proof; absent
  findings ≠ safe.
- Credibility providers (AbuseIPDB, MaxMind) are wired but adapters are
  stubbed; only DNS/RDAP/ip-api perform real lookups today.
