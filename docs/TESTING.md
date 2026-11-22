# Testing

Counts below are from the **P5z release runs (2026-11-22)** on a clean clone in a temporary directory, never
the developer's own database. CI repeats them on every push to `main` (`.github/workflows/ci.yml`).

## 1. Suites and counts

| Suite | Command | Result (P5z) |
|---|---|---|
| Backend, SQLite, with the ML stack (CI job `backend-sqlite`) | `cd backend && python -m pytest -q -rs` | **788 passed, 13 skipped** |
| Backend, SQLite, without the ML stack | same, in a virtualenv with only `requirements-dev.txt` | 753 passed, 15 skipped |
| Backend, PostgreSQL 17 (`make test-pg`; CI job `backend-postgres` runs it without the ML stack) | `make test-pg` | **789 passed, 12 skipped** (with the ML stack); 754 passed, 14 skipped without it (the CI configuration) |
| Frontend unit and component tests (16 files) | `cd frontend && npm test` | **205 passed** |
| Frontend typecheck | `npm run typecheck` | pass, no errors |
| Frontend lint | `npx eslint .` | pass, no findings |
| Frontend production build | `npm run build` | pass; Vite warns that the lazy-loaded Plotly chunk is 1.2 MB (406 kB gzip) |
| Documentation checks | `python3 scripts/matrix_counts.py --check`, `python3 scripts/check_docs.py` | pass (matrix totals consistent; 31 Markdown files, 0 problems) |
| End-to-end smoke test against the Docker demo | `python3 scripts/smoke.py` | 36 passed, 0 failed, 0 skipped (fresh from-scratch demo) |

The backend suite runs on a fresh temporary SQLite file (`tests/conftest.py`) with **network access blocked**
(`pytest-socket`, `--disable-socket`); the PostgreSQL run allows only `127.0.0.1`.

## 2. Skip reasons (all explicit)

| Skip | Count | Reason printed by pytest |
|---|---:|---|
| Live threat-intel tests | 11 | `live test: set AIPISH_RUN_LIVE=1 to run` (`tests/unit/test_intel.py`) |
| Live LLM test | 1 | `live test: set AIPISH_RUN_LIVE=1 to run` (`tests/unit/test_llm.py`) |
| PostgreSQL-only trigger test | 1 on SQLite | `PostgreSQL-only: trigger disable + rollback` (`tests/unit/test_audit.py`) |
| ML modules without the ML stack | 2 module skips | `could not import 'shap'` (`test_explain.py`), `could not import 'sklearn'` (`test_ml.py`) |

Tests that need the trained models or the dataset skip themselves with a reason when those local-only assets
are absent (they are never in git or CI).

## 3. Backend test inventory

`backend/tests/unit/`: access control (route inventory and role matrix), address comparison, alerts, assessment
report, ATT&CK, audit, authentication (SPF/DKIM/DMARC), config, correlation, cross-check and HTML report, dataset,
defect fixes, deployment, detection, **documentation consistency** (P5z), enrichment, errors, explain (SHAP),
forensics, geo and analytics, health, threat intel, threat-intel live shapes, LLM, ML, P4.1/P4.2 policies,
parser, risk. `backend/tests/integration/`: upload API and investigations.

`test_docs_consistency.py` (P5z) runs the matrix and link checks and fails when the generated tables in
[ARCHITECTURE.md](ARCHITECTURE.md) no longer match the code.

## 4. CI jobs

| Job | What it runs |
|---|---|
| `backend-sqlite` | Python 3.13, dev + CPU PyTorch + ML stack; full suite on SQLite |
| `backend-postgres` | PostgreSQL 17 service; full suite without the ML stack |
| `frontend` | Node 24: `npm ci`, typecheck, ESLint, tests, build |
| `docker` | Builds both images, `nginx -t`, validates the Compose file and profiles, refuses a config without secrets |
| `security` | Forbidden-file check, documentation checks, gitleaks over the full history, actionlint |

Live tests are always skipped in CI (no keys, no network to providers).

## 5. Mocked, simulated and live

| Area | Normal tests | Demo | Live |
|---|---|---|---|
| Threat-intel providers | Mocked HTTP (`respx`), including fixtures built from real response shapes (`tests/fixtures/intel/live_shapes/`) | SIMULATED data, labelled | One run on 2026-11-22, approved indicators only: [intel/LIVE_VERIFICATION.md](intel/LIVE_VERIFICATION.md) |
| DNS (SPF/DKIM/DMARC), RDAP, ip-api | Stubbed | Disabled (`APP_ENV=demo`) | Not verified live |
| Ollama / Mistral | Mocked (`respx`) | Real host Ollama | Real model in the demo; opt-in live test |
| ML models | Skipped when the models are absent; parity checks when present | Real models mounted | — |
| Geolocation | Stored data in tests | SIMULATED points, labelled | One real IPinfo point (8.8.8.8) in the live run |
| Alert e-mail | Local fake SMTP sink | Disabled | Not verified against a real server |
| PostgreSQL | Real PostgreSQL 17 (`make test-pg`, CI) | Real | — |

**Live-verification summary.** VirusTotal (IP, hash, domain shape), AbuseIPDB, Shodan, IPinfo and the Tor list
were called for real once, with 16 requests and the approved indicators only. Three response-shape defects were
fixed. Provider error, rate-limit and quota paths remain mocked-only.

## 6. Smoke test and exploratory sweep (P5z)

`scripts/smoke.py` runs against the running Compose demo through Nginx. It creates temporary viewer, analyst
and admin accounts with the backend CLI (password passed in the process environment, never on a command line;
no credential files are read), runs 36 checks, and disables the accounts at the end. It exits non-zero on any
failure. The checks cover:

- health and readiness; anonymous 401; role permissions;
- BEC upload (rules 100 `phishing_fraud_likely`, ML impersonated 0.4355) and a legitimate upload;
- combined risk, ATT&CK, campaign C-0001, correlation, SIMULATED geo, alert de-duplication on re-upload;
- PDF and HTML downloads, viewer masking, the report disclaimers;
- audit chain verification, retention dry run;
- security headers, CSP, `no-store`, no external resources;
- the models-absent path (status `unavailable`).

**Exploratory browser sweep** (viewer, analyst, admin; every analysis tab and every page) on the from-scratch
demo:

Fixed in P5z:
- The Analyse page said "the raw file is retained", which is false under the default `hash_only` policy.
  It now says only the SHA-256 and size are kept and what leaves the host.
- The Search verdict filter offered `low_risk` and `clean`, which the rule engine never produces, and lacked
  `minimal`. Regression test in `Correlation.test.tsx`.

The P5z report listed six low-severity issues as open. P5z.1 handled them as follows:

- **Fixed:** the Overview requested `GET /analyses/{id}/assessment` for each recent row. Rows without an
  assessment returned 404, which the browser logged as console errors. The list now carries
  `has_assessment`, and known-unassessed rows are not requested.
- **Fixed:** health, `/system/info` and `/ml/status` were requested several times on page load. One shared
  status poller now serves the status bar and the Overview.
- **Fixed:** an unauthorised page route (for example `#audit` as analyst) showed History with the URL
  unchanged. It now shows a 403 notice and rewrites the URL to `#history`.
- **Fixed:** a new-campaign alert showed its raise-time campaign size as if current. It is now labelled
  "when raised", with the current size beside it.
- **Not a defect (P5z finding withdrawn):** "after Resolve, the alert history did not show the resolve step".
  The P5z check truncated the captured page text at 1,200 characters, which cut off the last history line. A
  P5z.1 re-check confirmed the resolve step appears immediately, in the UI and in the API response.
- **Fixed:** SQLAlchemy `SAWarning` identity-map conflicts were logged from `correlation/engine.py` when
  campaign members were rewritten. The warning count in `test_correlation.py` went from 18 to 0.

No CSP violations or other console errors were seen.

## 7. Performance sanity (documented, not optimised)

Apple M4, 16 GB, Docker Desktop, demo stack (PostgreSQL), measured through Nginx:

| Operation | Time |
|---|---|
| Upload BEC sample (rules, offline enrichment, upload-time ML) | median 0.14 s (max 0.56 s) |
| Upload legitimate sample | median 0.09 s |
| `POST /ml/classify` | median 0.10 s |
| `POST /ml/explain` (ML + SHAP) | median 0.20 s |
| `POST /llm/forensic-summary` (ML + SHAP + Mistral via host Ollama) | 85.0 s and 87.1 s |
| Stored-analysis summary (Mistral only; ML/SHAP unavailable under `hash_only`) | 45.9 s and 56.0 s |
| `GET /analyses?limit=50` / `/analytics/summary?days=30` / `/campaigns` / `/alerts` (demo data) | 5 / 25 / 3 / 3 ms |

Throwaway SQLite database with **1,500 analyses** (rules only, offline, ML at upload off; in-process
TestClient):

| Operation | Time |
|---|---|
| Ingest 1,500 uploads | 89 s (median 57 ms, p95 100 ms per upload) |
| `GET /analyses?limit=50` | 6 ms |
| `GET /analytics/summary?days=30` / `?days=365` | 434 / 415 ms |
| `GET /search?q=invoice` | 8 ms |
| `POST /correlation/rebuild` | 3.9 s |

Docker: backend image 2.26 GB (ML stack), web image 85.2 MB. A from-scratch, no-cache build took 191 s (backend)
and 20 s (web). A fresh demo start with existing images took 95–99 s, including the BEC AI assessment.
