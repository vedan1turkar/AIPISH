# AIPISH — Email Forensics Platform: Project Work Report

> **Historical document (2026-10-11), kept for the record; superseded.** It describes the project before
> the ML, threat-intelligence, authentication, PostgreSQL, audit and alerting phases. Several statements
> are now outdated, for example "AbuseIPDB/MaxMind adapters stubbed" (AbuseIPDB is implemented and was
> live-verified for approved indicators; MaxMind is not configured) and the SQLite-only backend.
> For the current state see [docs/PROJECT_SUMMARY.md](docs/PROJECT_SUMMARY.md),
> [docs/LIMITATIONS.md](docs/LIMITATIONS.md) and [docs/REQUIREMENTS_SUMMARY.md](docs/REQUIREMENTS_SUMMARY.md).

**Report date:** 2026-10-11
**Repo:** `~/Documents/AIPISH` (backend/ + frontend/)
**Status:** Demo-ready. All core flows verified green on the live stack.

---

## 1. What the project is

An email threat-detection platform: upload a raw `.eml` file, the backend parses
it, runs header forensics, independently re-verifies SPF/DKIM/DMARC, runs
external DNS/RDAP/IP-geo enrichment, applies 18 weighted detection rules, and
produces an explainable risk score. Analysts explore results in a responsive
dashboard, view an interactive forensic trace graph, store the message in an
investigation case, re-verify evidence integrity, and download a ReportLab
forensic PDF.

---

## 2. Backend (`backend/` — Python, FastAPI, SQLAlchemy, SQLite)

### 2.1 Ingestion & parsing (`app/ingestion/parser.py`)
- stdlib-only `.eml` parser over `email` + hash of exact bytes (SHA-256 + size recorded).
- Never raises on malformed input — defects recorded (`parse_defects`).
- Handles multipart/alternative, base64/QP, address parsing, header counts.
- URL extraction from text + HTML parts with dedupe, in_text/in_html flags,
  zero-width-character obfuscation counting.
- Attachments: **hashed, never stored or returned**; filenames sanitized
  (`../`-traversal stripped); decode errors become defects, no crash.

### 2.2 Header forensics (`app/forensics/`)
- Relay-chain reconstruction from Received headers with per-hop confidence
  scores + reasons, trusted-boundary indexing, TLS flags.
- IP classification (public/private/reserved); **private-range IPs are never
  treated as public origin claims** (privacy/correctness).
- Measured, byte-provable inconsistencies (Return-Path vs From, Message-ID
  domain mismatch, timestamp order, etc.).

### 2.3 Authentication (`app/auth/`)
- Parses header **claims** from Authentication-Results; then **independently
  re-verifies** SPF/DKIM/DMARC via live DNS when enabled.
- Per-protocol statuses verified_pass/verified_fail/… kept strictly separate
  from claims; conflict detection ("header claimed pass, locally verified fail").

### 2.4 Enrichment (`app/enrichment/`)
- Providers: DNS (A/MX/TXT), RDAP (registration freshness), keyless IP-geo
  HTTP; AbuseIPDB/MaxMind adapters wired but stubbed → explicit `skipped`
  with reason when keys absent.
- Every result carries provider, status, latency_ms, evidence, provenance.
- SSRF-safe: only whitelist-validated normalized IPs/domains are looked up;
  private/loopback IPs never geolocated; strict httpx timeouts; 24h cache;
  bounded IOC/lookup budgets; rate-limit handling.

### 2.5 Detection engine (`app/detection/`)
- 18 rules across URL structure (IP-literal, shortener, punycode, risky TLD,
  embedded creds, obfuscation), sender (lookalike brand-domain, Reply-To
  mismatch), content (urgency lexicon, credential asks, payment diversion/BEC,
  ALL-CAPS subject), attachment risk types, header inconsistency, auth bridges
  (verified-fail, conflict, DMARC misalignment, provider-corroborated only).
- Scoring: per-rule weight, **contribution ≤ weight**, severity classes;
  every finding carries evidence + analyst-facing rationale; unknowns list
  what couldn't be evaluated (absence of evidence ≠ evidence of fraud).
- Bridged findings require external corroboration — provider unavailability
  never adds points.

### 2.6 Cases, evidence policy, audit (`app/cases/`, `app/core/models.py`)
- `investigation_case` (CASE-YYYY-NNNN), `case_analysis_link`, `audit_event`.
- **Hash-only by default**: raw bytes not stored; opt-in `CASE_EVIDENCE_STORE=raw`
  with optional `CASE_EVIDENCE_STORE_KEY` gating raw access/report download via
  `X-Evidence-Key`; documented `CASE_EVIDENCE_RETENTION_DAYS` (cleanup manual).
- Integrity endpoint recomputes SHA-256 over retained bytes: `match` / `mismatch`
  (+ both hashes) / honest `unavailable` under hash-only policy.
- Audit events: `analysis_created`, `evidence_accessed`, `integrity_verified`,
  `report_generated` — append-only at app layer; **no API mutates audit rows**
  (test-pinned); README states it is NOT tamper-resistant chain of custody.
- Persistence across restarts verified (fresh app instance on same DB).

### 2.7 Forensic PDF (`app/reports/pdf.py`, ReportLab)
- Downloadable report with: report ID + generation time, verdict banner,
  evidence SHA-256/size + integrity re-verification result, escaped metadata,
  findings table (severity/points/**OBSERVED FACT vs HEURISTIC**/evidence/
  rationale), auth claims-vs-verified per protocol, header anomalies, relay
  chain with trusted boundary, candidate/verified IP + enrichment provenance
  incl. degraded providers, missing-data section, limitations block stating
  attribution/geolocation are investigative indicators — not proof of identity
  or physical location; no custody claim.
- All email-derived text `html.escape`d before ReportLab mini-HTML insertion
  (injection-payload tested). `report_generated` audited with byte count.

### 2.8 API (`app/api/`)
- Uniform error envelope `{error:{code,message,request_id?}}` incl. coded
  validation/HTTP errors; catch-all 500 leaks nothing internal (logs server-side).
- Upload validation: extension/content-type whitelist, 10 MB cap → 413,
  empty → 400, wrong type → 415; malformed still → 201 with defects.
- CORS allow-list from config, credentials off, methods GET/POST/OPTIONS.
- Endpoints: health · analyses upload/list/get · cases create-from-analysis/
  list/get · evidence-integrity · forensic report download.

---

## 3. Frontend (`frontend/` — React 18, TypeScript, Vite, Tailwind)

### 3.1 Layout & navigation
- Sticky responsive header with backend status pill (online/degraded/offline).
- Hash routing (`#upload`, `#history`, `#analysis/{id}`) — refresh/back work.

### 3.2 Upload page
- Drag-drop + picker; client-side validation (extension, empty, 10 MB) before
  any request; upload → analyse progress bar; friendly coded errors from the
  backend envelope; retry after dismiss.

### 3.3 Results dashboard (5 tabs + trace)
- **Overview**: score ring + verdict, evidence behind every point, unevaluated
  data (`unavailable` badges), metadata rows, quick facts, create-case card,
  integrity check action, PDF download action.
- **Findings**: per-finding severity, contribution/weight points, evidence,
  rationale, OBSERVED FACT vs HEURISTIC badge, plus neutral observed-facts list.
- **Authentication**: claimed-vs-verified table per protocol with conflict
  highlighting („header claim conflicts with verification") and raw A-R lines.
- **Headers & relay**: relay-hop cards (trusted styling, TLS, confidence
  reasons/notes), boundary, candidate-vs-verified IP, anomalies, header counts.
- **IP & domain intel**: provider results table (status badges, latency,
  evidence, provenance), degraded-provider banner, URL/attachment lists.
- **Trace view** (Cytoscape.js): pure graph model from real record fields only
  (relay hosts, candidate public IPs, sender/URL-host domains, URLs);
  distinct styles for **observed / externally enriched / inferred** nodes with
  legend; click any node/edge → evidence + source card; loading/error/empty/
  single-node states; disclaimers that the relay graph is an infrastructure
  path, not a person's travel or identity; **map** renders only when the
  configured geo provider returned coordinates (otherwise labeled
  unavailable—nothing invented); verified graph differs per analyzed email.

### 3.4 History page
- Analyses grid + investigation cases list; severity/score chips, auth status
  summaries, evidence policy display; click-through reopen (with 404 handling);
  both lists with empty states.

### 3.5 Status language & honesty
- Uniform badges + tooltips for **Verified / Claimed / Inferred / Unavailable /
  Unknown** applied consistently; all panels render API values verbatim with
  explicit "not present / none / not determined" states — no invented data,
  `DemoDataBanner` for labeled sample material.

### 3.6 API client (`src/api/client.ts`)
- Single configurable `API_BASE` (`VITE_API_BASE`), same-origin default via
  Vite proxy; typed models matching FastAPI schemas; both FastAPI error
  envelope and plain `detail` shapes normalized; abortable requests.

---

## 4. Tooling, tests, and verification

### 4.1 Testing
- **101 backend tests** (unit: parser/auth/forensics/enrichment/detection/
  errors/health; integration: upload API, investigations incl. restart
  persistence, corrupted-evidence mismatch, hash-only honesty, PDF
  generation/malformed/404/enrichment-degradation).
- **E2E suite (`e2e_verify.py`)**: 14 scenario groups / 21 checks against the
  live backend — legit, phishing, BEC, spoofing, suspicious URLs, malformed,
  missing auth headers, private IPs, oversized (>10 MB → 413), empty (→400),
  wrong type (→415), persistence + SHA-256 round-trip, case + integrity + PDF,
  health, unknown-route envelope.
- **Demo flow (`demo_verify.py`)**: 26 checks across three synthetic fixtures,
  upload → analysis → trace → case → integrity → PDF → history.

### 4.2 Frontend checks
- `tsc -b` typecheck: 0 errors; production build green.
- **ESLint (typescript-eslint) added from scratch** (none existed): proper TS
  parsing config, 0 problems; no rules selectively disabled to pass.

### 4.3 Defects found & fixed during verification (real fixes, tests re-run)
1. `domain_no_mx_shortlived` bridge fired on bare DNS `not_found` without
   RDAP freshness corroboration (violated the rule's own contract; misfired on
   reserved `example.*` demo domains) → now requires actual RDAP evidence.
   Full suite re-ran green; no test had pinned the shortcut.
2. Integrity audit not recorded on the hash-only path → now fires for
   `unavailable` too.
3. ReportLab color API misuse found during PDF verification → fixed.
4. Frontend: 6 initial build/type errors fixed; trace-view grid class typos
   removed; several harness bugs in verification scripts fixed (no product or
   assertion changes needed).

### 4.4 Security review (no unresolved findings)
- SSRF: no raw fetch of user-supplied URLs/domains; only whitelisted normalized
  IOCs; private IPs excluded from geo; strict timeouts.
- Attachments: hash-only, never executed/stored; traversal-safe filenames.
- Upload validation mirrors backend limits; uniform error envelope; no
  traceback leakage; CORS allow-list without credentials; secrets env-only,
  never serialized or returned.

---

## 5. Demonstration-readiness deliverables
- **README expanded**: macOS quickstart (venv, pip, uvicorn; npm dev), all
  environment variables table, API endpoint table, optional API-keys section
  (explicit `skipped` semantics), test commands, troubleshooting table (9
  symptoms incl. multipart/reportlab/port-in-use/CORS/evidence-key), demo
  fixtures list, known limitations.
- **Environment hygiene**: `.env` confirmed git-ignored (`git check-ignore`);
  `.env.example` placeholders only, zero secrets.
- **Three synthetic fixtures** (`backend/tests/fixtures/demo/`), each with a
  `SYNTHETIC DEMO DATA — NOT A REAL MESSAGE` footer; reserved/documentation
  domains (RFC 2606 example.*, RFC 5737 IPs), invented names, no real PII:
  `legitimate_invoice.eml` (score ~15, benign) · `phishing_account_verify.eml`
  (score 100: lookalike + credential + auth-fail) · `bec_wire_change.eml`
  (score 100: payment_diversion + Reply-To mismatch + urgency).

---

## 6. Actual final test results (exit codes captured)

| Command | Result |
|---|---|
| `pytest tests -q` | **101 passed**, exit 0 |
| `npx tsc -b --noEmit` / `npm run build` | exit 0 / ✓ built |
| `npx eslint 'src/**/*.{ts,tsx}'` | 0 problems, exit 0 |
| `python3 /tmp/e2e_verify.py` | **21 passed, 0 failed**, exit 0 |
| `python3 /tmp/demo_verify.py` | **26 passed, 0 failed**, exit 0 |
| live PDF download | valid `%PDF-`, ~7–11 KB per fixture |

---

## 7. Completed / partial / deferred

**Completed:** parser · forensics · auth verification · detection engine ·
enrichment · cases/audit/evidence policy · PDF reporting · full dashboard ·
trace graph · history · test/lint/build tooling · demo fixtures/docs.

**Partial:** AbuseIPDB/MaxMind adapters (stubbed, `skipped` without keys);
retention cleanup (manual); single-operator access (no RBAC).

**Deferred:** multi-tenant auth; WORM/hash-chained custody; automated retention
daemon; backend ruff/mypy linting; JS bundle code-splitting (646 kB warning).

**Known limitations (documented):** application-level audit is not tamper-proof;
IP geolocation = infrastructure, never a person; heuristic score = investigative
indicator, absence of findings ≠ safe; live geo/map requires an outbound provider.

---

## 8. Manual demo steps
1. `cd backend && python -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt`
2. (Optional) `cp .env.example .env` — defaults work with **no API keys**.
3. `uvicorn app.main:app --port 8000` (terminal 1) · `cd frontend && npm install && npm run dev` (terminal 2)
4. Browse `http://localhost:5173`, upload each `backend/tests/fixtures/demo/*.eml`,
   walk Findings/Auth/Headers/Intel/Trace tabs, then **Download forensic PDF**.
