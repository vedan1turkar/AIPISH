# AIPISH deployment (P5i)

AIPISH ships as three containers orchestrated by Docker Compose: PostgreSQL, the FastAPI backend and an
nginx web container that serves the React SPA and reverse-proxies the API. The local LLM (Ollama +
Mistral) stays on the host. CI runs on GitHub Actions.

**Not included** (out of scope for P5i): Redis/Celery background workers, OpenSearch, Neo4j, OAuth/SSO,
maps, a retention/audit UI, TLS certificates, image publishing to a registry, and any cloud LLM.

## Architecture

```
            browser
               │  http://127.0.0.1:8080  (loopback by default; TLS terminator in front for real use)
               ▼
 ┌──────────────────────────────┐
 │ web  (nginx-unprivileged)    │  /            → SPA (index.html fallback), self-hosted fonts
 │ 172.30.89.10:8080, uid 101   │  /api/        → backend:8000   (read timeout 300 s, body 11m)
 │ read-only rootfs             │  /docs, /openapi.json, /redoc → 404
 └──────────────┬───────────────┘  security headers, gzip, no version disclosure
                │ X-Forwarded-For = real peer (overwritten, never appended)
                ▼
 ┌──────────────────────────────┐        ┌─────────────────────────────┐
 │ backend (FastAPI, uvicorn)   │ ─────▶ │ postgres 17 (named volume)  │
 │ uid 10001, read-only rootfs  │  SQL   │ no published port           │
 │ /models (read-only mount)    │        └─────────────────────────────┘
 │ /app/var (demo credentials)  │
 └──────────────┬───────────────┘
                │ http://host.docker.internal:11434 (optional)
                ▼
          Ollama on the host (Mistral)
```

- **Images:**
  - `aipish-backend`: python 3.13.18-slim (trixie), multi-stage build, pinned via `backend/constraints.txt`.
  - `aipish-web`: Node 24.22.3 build stage, then `nginxinc/nginx-unprivileged:1.29.8-alpine`.
- **Image contents:** the images contain no secrets, models, datasets or databases. Both `.dockerignore`
  files are allow-lists or exclude `.env*`, `*.sqlite*`, PDFs, credentials, `approval.json` and
  `ctf-operator/`.
- **Image sizes (arm64, measured):**

  | Image | Size | Notes |
  |---|---|---|
  | backend, `WITH_ML=1` | 2.26 GB | CPU-only PyTorch 2.15.0+cpu, transformers, XGBoost, SHAP, scikit-learn. CUDA wheels would add about 2 GB, so the CPU index is used. |
  | backend, `AIPISH_WITH_ML=0` | 354 MB | Rules only; ML reports "unavailable". |
  | web | 83 MB | — |

- **Volumes:**
  - `pgdata`: the database.
  - `backend-var`: demo credentials only.
  - `../models`: mounted read-only at `/models`.
  - Uploads and evidence live in the database, so no upload directory is needed. The training dataset
    (`data/`) is not needed at runtime and is not mounted.
- **Health:**
  - `GET /api/v1/health`: liveness. Anonymous; used by the UI status bar.
  - `GET /api/v1/health/ready`: readiness. Anonymous; returns only `{"status":"ok"}` (200) or
    `{"status":"unavailable"}` (503), with no versions, hosts or errors.
  - Container health checks: the backend uses `/health/ready`; nginx uses its own `/healthz`.

## Quick start: one-command demo (synthetic data)

Requirements: Docker Desktop (or Docker Engine + Compose v2), about 5 GB of free disk for images, and
optionally the trained models in `models/aipish-email-v1/` and Ollama with `mistral` on the host.

```bash
git clone https://github.com/vedan1turkar/AIPISH.git && cd AIPISH
cp deploy/env.example deploy/.env      # optional: demo-up.sh does this and fills the secrets
scripts/demo-up.sh
```

Open **http://localhost:8080** and sign in with an account from `.demo/credentials` (one line per account:
username, role, password; mode 0600, gitignored). The script prints only the file path.

`scripts/demo-up.sh`:
1. Generates `POSTGRES_PASSWORD`, `AIPISH_JWT_SECRET` and `AIPISH_AUDIT_KEY` in `deploy/.env` if they are empty, without
   printing them.
2. Starts the stack as Compose project `aipish-demo` with `APP_ENV=demo`. This is production hardening
   plus permitted synthetic seeding, with no live DNS or threat-intel lookups.
3. Waits for every health check, then runs `python -m app.cli init-demo` inside the backend, which:
   - creates `demo-admin`, `demo-analyst` and `demo-viewer` with random passwords;
   - seeds the SYNTHETIC campaign through the real pipeline;
   - analyses the synthetic BEC sample, with the ML, SHAP and Mistral assessment when models are mounted
     and Ollama is running.
4. Copies the credentials to `.demo/credentials`.

Measured on an Apple M4 with images already built: healthy 26 s after `up`, and 156 s end to end
including the Mistral summary. A first build of the backend image takes about 2.5 minutes.

| Action | Command |
|---|---|
| Stop | `docker compose -p aipish-demo -f deploy/docker-compose.yml --env-file deploy/.env down` |
| Reset (deletes the demo database and credentials) | `scripts/demo-reset.sh` (add `--up` to start fresh) |
| Make targets | `make demo-up`, `make demo-reset` |

Seeding runs only when explicitly requested: `init-demo`, or `AIPISH_SEED_DEMO=1` at container start. It
is refused when `APP_ENV=production`.

## Production deployment

```bash
cp deploy/env.example deploy/.env && chmod 600 deploy/.env
# set POSTGRES_PASSWORD (≥16 random chars), AIPISH_JWT_SECRET (≥32) and AIPISH_AUDIT_KEY (≥32; keep it)
docker compose -f deploy/docker-compose.yml up -d --build --wait
docker compose -f deploy/docker-compose.yml exec backend python -m app.cli create-user --username admin --role admin
#   (interactive password prompt; or set AIPISH_NEW_USER_PASSWORD in that command's environment)
```

`APP_ENV=production` (the default in the image and the compose file) **fails closed**. The containers
refuse to start with a clear message, without printing values, when:
- `POSTGRES_PASSWORD`, `AIPISH_JWT_SECRET` or `AIPISH_AUDIT_KEY` is missing. Compose itself stops before starting anything.
- the JWT secret or the audit key is weak or a placeholder (P5e).
- the database is not PostgreSQL, or its password is shorter than 16 characters or a placeholder.
- demo seeding is requested.

In production mode:
- `/docs`, `/redoc` and `/openapi.json` are disabled in the backend and blocked by nginx.
- CORS allows no origins unless `APP_ALLOWED_ORIGINS` is set, because the SPA is same-origin.
- Live DNS and enrichment behave as in development. Threat-intel lookups still need per-analysis consent.

Verified with a real production-mode stack on a fresh volume:
- healthy in 18 s;
- `/docs` and `/openapi.json` return 404 and anonymous API calls 401;
- a preflight from a foreign origin gets no `Access-Control-Allow-Origin`;
- nothing was seeded.

Each misconfiguration above was also started for real and refused.

The backend runs **one uvicorn worker** because login throttling state is in memory and per process (see
`docs/auth/README.md`). Scale vertically, or move the throttle to a shared store first.

### Client IP and proxy trust

The backend reads `X-Forwarded-For` **only** when the TCP peer is listed in `AIPISH_TRUSTED_PROXIES`
(Compose sets it to the web container's fixed address, `AIPISH_PROXY_IP`). It then takes the rightmost
address that is not itself a trusted proxy. nginx, as the edge, **replaces** any client-supplied
`X-Forwarded-For` with the real peer address.

As a result, a client cannot choose its login-throttling identity. Tested in unit tests and through the
real proxy: 22 failed logins, each with a different spoofed `X-Forwarded-For`, were throttled as one
client (429 after 20).

If you put another reverse proxy or TLS terminator in front of nginx:
- enable nginx's `real_ip` module for that proxy's address;
- keep nginx overwriting `X-Forwarded-For`;
- never add arbitrary networks to `AIPISH_TRUSTED_PROXIES`.

### TLS

Plain HTTP on loopback is the default. For real use, terminate TLS in front of the web container, or in it:
1. Mount a certificate and key read-only, for example
   `./deploy/tls/fullchain.pem:/etc/nginx/tls/fullchain.pem:ro` and the same for `privkey.pem`.
   **Never commit certificates or keys:** `*.pem` and `*.key` are rejected by the CI forbidden-file check.
2. Add a server block that listens on 8443 with `ssl`, `ssl_certificate`, `ssl_certificate_key`,
   `ssl_protocols TLSv1.2 TLSv1.3` and an HSTS header, and publish `443:8443`.
3. Redirect port 8080 to HTTPS.

### Ollama (local Mistral)

Ollama is not containerised. The backend reaches it at `OLLAMA_BASE_URL`
(`http://host.docker.internal:11434`); `extra_hosts: host-gateway` makes that name work on Linux too.
- **Docker Desktop:** forwards to the host's loopback, so a default Ollama install works. This was
  verified: the BEC assessment completed with `mistral:latest`.
- **Linux:** Ollama must listen on an address the Docker bridge can reach (`OLLAMA_HOST=0.0.0.0` with a
  firewall, or the bridge IP).
- **Ollama down:** the AI assessment reports the LLM as unavailable; the rule verdict, ML and SHAP are
  unaffected.

### CSP and the P5g map/analytics

P5g needed **no CSP change**:
- the Leaflet map (vector outline, no tiles) and Plotly charts use neither `eval` nor external resources;
- inline style attributes were already allowed (`style-src 'self' 'unsafe-inline'`).

Verified through nginx: zero CSP violations and zero external requests on the Geo tab, the campaign
geo panel and Analytics.

Anonymous `GET /api/v1/health` now returns only `{"status"}`. Container health checks use
`/api/v1/health/ready` and nginx `/healthz`, so they were unaffected.

## Environment variables (deployment)

`deploy/env.example` lists every variable with placeholders. The main ones:

| Variable | Default | Purpose |
|---|---|---|
| `POSTGRES_PASSWORD` | — (required) | Database password. Production requires ≥16 random characters. |
| `AIPISH_JWT_SECRET` | — (required) | Token signing secret, ≥32 random characters. |
| `APP_ENV` | `production` | `production`, or `demo` (seeding allowed, no live lookups). `dev`/`test` are for local runs. |
| `DATABASE_URL` | set by Compose | `postgresql+psycopg://…`; unset means SQLite at `APP_DB_PATH` (dev). |
| `AIPISH_BIND_ADDRESS` / `AIPISH_HTTP_PORT` | `127.0.0.1` / `8080` | Host address and port of the web container. |
| `AIPISH_NET_SUBNET` / `AIPISH_PROXY_IP` | `172.30.89.0/24` / `.10` | Compose network; the proxy address the backend trusts. |
| `AIPISH_TRUSTED_PROXIES` | set by Compose | Comma-separated IPs or CIDRs allowed to set `X-Forwarded-For`. Empty means none. |
| `APP_ALLOWED_ORIGINS` | empty | Extra CORS origins (production default: none). |
| `APP_UPLOAD_MAX_MB` / `NGINX_CLIENT_MAX_BODY_SIZE` | `10` / `11m` | Upload limit. Oversize requests get a JSON 413 from the API (above 10 MB) or nginx (above 11 MB). |
| `NGINX_API_READ_TIMEOUT` | `300s` | Proxy read/send timeout for `/api` (local LLM summaries). |
| `AIPISH_MODELS_DIR` | `../models` | Host directory mounted read-only at `/models`. |
| `AIPISH_WITH_ML` | `1` | Build the backend with the CPU ML stack (`0` = rules only). |
| `OLLAMA_BASE_URL` / `OLLAMA_ALLOWED_HOSTS` / `OLLAMA_MODEL` | host.docker.internal / same / `mistral` | Local LLM. |
| `AIPISH_SEED_DEMO` | `0` | `1` runs `init-demo` at start (refused in production). |
| `AIPISH_AUDIT_KEY` | — (required) | HMAC key of the tamper-evident audit chain (P5e), ≥32 random characters. Keep it with your backups: without it the existing chain cannot be verified. `demo-up.sh` generates it. |
| `RETENTION_ANALYSIS_DAYS` / `RETENTION_EVIDENCE_DAYS` | `0` / `0` | Retention periods (0 = disabled). Nothing is purged unless a run is applied. |
| `RETENTION_MODE` / `RETENTION_GRACE_DAYS` | `redact` / `0` | `redact` or `delete`; extra days before eligibility. Audit events are never purged. |
| `RETENTION_INTERVAL_SECONDS` | `86400` | Loop interval of the optional `retention` profile service. |
| `ALERTS_ENABLED` and `ALERT_*` | see `env.example` | P5f risk-based alerts (explicitly enabled in the template). Raised when an analysis is processed; no real-time mailbox monitoring. Rules: docs/alerts/README.md. |
| `ALERT_EMAIL_ENABLED`, `ALERT_SMTP_HOST/PORT/SECURITY/USERNAME/PASSWORD`, `ALERT_EMAIL_FROM/TO`, `APP_BASE_URL` | e-mail off | Optional alert e-mail. TLS verification always on; secrets only in `deploy/.env`, never logged or returned. `scripts/demo-up.sh` forces e-mail off for the demo. |
| `AIPISH_ML_AT_UPLOAD` / `AIPISH_ML_UPLOAD_TIMEOUT_SECONDS` | `1` / `20` | P5h upload-time ML classification (cheap ensemble only) and its time bound. Without mounted models it is stored as `unavailable`. |
| `CASE_EVIDENCE_STORE` etc. | see `.env.example` | Evidence policy, auth throttling, intel keys: as in development. |

### Retention scheduling (P5e)

There is **no built-in scheduler**. Retention runs only when something calls it:

- `scripts/retention-run.sh` (dry run by default; `--apply` to purge; contains a cron example), or
  `make retention-dry-run`;
- the optional Compose profile `retention`, a loop container running `python -m app.cli retention-run --apply`
  every `RETENTION_INTERVAL_SECONDS`: `docker compose -f deploy/docker-compose.yml --profile retention up -d`.
  With the retention periods at 0 it does nothing;
- by hand from the admin Retention page (preview, then type `APPLY` to confirm).

Audit verification from the host: `docker compose -f deploy/docker-compose.yml exec backend python -m app.cli audit-verify`
(exit 1 when the chain is broken). Details: [docs/audit/README.md](../audit/README.md).

## Database: PostgreSQL, migrations, backup

- **Driver:** psycopg 3 (`psycopg[binary]==3.3.9`). SQLite stays the default for development and tests.
- **Time zone:** the connection is pinned to UTC, and timestamps are `timestamp with time zone`. The API
  returns `…+00:00` on PostgreSQL. SQLite still returns naive UTC strings, unchanged from before P5i.
- **Search:** case-insensitive on both dialects. `ILIKE` on PostgreSQL; on SQLite, `lower() LIKE lower()`,
  which behaves as before.

### Migrations

`app/core/migrations.py` holds a versioned, idempotent runner with a `schema_migrations` table and ordered
steps. Alembic was not used: there are only three additive steps and no new dependency is needed.

The runner is called by:
- app start-up;
- every CLI command;
- `python -m app.cli migrate`, which the container entrypoint runs before the API starts.

On PostgreSQL a `pg_advisory_lock` serialises concurrent starts. Current steps:

| Version | Name |
|---|---|
| 1 | `baseline_tables` |
| 2 | `audit_event_actor_user_id` |
| 3 | `analysis_search_indexes` |

Verified on a real container: the first boot applied all three steps, and a restart reported
`applied now: none (already up to date)`.

To add a migration:
1. Append `(next_version, "name", fn(engine))` to `STEPS`.
2. Make `fn` idempotent: inspect first, and use SQL valid on both dialects (`ALTER TABLE … ADD COLUMN`,
   `CREATE INDEX IF NOT EXISTS`).
3. Never edit or reorder existing steps.
4. Add a test that runs `upgrade` twice.
5. Back up before any destructive change.

### Upgrade procedure

1. Back up the database.
2. `git pull`
3. `docker compose -f deploy/docker-compose.yml up -d --build --wait`. Migrations run automatically; check
   the output of `docker compose … logs backend | grep "schema version"`.

### Backup and restore

```bash
# backup (custom format; never commit dumps)
docker compose -f deploy/docker-compose.yml exec -T postgres sh -c 'pg_dump -U "$POSTGRES_USER" -Fc "$POSTGRES_DB"' > aipish-$(date +%F).dump
# restore into an empty database
docker compose -f deploy/docker-compose.yml exec -T postgres sh -c 'pg_restore -U "$POSTGRES_USER" -d "$POSTGRES_DB" --clean --if-exists' < aipish-YYYY-MM-DD.dump
```

### SQLite → PostgreSQL

There is **no data-migration tool**: P5i does not copy an existing SQLite database into PostgreSQL. On a
fresh PostgreSQL database:

1. Start the stack; migrations create the schema.
2. Recreate users with `python -m app.cli create-user`.
3. Re-upload the `.eml` files you need. With the default `hash_only` evidence policy the raw bytes were
   never kept, so stored analyses cannot be re-derived from the old database.
4. Run `python -m app.cli rebuild-correlation` and `python -m app.cli backfill-attack`. Both are idempotent.

For a demo, `init-demo` does all of this with synthetic data.

## Tests

| Suite | Command |
|---|---|
| Backend, SQLite (default) | `cd backend && .venv/bin/python -m pytest` uses a fresh temporary SQLite file per run, so it never touches the dev database. |
| Backend, PostgreSQL | Start `docker compose -f deploy/docker-compose.yml --profile test up -d postgres-test` (loopback port 55432, tmpfs, passwordless), then `cd backend && TEST_DATABASE_URL=postgresql://aipish_test@127.0.0.1:55432/aipish_test .venv/bin/python -m pytest --allow-hosts=127.0.0.1`, or run `make test-pg`. |
| Frontend | `cd frontend && npm test` |

The PostgreSQL run drops and re-creates the named database, then drops it again at the end. Database names
that do not look like test databases (for example `aipish`) are refused.

## CI (`.github/workflows/ci.yml`)

The workflow runs on pushes to `main` and on pull requests. Actions are pinned to commit SHAs,
permissions are `contents: read`, superseded runs are cancelled, and no secrets or provider calls are
needed.

| Job | Steps |
|---|---|
| `backend-sqlite` | Python 3.13 with pip cache and the CPU ML stack; full suite. |
| `backend-postgres` | PostgreSQL 17 service; full suite against a dedicated `aipish_test` database, without the ML stack (ML tests skip with a reason). |
| `frontend` | `npm ci`, typecheck, ESLint, vitest, production build. |
| `docker` | Build both images (not pushed, GHA cache); `nginx -t` inside the web image; `docker compose config` with placeholders, plus a check that compose refuses empty secrets. |
| `security` | Forbidden-file check (`scripts/ci/check-forbidden-files.sh`); gitleaks over the full history (reviewed false positives pinned by fingerprint in `.gitleaksignore`); actionlint. |

**Verified remotely:** run [44894449094](https://github.com/vedan1turkar/AIPISH/actions/runs/44894449094) on
commit `0931334` passed every job on the first attempt:

| Job | Result |
|---|---|
| `backend-sqlite` | 601 passed / 6 skipped |
| `backend-postgres` | 566 passed / 8 skipped (no ML stack) |
| `frontend` | 154 tests |
| `docker` | amd64 images built, `nginx -t` OK, compose validated |
| `security` | gitleaks clean, forbidden files OK, actionlint OK |

The same counts were reproduced beforehand from a clean clone with fresh virtualenvs (601 / 6 with the ML
stack, 566 / 8 without).

No test needs the local-only models or dataset:
- Tests that use models build tiny temporary bundles.
- The 6 skips are opt-in live-provider and integration tests (`AIPISH_RUN_LIVE=1` /
  `AIPISH_RUN_INTEGRATION=1`).
- Without the ML stack (the PostgreSQL job), the ML, SHAP and explain test modules also skip through
  `pytest.importorskip`.
