# Authentication, JWT and role-based access control (P5b)

The backend runs **local username/password authentication** and issues short-lived **HS256 JWT bearer
tokens**. Every API route is checked against a central permission map; anything not in the map is
denied.

> This is **not** OAuth 2.0 / OIDC. There is no external identity provider, no SSO and no refresh token.
> R53 (OAuth 2.0) remains open.

The UI hides actions a role cannot perform. That is a convenience, **not** the control: the backend
enforces every permission itself, and the tests prove this by calling every route directly with each
role.

## Roles

| Role | Can do |
|---|---|
| **viewer** | Read analyses, cases, results, threat-intel results and assessment history; download PDFs; see ML model status; read correlation, campaigns and search (P5c). P5h: reads the combined risk assessment (`risk:read`). P5f: reads alerts (`alert:read`). P5e: sees personal data **masked** (addresses `x***@domain`, display names "restricted", no body; PDF labelled "MASKED VIEW"). |
| **analyst** | Everything a viewer can, plus: upload and analyse emails; run ML / SHAP / Mistral assessments; run threat-intel lookups; create cases and add analyses to them; verify evidence integrity. P5e: `pii:view` (unmasked personal data) and `custody:read` (custody timeline). P5h: `risk:recompute`. P5f: `alert:manage` (acknowledge / resolve / reopen alerts). |
| **admin** | Everything an analyst can, plus: user management (create, list, change role, disable / enable, reset password); view `/intel/status` and `/llm/status`; read the API docs (dev and test only); rebuild correlation (P5c). P5e: `audit:read` / `audit:manage` (audit log, verify, export, checkpoint) and `retention:manage` (retention runs, legal holds, erasure). |

The role → permission map is in `backend/app/security/permissions.py` (`ROLE_PERMISSIONS`).

## Per-route permissions

This table was generated from the running app's route inventory. `test_every_route_is_mapped_in_the_permission_map`
fails if any route is missing from `ROUTE_PERMISSIONS`.

| Method | Path | Permission | Allowed roles |
|---|---|---|---|
| `GET` | `/api/v1/health` | `public` | anonymous (public) |
| `GET` | `/api/v1/health/ready` | `public` | anonymous (public): container readiness probe; returns only `{"status"}` (P5i) |
| `GET` | `/api/v1/system/info` | `analysis:read` | viewer (P5g: version/environment moved off anonymous `/health`) |
| `GET` | `/api/v1/analyses/{analysis_id}/geo` | `analysis:read` | viewer (P5g, stored data only) |
| `GET` | `/api/v1/campaigns/{campaign_id}/geo` | `correlation:read` | viewer (P5g) |
| `GET` | `/api/v1/analytics/summary` | `analysis:read` | viewer (P5g) |
| `POST` | `/api/v1/auth/login` | `public` | anonymous (public) |
| `GET` | `/api/v1/auth/me` | `self` | any signed-in user |
| `POST` | `/api/v1/auth/logout` | `self` | any signed-in user |
| `POST` | `/api/v1/auth/change-password` | `self` | any signed-in user |
| `GET` | `/api/v1/analyses` | `analysis:read` | viewer, analyst, admin |
| `GET` | `/api/v1/analyses/{analysis_id}` | `analysis:read` | viewer, analyst, admin |
| `POST` | `/api/v1/analyses` | `analysis:create` | analyst, admin |
| `GET` | `/api/v1/analyses/{analysis_id}/assessment` | `assessment:read` | viewer, analyst, admin |
| `GET` | `/api/v1/analyses/{analysis_id}/assessments` | `assessment:read` | viewer, analyst, admin |
| `GET` | `/api/v1/analyses/{analysis_id}/assessments/{assessment_id}` | `assessment:read` | viewer, analyst, admin |
| `POST` | `/api/v1/analyses/{analysis_id}/forensic-summary` | `assessment:run` | analyst, admin |
| `POST` | `/api/v1/llm/forensic-summary` | `assessment:run` | analyst, admin |
| `GET` | `/api/v1/llm/status` | `config:status` | admin |
| `GET` | `/api/v1/analyses/{analysis_id}/threat-intel` | `intel:read` | viewer, analyst, admin |
| `POST` | `/api/v1/analyses/{analysis_id}/threat-intel` | `intel:run` | analyst, admin |
| `GET` | `/api/v1/intel/status` | `config:status` | admin |
| `GET` | `/api/v1/investigations` | `case:read` | viewer, analyst, admin |
| `GET` | `/api/v1/investigations/{case_id}` | `case:read` | viewer, analyst, admin |
| `POST` | `/api/v1/investigations/from-analysis/{analysis_id}` | `case:write` | analyst, admin |
| `POST` | `/api/v1/investigations/{case_id}/evidence-integrity/{analysis_id}` | `evidence:verify` | analyst, admin |
| `GET` | `/api/v1/investigations/{case_id}/report/{analysis_id}` | `report:download` | viewer, analyst, admin |
| `GET` | `/api/v1/ml/status` | `ml:status` | viewer, analyst, admin |
| `POST` | `/api/v1/ml/classify` | `ml:run` | analyst, admin |
| `POST` | `/api/v1/ml/explain` | `ml:run` | analyst, admin |
| `GET` | `/api/v1/investigations/{case_id}/analyses` | `case:read` | viewer, analyst, admin |
| `GET` | `/api/v1/investigations/{case_id}/indicators` | `case:read` | viewer, analyst, admin |
| `POST` | `/api/v1/investigations/{case_id}/analyses` | `case:write` | analyst, admin |
| `DELETE` | `/api/v1/investigations/{case_id}/analyses/{analysis_id}` | `case:write` | analyst, admin |
| `GET` | `/api/v1/analyses/{analysis_id}/correlation` | `correlation:read` | viewer, analyst, admin |
| `GET` | `/api/v1/campaigns` | `correlation:read` | viewer, analyst, admin |
| `GET` | `/api/v1/campaigns/{campaign_id}` | `correlation:read` | viewer, analyst, admin |
| `GET` | `/api/v1/graph/entities/{entity_type}/{value}` | `correlation:read` | viewer, analyst, admin |
| `GET` | `/api/v1/search` | `search:read` | viewer, analyst, admin |
| `POST` | `/api/v1/correlation/rebuild` | `correlation:rebuild` | admin |
| `GET` | `/api/v1/analyses/{analysis_id}/attack` | `attack:read` | viewer, analyst, admin |
| `GET` | `/api/v1/analyses/{analysis_id}/attack/history` | `attack:read` | viewer, analyst, admin |
| `POST` | `/api/v1/analyses/{analysis_id}/attack/recompute` | `attack:recompute` | analyst, admin |
| `GET` | `/api/v1/admin/users` | `users:manage` | admin |
| `POST` | `/api/v1/admin/users` | `users:manage` | admin |
| `PATCH` | `/api/v1/admin/users/{user_id}` | `users:manage` | admin |
| `POST` | `/api/v1/admin/users/{user_id}/reset-password` | `users:manage` | admin |
| `GET` | `/api/v1/analyses/{analysis_id}/risk` | `risk:read` | viewer, analyst, admin (P5h; masked per P5e) |
| `GET` | `/api/v1/analyses/{analysis_id}/risk/history` | `risk:read` | viewer, analyst, admin (P5h) |
| `POST` | `/api/v1/analyses/{analysis_id}/risk/recompute` | `risk:recompute` | analyst, admin (P5h; audited) |
| `GET` | `/api/v1/analyses/{analysis_id}/report.html` | `report:download` | viewer, analyst, admin (P5k-lite; masked like the PDF; audited) |
| `GET` | `/api/v1/alerts` | `alert:read` | viewer, analyst, admin (P5f) |
| `GET` | `/api/v1/alerts/summary` | `alert:read` | viewer, analyst, admin (P5f) |
| `GET` | `/api/v1/alerts/{alert_id}` | `alert:read` | viewer, analyst, admin (P5f) |
| `POST` | `/api/v1/alerts/{alert_id}/acknowledge` | `alert:manage` | analyst, admin (P5f; audited) |
| `POST` | `/api/v1/alerts/{alert_id}/resolve` | `alert:manage` | analyst, admin (P5f; note required; audited) |
| `POST` | `/api/v1/alerts/{alert_id}/reopen` | `alert:manage` | analyst, admin (P5f; audited) |
| `GET` | `/api/v1/admin/alerts/config` | `config:status` | admin (P5f; secrets never returned) |
| `GET` | `/api/v1/audit/events` | `audit:read` | admin (P5e) |
| `GET` | `/api/v1/audit/export` | `audit:read` | admin (P5e; capped, audited) |
| `GET` | `/api/v1/audit/verify` | `audit:read` | admin (P5e) |
| `GET` | `/api/v1/audit/checkpoint` | `audit:read` | admin (P5e) |
| `POST` | `/api/v1/audit/checkpoint` | `audit:manage` | admin (P5e) |
| `GET` | `/api/v1/analyses/{analysis_id}/custody` | `custody:read` | analyst, admin (P5e) |
| `GET` | `/api/v1/admin/retention/status` | `retention:manage` | admin (P5e) |
| `POST` | `/api/v1/admin/retention/run` | `retention:manage` | admin (P5e; dry run unless `dry_run: false`) |
| `GET` | `/api/v1/admin/holds` | `retention:manage` | admin (P5e) |
| `POST` | `/api/v1/admin/holds` | `retention:manage` | admin (P5e) |
| `POST` | `/api/v1/admin/holds/{hold_id}/clear` | `retention:manage` | admin (P5e) |
| `DELETE` | `/api/v1/admin/analyses/{analysis_id}` | `retention:manage` | admin (P5e; reason required, 409 on legal hold) |
| `GET` | `/openapi.json` | `docs:read` | admin (`APP_ENV` dev / test only; 404 otherwise) |
| `GET` | `/docs` | `docs:read` | admin (dev / test only) |
| `GET` | `/redoc` | `docs:read` | admin (dev / test only) |

### How enforcement works

- `enforce_access` (`backend/app/security/deps.py`) is an **application-level FastAPI dependency**, so it
  runs for every route, including routes added later. It is not opt-in per router.
- It maps the matched endpoint to its `(method, path)` entry in `ROUTE_PERMISSIONS`.
- A missing entry is denied:
  - anonymous callers get **401**;
  - signed-in callers get **403 `ROUTE_NOT_PERMITTED`**, even admins.
- Responses:
  - missing, invalid or expired token: **401** with `WWW-Authenticate: Bearer` (and `error="invalid_token"` for bad tokens);
  - insufficient role: **403 `FORBIDDEN`**;
  - account still on a temporary password: **403 `PASSWORD_CHANGE_REQUIRED`** on everything except the `self` routes.
- FastAPI's default `/docs`, `/redoc` and `/openapi.json` are switched off. They are re-registered as
  admin-only routes, and only when `APP_ENV` is `dev` or `test`.

**Adding an endpoint:** add a line to `ROUTE_PERMISSIONS`. Until you do, the endpoint is unreachable and
the route-inventory test fails.

## Endpoints

### `POST /api/v1/auth/login`

**JSON body** (chosen over the OAuth2 password form):

```json
{"username": "alice", "password": "…"}
```

- Success, `200`:
  ```json
  {"access_token", "token_type": "bearer", "expires_at", "user": {id, username, role, is_active, must_change_password, …}}
  ```
- An unknown user, a wrong password and a disabled user all return the same response:
  `401 {"error": {"code": "INVALID_CREDENTIALS", "message": "invalid credentials"}}`.
- Unknown usernames still run a dummy scrypt verification, so timing differences are reduced.
- While throttled or locked: `429 TOO_MANY_ATTEMPTS` with `Retry-After`. The password is **not evaluated**
  (a dummy hash still runs), so the response is identical whether the password was right or wrong.

### Other auth endpoints

- **`GET /api/v1/auth/me`:** the current user and their permission list.
- **`POST /api/v1/auth/logout`:**
  - bumps the user's `token_version`, which revokes **all** of that user's tokens on every device and tab;
  - there is no per-session logout, because without refresh tokens or a server-side session table,
    "log out everywhere" is the precise behaviour available.
- **`POST /api/v1/auth/change-password`:**
  - body `{"current_password", "new_password"}`;
  - the current password is required and is throttled like logins;
  - success revokes every old token and returns a new token, so the current tab continues.

### Admin endpoints

- **`GET /api/v1/admin/users`, `POST /api/v1/admin/users`:**
  - `POST` takes `{"username", "role"}` and creates the user with a **random temporary password**;
  - the password is returned once in the response;
  - the user must change it at first sign-in.
- **`PATCH /api/v1/admin/users/{id}`:**
  - takes `{"role"?, "is_active"?}`;
  - any change revokes the user's existing tokens;
  - demoting or disabling the **last active admin** (including yourself) is refused with `409 LAST_ADMIN`.
- **`POST /api/v1/admin/users/{id}/reset-password`:**
  - returns a new temporary password once;
  - revokes existing tokens and clears the lockout;
  - the user must change the password at next sign-in.

## Tokens

| Item | Value |
|---|---|
| Algorithm | HS256 only. `alg=none`, HS512 and any other algorithm are rejected before signature checking. |
| Secret | `AIPISH_JWT_SECRET` (environment, then repo-root `.env`). |
| Claims | `sub` (user id), `role`, `tv` (token_version), `jti`, `iat`, `exp`, `iss=aipish`, `aud=aipish-api`. `exp`, `iat`, `sub`, `jti`, `iss` and `aud` are required. |
| Lifetime | 60 minutes (`AIPISH_JWT_TTL_MINUTES`, clamped to 1–1440). No refresh tokens. |
| Revocation | A token is rejected if the user is deleted or disabled, or if `tv` ≠ the user's current `token_version`. `token_version` is bumped on password change, admin reset, role change, disable and logout. |
| Role source | The role is re-read from the database on every request. The `role` claim is informational. |

**Fail closed:**
- When `APP_ENV` is anything other than `test`, the app **refuses to start** if the secret is:
  - missing;
  - shorter than 32 characters;
  - low-variety;
  - placeholder-like (`change`, `secret`, `example`, `your`, …).
- The error never echoes the value.
- Under `APP_ENV=test` only, a random per-process secret is used. Tokens are still fully signed and
  verified; **there is no auth-bypass flag anywhere in the code**.
- The local dev `.env` holds a randomly generated secret. `.env` is gitignored, and the secret was never
  printed.

## Passwords

- **Hashing:** stdlib `hashlib.scrypt` (N=2¹⁵, r=8, p=1, 32-byte key) with a 16-byte random per-user salt,
  stored as `scrypt$N$r$p$salt$hash`. Verification uses a constant-time compare (`hmac.compare_digest`).
  No new hashing dependency was added. The only new dependency is **PyJWT**.
- **Policy:**
  - 12–128 characters;
  - at least 5 distinct characters;
  - not on a small common-password list (also after stripping trailing digits);
  - not a simple alphabet or keyboard sequence;
  - not based on the username.
- **Never exposed:** password material and hashes never appear in API responses, logs, audit details or
  exception messages. Tests assert this.

## Brute-force protection

- **Limits:**
  - per username: 5 failures in 15 minutes → 15-minute lockout;
  - per source IP: 20 failures in 15 minutes → 15-minute lockout.
  - Configure with `AIPISH_LOGIN_MAX_FAILURES_USER`, `AIPISH_LOGIN_MAX_FAILURES_IP`,
    `AIPISH_LOGIN_WINDOW_SECONDS` and `AIPISH_LOGIN_LOCKOUT_SECONDS`.
- **Unknown usernames** are throttled the same way, so lockout does not reveal whether an account exists.
- **State:**
  - counters are **in memory**, bounded to 10,000 keys per limiter, and **reset on restart**;
  - per-user lockout is also written to `app_user.locked_until`, so that part survives a restart.
- **Source IP** (P5i): the direct peer address, unless that peer is listed in `AIPISH_TRUSTED_PROXIES`
  (comma-separated IPs/CIDRs, empty by default). Only then is `X-Forwarded-For` read, right to left, and the
  first address that is not a trusted proxy is used. In the Compose deployment only the nginx container is
  trusted and nginx overwrites the header with the real peer, so clients cannot spoof their throttling
  identity (`app/security/client_ip.py`; tests in `test_deploy.py`; see docs/deployment/README.md).

## Audit events

Audit events reuse `audit_event`. A new nullable column, **`actor_user_id`**, is set from the
authenticated request automatically for every audit write, including the existing ones:
- `analysis_created` (case creation);
- `threat_intel_lookup`;
- `integrity_verified`;
- `report_generated`.

On existing SQLite databases the column is added in place and idempotently (`migrate_audit_actor`), at
app start and by the CLI.

New event types:

| Event | Detail recorded (never a password or token) |
|---|---|
| `login_success` | user id, username, source IP |
| `login_failed` | username attempted, source IP, internal reason (`unknown_user` / `bad_password` / `disabled`) |
| `login_lockout` | username attempted, source IP, scope (username / ip), lockout seconds |
| `login_throttled` | username attempted, source IP, retry-after |
| `logout` | user id, scope `all_sessions` |
| `password_changed`, `password_change_failed` | user id |
| `user_created` | user id, username, role, source (`admin` / `cli` / `dev_seed`) |
| `user_role_changed` | user id, from, to |
| `user_disabled`, `user_enabled`, `user_password_reset` | user id, username |

- **P5e:** every event now also carries `target_type`, `target_id`, `outcome` and `source_ip`, and is
  appended to an HMAC-SHA256 hash chain. AI assessment runs, ML runs, uploads, views, searches, case
  membership changes, audit and retention actions are audited too, and there is an admin read API and
  UI. Full list, chain design and guarantees: [docs/audit/README.md](../audit/README.md).

## Bootstrap and local dev users

```bash
cd backend
# any environment: password from $AIPISH_NEW_USER_PASSWORD or getpass (twice); never from argv
.venv/bin/python -m app.cli create-user --username alice --role admin [--must-change-password]
# disable an account locally (revokes tokens; refuses the last active admin; audited)
.venv/bin/python -m app.cli disable-user --username alice

# LOCAL DEV ONLY (APP_ENV=dev; refuses otherwise)
.venv/bin/python -m app.cli seed-dev-users
```

`seed-dev-users`:
- (re)creates `demo-admin`, `demo-analyst` and `demo-viewer` with random 20-character passwords;
- writes them to **`backend/.dev_credentials`** (mode `0600`, gitignored);
- prints only the file path.

No default or hard-coded password exists anywhere in the source.

## Frontend

- **Login page:** an anonymous visit to any view shows sign-in.
- **Token storage:**
  - held in memory and mirrored to **`sessionStorage`** (never `localStorage`), so a refresh keeps you
    signed in within that tab;
  - **XSS trade-off:** any script-readable storage, including sessionStorage, could be read by injected
    script. This is mitigated, not eliminated, by:
    - short token lifetime;
    - server-side revocation (`token_version`);
    - React escaping all untrusted text;
    - per-tab scope (cleared when the tab closes).
  - An HttpOnly cookie would avoid this exposure but would need CSRF protection. It was not done in P5b.
- **Central API client** (`authedFetch`): attaches `Authorization: Bearer …` to every call. On any 401 it
  clears the session and returns to the login page with a reason ("session expired", "no longer valid").
  A 403 is shown as an error and does not sign out.
- **PDF download:** an authenticated `fetch` → `Blob` → object URL → download. A bare link could not carry
  the token.
- **Expiry timer:** the session is cleared locally the moment the token expires.
- **Role-aware UI:**
  - viewers get no Analyse page, *New analysis*, case creation, integrity check, threat-intel run or
    assessment generation;
  - analysts get those actions but not *Users*;
  - admins also get *Users*;
  - admin-only status endpoints are not requested for other roles.
- **Header:** current user, role, *Password* (change) and *Sign out*.
- **Admin page:** list, create, change role, disable / enable and reset password. A temporary password is
  shown once, in page state only, and never stored or logged.
- **Temporary passwords:** an account with `must_change_password` sees only the change-password screen
  until the password is changed.

## Other hardening

- **CORS:**
  - only the origins in `APP_ALLOWED_ORIGINS`; `*` is dropped even if configured;
  - `allow_credentials` is off (bearer tokens, no cookies);
  - allowed headers include `Authorization`; `Content-Disposition` and `Retry-After` are exposed.
- **Response headers:**
  - every response: `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`,
    `Content-Security-Policy: frame-ancestors 'none'`, `Referrer-Policy: no-referrer`;
  - every `/api/*` response (JSON and PDF): `Cache-Control: no-store` and `Pragma: no-cache`.
- **Errors:** the error envelope now forwards `WWW-Authenticate` and `Retry-After`. No stack trace, token
  or claim is returned. Authorization headers and tokens are never logged; the request log is uvicorn's
  access log, which does not include headers.

## Threat model notes and known limitations

| # | Limitation | Note |
|---|---|---|
| 1 | Local password auth only | No OAuth2 / OIDC / SSO / MFA (R53 open). |
| 2 | No refresh tokens | Users sign in again after 60 minutes. |
| 3 | Logout revokes all of a user's sessions | There is no per-device logout. |
| 4 | In-memory throttling | Resets on restart (per-user lockout persists). Not shared across multiple workers or processes. The proxy IP is not trusted. |
| 5 | No per-case ownership or ACLs | Every viewer can read every analysis and case. |
| 6 | sessionStorage token | Readable by injected script (XSS trade-off above). |
| 7 | Secret rotation | Changing `AIPISH_JWT_SECRET` invalidates all tokens. There is no key-id rotation. |
| 8 | Audit log | P5e: tamper-evident (HMAC hash chain), not tamper-proof. Append-only triggers can be bypassed by a database superuser; the chain then detects the change. See docs/audit/README.md. |
| 9 | API docs | Admin-only and only in dev/test. A browser cannot send the bearer header to `/docs`, so use an API client with the token or `GET /openapi.json`. |
| 10 | Evidence key | The optional `X-Evidence-Key` raw-evidence gate is unchanged and is in addition to RBAC. |
