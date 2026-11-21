# Audit log, custody, retention and personal-data masking (P5e)

**The guarantee, exactly as shown in the UI, API and CLI:**

> Tamper-evident (HMAC hash chain), not tamper-proof: an attacker with both database write access and
> the audit key could forge a chain; external checkpoints reduce that risk.

For stored evidence:

> SHA-256 detects change to the stored file; it does not make storage tamper-proof.

AIPISH does not provide immutable or WORM storage. The audit log is append-only at the application
and trigger level, and it can be checked for changes. It cannot stop changes.

## 1. Hash chain

### Columns on `audit_event`

| Column | Meaning |
|---|---|
| `seq` | Gap-free sequence number (unique index `ux_audit_event_seq`) |
| `prev_hash` | `event_hash` of `seq - 1`; 64 zeros for the first event |
| `event_hash` | `HMAC-SHA256(AIPISH_AUDIT_KEY, canonical(event) + "\|" + prev_hash)`, hex |
| `target_type`, `target_id` | What the action was about (analysis, case, user, file, retention, audit…) |
| `outcome` | `success` or `failure` |
| `source_ip` | Client IP, resolved through the trusted-proxy rules in `docs/auth/README.md` |

### Canonical form

The canonical form is compact JSON with sorted keys. It covers these fields:

- `seq`, `id`, `event_type`;
- `created_at` (UTC, microseconds, `Z`);
- `actor_user_id`, `analysis_id`, `case_id`;
- `target_type`, `target_id`, `outcome`, `source_ip`;
- `detail`.

The code is in `backend/app/audit/chain.py`.

### Serialised appends

Every append runs `UPDATE audit_chain_head SET seq = seq + 1 … RETURNING seq, last_hash`.

- On PostgreSQL this is a row lock.
- On SQLite it is the database write lock.

Concurrent writers therefore cannot fork the chain. The event and the head update commit together with
the action they record.

### What verification checks

`verify()` checks, in order:

1. `seq` is continuous from 1.
2. Every `prev_hash` matches the previous `event_hash`.
3. Every HMAC recomputes.
4. The head row matches the last event, which detects deleting the tail.
5. No unchained rows exist.

It reports the **first broken seq** and a reason, for example:

| Tampering | Reason reported |
|---|---|
| Row modified | `event_hash mismatch: the event content was changed` |
| Row deleted | `seq N is missing (deleted or never written)` |
| Tail deleted | `chain head mismatch: events after the last verified one are missing` |
| Rows reordered or re-linked | `prev_hash does not link to the previous event…` |

### Append-only triggers

Triggers reject `UPDATE` and `DELETE` on `audit_event`:

- **PostgreSQL:** function `aipish_audit_append_only`, trigger `audit_event_no_update_delete`, and a
  `TRUNCATE` trigger.
- **SQLite:** `audit_event_no_update` and `audit_event_no_delete`.

The migration creates the triggers, and every upgrade re-creates them.

**A database superuser or table owner can bypass them**, for example with
`ALTER TABLE … DISABLE TRIGGER` or by editing the SQLite file. That is exactly the case the hash chain
detects.

### Legacy events (migration step 6, `audit_chain_genesis`)

Events that existed before P5e are chained once, in `(created_at, id)` order.

- Only their chain columns are set. Their content is never rewritten.
- A `chain_genesis` event records how many legacy events there were.
- Those events prove order and integrity only from the migration onwards.

### Checkpoints

`POST /audit/checkpoint` and `python -m app.cli audit-checkpoint` record the current tip (`seq`,
`event_hash`) as an `audit_checkpoint` event and return it.

Copy the tip somewhere outside this system, such as a ticket, a signed e-mail or a notebook. A later
verification can then be compared against that external copy. This is the only defence against an
attacker who holds both database write access and the key and re-forges the whole chain.

## 2. Audit key (`AIPISH_AUDIT_KEY`)

| Environment | Behaviour |
|---|---|
| `production` (and any other non-dev environment) | **Fails closed.** Start-up, the production pre-flight and `docker compose` refuse a missing or weak key: shorter than 32 characters, containing "change", "placeholder" or "example", or fewer than 10 distinct characters. |
| `dev`, `offline` | If the key is missing, a random key is generated into the gitignored `.env` (mode 0600) and is never printed. |
| `test` | A random per-process key. |
| Docker demo | `scripts/demo-up.sh` generates it into `deploy/.env` along with the other secrets. |

**Keep the key.** Without it, the existing chain cannot be verified. Changing it makes every existing
event fail verification.

There is no key rotation or key id. To rotate the key, create a checkpoint, archive an export and the
old key offline, and start a new deployment.

## 3. What is recorded

Every event has an actor, a target, an outcome, a source IP and a timestamp. Details never contain
bodies, subjects, recipients, passwords, tokens or keys:

- `app/audit/sanitize.py` replaces such keys with `[omitted]`;
- e-mail addresses in details are masked to `x***@domain`.

| Area | Events |
|---|---|
| Authentication | `login_success`, `login_failed`, `login_lockout`, `login_throttled`, `logout`, `password_changed`, `password_change_failed` |
| User administration | `user_created`, `user_role_changed`, `user_disabled`, `user_enabled`, `user_password_reset` |
| Analyses | `analysis_uploaded` (sha256, size), `analysis_viewed` (at most once per user per analysis per **15 minutes**; records whether the view was masked) |
| Cases | `analysis_created` (case), `case_analysis_added`, `case_analysis_removed` |
| Evidence | `integrity_verified`, `report_generated` (records masked or redacted) |
| Analysis runs | `threat_intel_lookup`, `assessment_run`, `ml_run` (sha256 and size only), `attack_recomputed`, `attack_backfilled`, `correlation_rebuilt` |
| Search | `search_performed` (query **truncated to 64 characters** and filters) |
| Audit | `audit_verified`, `audit_checkpoint`, `audit_exported` |
| Retention | `retention_run`, `retention_purge`, `legal_hold_set`, `legal_hold_cleared`, `analysis_erased`, `analysis_erasure_refused` |

How `audit_verified` is recorded:

- A **failed** verification is always recorded.
- A successful one is recorded at most once per admin every 5 minutes, because the Audit page verifies on
  every load. The response says `"recorded": false` when it skips one.

## 4. Endpoints

| Method | Path | Permission | Notes |
|---|---|---|---|
| GET | `/api/v1/audit/events` | `audit:read` (admin) | Filters: `actor`, `action`, `target_type`, `target_id`, `outcome`, `date_from`, `date_to`. Paginated; newest first. Each event includes `seq` and a hash prefix. |
| GET | `/api/v1/audit/export?format=csv\|json` | `audit:read` | Uses the same filters. Capped at 10,000 rows (`capped` flag). The export itself is audited. |
| GET | `/api/v1/audit/verify` | `audit:read` | Returns `ok`, `checked`, `last_seq`, `last_hash`, `first_broken_seq`, `reason` and `guarantee`. |
| GET / POST | `/api/v1/audit/checkpoint` | `audit:read` / `audit:manage` | Latest checkpoint / create a checkpoint. |
| GET | `/api/v1/analyses/{id}/custody` | `custody:read` (analyst, admin) | Custody timeline, SHA-256, size, stored or not stored, retention state, hold, integrity note. |
| GET | `/api/v1/admin/retention/status` | `retention:manage` (admin) | Policy, last run, counts. |
| POST | `/api/v1/admin/retention/run` | `retention:manage` | Body `{"dry_run": true}` is the default. Send `false` to apply. |
| GET / POST | `/api/v1/admin/holds` | `retention:manage` | List holds / set a hold `{target_type: analysis\|case, target_id, reason}`. |
| POST | `/api/v1/admin/holds/{id}/clear` | `retention:manage` | Body `{reason}`. |
| DELETE | `/api/v1/admin/analyses/{id}` | `retention:manage` | Erasure. Body `{reason}` is required. Returns 409 `LEGAL_HOLD` when the analysis is held. |

### CLI

```bash
python -m app.cli audit-verify        # exit 0 = OK, 1 = BROKEN (prints first broken seq and reason)
python -m app.cli audit-checkpoint    # prints the tip to copy outside the system
python -m app.cli retention-run       # dry run (default)
python -m app.cli retention-run --apply
```

## 5. Retention

Retention is **disabled by default.** Nothing is purged unless a period is set *and* a run is applied.

| Variable | Default | Meaning |
|---|---|---|
| `RETENTION_ANALYSIS_DAYS` | `0` (off) | Analyses older than this are redacted or deleted. |
| `RETENTION_EVIDENCE_DAYS` | `0` (off) | Stored raw `.eml` bytes older than this are purged. The hash is kept. |
| `RETENTION_MODE` | `redact` | `redact` or `delete`. |
| `RETENTION_GRACE_DAYS` | `0` | Extra days added before anything becomes eligible. |

### Modes

**`redact`** removes personal content and keeps the investigative record.

- Removed:
  - body, subject;
  - sender, recipient, Reply-To and Return-Path addresses, and display names;
  - raw bytes and attachment file names;
  - AI summaries that quote content;
  - display-name correlation entities.
- Kept:
  - hashes, IOCs, verdicts and scores, findings;
  - correlation observations, ATT&CK mappings, intel results and geo data.
- Remaining e-mail addresses inside detection, forensics and auth JSON are masked.

Cases and campaigns stay valid. The analysis is marked `redacted` and shows a "content redacted per
retention policy" note in the UI and the PDF.

**`delete`** removes the analysis and every row that references it. It finds those rows generically: every
mapped table with an `analysis_id` column except `audit_event`. It then cleans orphan correlation
entities and recomputes campaigns.

### Rules that always apply

- **Audit events are never purged.** They reference ids only, so erasure leaves the custody trail intact.
- **Legal holds** on an analysis, or on a case that contains it, exempt the analysis from retention and
  from erasure. Setting or clearing a hold requires a reason and is audited.
- Each analysis is processed in its own transaction, and every purge writes a `retention_purge` event
  with ids and counts only.

### Scheduling: there is no built-in scheduler

Pick one of these:

- cron or a systemd timer calling `scripts/retention-run.sh --apply` (the script contains a cron
  example; it does a dry run without `--apply`);
- the Compose `retention` profile, a small loop container that runs `retention-run --apply` every
  `RETENTION_INTERVAL_SECONDS` (default 86400):
  `docker compose --profile retention up -d`.

You can also apply a run by hand from the admin Retention page. It previews first, and applying needs
`APPLY` typed into a confirmation dialog.

## 6. Personal-data masking

The permission **`pii:view`** is held by analyst and admin, not by viewer.

For a user without it, one serializer (`app/privacy/masking.py`, applied by middleware to every JSON
response under `/api/v1`) masks:

| Field | Viewer sees |
|---|---|
| E-mail addresses (From, To, Cc, Reply-To, Return-Path, in findings and evidence text) | `d***@domain.example` |
| Display names (`display_name`, `from_display_name`, display-name entities and "(display name: …)" phrases) | `restricted` |
| Body text | removed, with `body_restricted: true` |
| Masked objects | flagged `pii_masked: true` |

What still shows:

- Domains, IPs, URLs, hashes, verdicts and findings stay visible. Viewers need them to read an
  analysis, and they are not personal data in this model.
- Subjects are not masked. This is a documented limitation: they can contain personal data.

The **PDF** for a viewer is built from masked inputs and labelled **"MASKED VIEW"** under the title. The
`report_generated` event records `masked: true`.

The UI shows masked and redacted states, with banners on the analysis page, tags in History and Case,
and "restricted" labels.

## 7. Limitations

- The log is tamper-evident, not tamper-proof (see above). There is no external timestamping
  authority or WORM storage. Checkpoints are manual.
- Triggers can be bypassed by a superuser or table owner, and the hash chain then detects the change.
- Masking is presentation-level and role-based. Data is stored in clear: there is no at-rest
  encryption and no per-case access control.
- `analysis_viewed` is de-duplicated per 15 minutes, so the log shows that a user viewed an analysis,
  not every page load.
- There is no key rotation or key id for `AIPISH_AUDIT_KEY`.
- Retention needs an external scheduler (cron or the Compose profile).
- The custody timeline shows at most the first 1,000 events per analysis. Holds are listed up to 500.
