# Upgrading an existing development SQLite database

This is a procedure for bringing an **existing local dev database** (`backend/db/app.sqlite`, or whatever
`APP_DB_PATH` points to) up to the current schema and derived data. It was written for this release and has
**not** been run against the maintainer's dev database.

> **Recommended for evaluation: use the Docker demo instead** (`scripts/demo-up.sh`, see the
> [README](../README.md)). It starts from an empty PostgreSQL database with synthetic data only. The dev
> database usually holds hundreds of re-uploads of the same fixtures from earlier phases, which inflate
> campaign member counts, alerts and analytics (see [correlation/README.md](correlation/README.md) "Dev
> database inflation").

## What changes

`python -m app.cli migrate` applies the versioned steps in `backend/app/core/migrations.py` that are not yet
recorded in `schema_migrations` (the full list is generated in [ARCHITECTURE.md](ARCHITECTURE.md)). Steps
are additive and idempotent. The ones that matter for an old dev DB:

| Step | Effect on existing data |
|---|---|
| 5 `audit_and_retention_columns` | Adds chain and retention columns. |
| 6 `audit_chain_genesis` | Chains existing audit events once, in `(created_at, id)` order, without rewriting their content, and records a `chain_genesis` event. Needs `AIPISH_AUDIT_KEY`. |
| 7 `audit_append_only_triggers` | Creates triggers that reject `UPDATE` and `DELETE` on `audit_event`. |
| 8, 9 | New tables for upload-time ML, combined risk and alerts. Existing analyses get no rows until a backfill. |
| 10 `analysis_parser_crosscheck` | New nullable column; existing analyses keep `NULL` (no cross-check). |

The app also runs the migrations on start-up and before every CLI command, so **starting the new backend
against the old file upgrades it**. Take the backup first.

## Procedure

Run from `backend/` with the project virtualenv active.

1. **Stop the backend** (and the Vite dev server), so nothing writes to the file.

2. **Back up the database** (and keep the `.env` that holds `AIPISH_AUDIT_KEY`):

   ```bash
   cp db/app.sqlite db/app.sqlite.bak-$(date +%Y%m%d-%H%M%S)
   ```

   The audit key matters: without the same key the chain cannot be verified later. In `dev` and `offline`
   a missing key is generated into the gitignored `.env`; never change it afterwards.

3. **Migrate** (idempotent; prints the schema version):

   ```bash
   python -m app.cli migrate
   ```

4. **Backfill ATT&CK mappings** for analyses stored before P5d (idempotent):

   ```bash
   python -m app.cli backfill-attack
   ```

5. **Backfill combined risk** (idempotent; adds a version only when the result changes). By default it raises
   **no alerts**, to avoid an alert storm over old uploads; add `--alerts` only if you want them:

   ```bash
   python -m app.cli backfill-risk
   ```

   The backfill does not run ML. It uses the most recent stored ML result for each analysis (a saved AI
   assessment or an upload-time classification). Old analyses with neither are scored with the ML component
   missing, and the Risk tab says so.

6. **Rebuild correlation** (backfills observations and recomputes all candidate campaigns):

   ```bash
   python -m app.cli rebuild-correlation
   ```

7. **Verify the audit chain** (read-only):

   ```bash
   python -m app.cli audit-verify
   ```

   Expected: `chain: OK`. Events written before step 6 prove order and integrity only from the migration
   onwards.

8. **Optional: record a checkpoint** and keep its output outside the system:

   ```bash
   python -m app.cli audit-checkpoint
   ```

## Rolling back

Stop the backend and restore the backup file over `db/app.sqlite`. Migrations have no down-steps.

## Moving to PostgreSQL

There is no SQLite → PostgreSQL data copy tool. The documented path is to start a fresh PostgreSQL deployment
and re-seed or re-upload ([deployment/README.md](deployment/README.md)).
