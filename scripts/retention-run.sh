#!/usr/bin/env bash
# AIPISH retention run (P5e). There is no built-in scheduler: run this from cron (or use the compose
# "retention" profile). DRY RUN by default; pass --apply to redact/delete eligible analyses.
#   scripts/retention-run.sh            # dry run: counts and ids only, nothing changes
#   scripts/retention-run.sh --apply    # apply the RETENTION_* policy (legal holds are skipped)
# Example crontab (daily 03:15, Compose deployment):
#   15 3 * * * cd /opt/aipish && scripts/retention-run.sh --apply >> /var/log/aipish-retention.log 2>&1
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
ARGS=()
[ "${1:-}" = "--apply" ] && ARGS+=(--apply)
if [ -f deploy/.env ] && docker compose -f deploy/docker-compose.yml --env-file deploy/.env ps --status running backend >/dev/null 2>&1 \
   && [ -n "$(docker compose -f deploy/docker-compose.yml --env-file deploy/.env ps -q backend 2>/dev/null)" ]; then
  exec docker compose -f deploy/docker-compose.yml --env-file deploy/.env exec -T backend python -m app.cli retention-run ${ARGS[@]+"${ARGS[@]}"}
fi
cd backend
exec .venv/bin/python -m app.cli retention-run ${ARGS[@]+"${ARGS[@]}"}
