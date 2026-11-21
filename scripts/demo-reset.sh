#!/usr/bin/env bash
# AIPISH demo reset (P5i): stop the demo stack and delete ITS volumes (database, demo credentials).
# Only the "aipish-demo" Compose project is touched; a deployment under another project is unaffected.
#   scripts/demo-reset.sh            stop + delete demo data
#   scripts/demo-reset.sh --up       ... then start a fresh demo (scripts/demo-up.sh)
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
PROJECT="${AIPISH_DEMO_PROJECT:-aipish-demo}"
ENV_FILE="deploy/.env"
[ -f "$ENV_FILE" ] || ENV_FILE="deploy/env.example"

# Interpolation needs values even for `down`; these dummies are never used to start anything.
POSTGRES_PASSWORD="${POSTGRES_PASSWORD:-unused}" AIPISH_JWT_SECRET="${AIPISH_JWT_SECRET:-unused}" \
  AIPISH_AUDIT_KEY="${AIPISH_AUDIT_KEY:-unused}" \
  docker compose -p "$PROJECT" -f deploy/docker-compose.yml --env-file "$ENV_FILE" down -v --remove-orphans
rm -f .demo/credentials
echo "demo stack stopped and its volumes removed"
if [ "${1:-}" = "--up" ]; then
  exec scripts/demo-up.sh
fi
