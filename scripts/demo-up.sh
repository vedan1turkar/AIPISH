#!/usr/bin/env bash
# AIPISH one-command demo (P5i).
#
#   scripts/demo-up.sh            build + start a DEMO stack on a fresh, separate database and seed it
#   scripts/demo-reset.sh         stop the demo and delete its database volume
#
# What it does:
#   1. creates deploy/.env from deploy/env.example if missing, and fills POSTGRES_PASSWORD /
#      AIPISH_JWT_SECRET with random values when empty (never printed; file mode 0600);
#   2. starts the stack as Compose project "aipish-demo" (its own volumes, network and APP_ENV=demo:
#      production hardening, synthetic seeding allowed, no live DNS/intel lookups);
#   3. waits until every service is healthy, then runs `init-demo`: demo users with random passwords,
#      the SYNTHETIC campaign and the synthetic BEC sample (with the AI assessment when models are mounted
#      and host Ollama is running);
#   4. copies the credentials to .demo/credentials (gitignored, 0600) and prints ONLY that path and the URL.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
ENV_FILE="deploy/.env"
COMPOSE_FILE="deploy/docker-compose.yml"
PROJECT="${AIPISH_DEMO_PROJECT:-aipish-demo}"
PORT="${AIPISH_DEMO_PORT:-8080}"
CREDS_DIR=".demo"
CREDS="$CREDS_DIR/credentials"

command -v docker >/dev/null || { echo "docker is required" >&2; exit 1; }
docker info >/dev/null 2>&1 || { echo "Docker is not running: start Docker Desktop / the docker daemon first" >&2; exit 1; }
docker compose version >/dev/null 2>&1 || { echo "Docker Compose v2 is required" >&2; exit 1; }

umask 077
if [ ! -f "$ENV_FILE" ]; then
  cp deploy/env.example "$ENV_FILE"
  echo "created $ENV_FILE from deploy/env.example"
fi
chmod 600 "$ENV_FILE"

gen() { python3 -c 'import secrets,sys; print(secrets.token_urlsafe(int(sys.argv[1])))' "$1" 2>/dev/null \
        || openssl rand -base64 "$1" | tr -d '\n=+/' ; }
ensure_secret() {   # ensure_secret NAME LENGTH: set NAME in $ENV_FILE if it is empty or missing
  local name="$1" len="$2" current
  current="$(grep -E "^${name}=" "$ENV_FILE" | tail -1 | cut -d= -f2- || true)"
  if [ -z "$current" ]; then
    local value; value="$(gen "$len")"
    if grep -qE "^${name}=" "$ENV_FILE"; then
      local tmp; tmp="$(mktemp)"
      awk -v n="$name" -v v="$value" 'BEGIN{FS=OFS="="} $1==n{$0=n"="v} {print}' "$ENV_FILE" > "$tmp" && mv "$tmp" "$ENV_FILE"
    else
      printf '%s=%s\n' "$name" "$value" >> "$ENV_FILE"
    fi
    chmod 600 "$ENV_FILE"
    echo "generated $name in $ENV_FILE"
  fi
}
ensure_secret POSTGRES_PASSWORD 32
ensure_secret AIPISH_JWT_SECRET 48

# The demo runs as its own Compose project with its own network so it can coexist with a deployment.
export APP_ENV=demo
export AIPISH_HTTP_PORT="$PORT"
export AIPISH_NET_SUBNET="${AIPISH_DEMO_SUBNET:-172.30.90.0/24}"
export AIPISH_PROXY_IP="${AIPISH_DEMO_PROXY_IP:-172.30.90.10}"
export AIPISH_SEED_DEMO=0          # seeded explicitly below, after the stack is healthy

compose() { docker compose -p "$PROJECT" -f "$COMPOSE_FILE" --env-file "$ENV_FILE" "$@"; }

started=$(date +%s)
echo "building and starting the demo stack (first run builds the images; this can take a few minutes)..."
compose up -d --build --wait --wait-timeout 300
echo "stack healthy after $(( $(date +%s) - started ))s; seeding synthetic demo data..."
compose exec -T backend python -m app.cli init-demo

mkdir -p "$CREDS_DIR"
chmod 700 "$CREDS_DIR"
compose exec -T backend cat /app/var/demo/credentials > "$CREDS"
chmod 600 "$CREDS"

echo
echo "AIPISH demo is running: http://localhost:${PORT}"
echo "demo credentials (username, role, password): $ROOT/$CREDS"
echo "stop:   docker compose -p $PROJECT -f $COMPOSE_FILE --env-file $ENV_FILE down"
echo "reset:  scripts/demo-reset.sh"
