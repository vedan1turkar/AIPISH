#!/bin/sh
# AIPISH backend container entrypoint (P5i).
#   serve (default)  migrate the schema (idempotent), optionally seed the demo, then run the API
#   migrate          migrate only
#   cli <args...>    run a management command, e.g. `cli rebuild-correlation`
set -eu

case "${1:-serve}" in
  serve)
    python -m app.cli migrate
    if [ "${AIPISH_SEED_DEMO:-0}" = "1" ]; then
      # init-demo itself refuses APP_ENV=production; seeding only ever runs when explicitly requested
      python -m app.cli init-demo
    fi
    # One worker: login throttling state is in-memory per process (see docs/deployment).
    # --no-proxy-headers: the app reads X-Forwarded-For itself, only from AIPISH_TRUSTED_PROXIES.
    exec uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 1 \
      --no-proxy-headers --no-server-header --timeout-keep-alive 75 \
      --log-level "$(echo "${APP_LOG_LEVEL:-info}" | tr 'A-Z' 'a-z')"
    ;;
  migrate)
    exec python -m app.cli migrate
    ;;
  cli)
    shift
    exec python -m app.cli "$@"
    ;;
  *)
    exec "$@"
    ;;
esac
