#!/usr/bin/env bash
# Fail if local-only or sensitive files are tracked by git (P5i). Runs in CI and locally.
#   .env files (except the documented templates), SQLite/DB files, trained models, raw/processed datasets,
#   PDFs, credential files, approval.json and ctf-operator/.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

pattern='(^|/)\.env($|\.)|\.sqlite3?$|\.db$|(^|/)models/|^data/(raw|processed)/|\.pdf$|(^|/)\.dev_credentials$|(^|/)\.demo_credentials$|^\.demo/|(^|/)approval\.json$|(^|/)ctf-operator/|\.(pem|key|p12|pfx)$|\.safetensors$|\.joblib$'
allowed='^(\.env\.example|deploy/env\.example)$'

bad="$(git ls-files | grep -E "$pattern" | grep -vE "$allowed" || true)"
if [ -n "$bad" ]; then
  echo "Forbidden files are tracked by git:" >&2
  echo "$bad" >&2
  exit 1
fi
echo "forbidden-file check: OK ($(git ls-files | wc -l | tr -d ' ') tracked files)"
