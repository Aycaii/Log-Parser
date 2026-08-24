#!/usr/bin/env bash
# Runs the whole app locally: creates the DB if needed, then starts the
# Go API and the Next.js client together. Ctrl-C stops both.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

DB_NAME="${DB_NAME:-logparseapp}"

if ! command -v go >/dev/null 2>&1; then
  echo "error: go is not installed (https://go.dev/)" >&2
  exit 1
fi
if ! command -v npm >/dev/null 2>&1; then
  echo "error: npm/node is not installed (https://nodejs.org/)" >&2
  exit 1
fi

if [ -z "${GEMINI_API_KEY:-}" ]; then
  echo "warning: GEMINI_API_KEY is not set — uploads will parse but skip AI anomaly detection" >&2
fi

if command -v createdb >/dev/null 2>&1 && command -v psql >/dev/null 2>&1; then
  if ! psql -lqt 2>/dev/null | cut -d '|' -f 1 | grep -qw "$DB_NAME"; then
    echo "Creating database '$DB_NAME'..."
    createdb "$DB_NAME"
  fi
else
  echo "warning: createdb/psql not found — skipping database creation, make sure '$DB_NAME' exists" >&2
fi

if [ ! -d client/node_modules ]; then
  echo "Installing client dependencies..."
  (cd client && npm install)
fi

set -m # give each background job its own process group so cleanup can kill grandchildren (e.g. the binary `go run` spawns)

pids=()
cleanup() {
  trap - EXIT INT TERM
  for pid in "${pids[@]:-}"; do
    kill -TERM -- "-$pid" 2>/dev/null || kill "$pid" 2>/dev/null || true
  done
  wait 2>/dev/null || true
}
trap cleanup EXIT INT TERM

(cd server && exec go run .) &
pids+=("$!")

(cd client && exec npm run dev) &
pids+=("$!")

# Portable "wait for the first job to exit" (macOS ships bash 3.2, no `wait -n`).
while :; do
  for pid in "${pids[@]}"; do
    if ! kill -0 "$pid" 2>/dev/null; then
      exit 0
    fi
  done
  sleep 1
done
