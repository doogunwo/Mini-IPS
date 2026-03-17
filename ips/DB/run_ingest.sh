#!/usr/bin/env sh
set -e

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_DIR=$(CDPATH= cd -- "${SCRIPT_DIR}/.." && pwd)

if [ -n "${LOG_FILE:-}" ]; then
  INGEST_LOG_FILE="${LOG_FILE}"
elif [ -f "/logs/ips.log" ]; then
  INGEST_LOG_FILE="/logs/ips.log"
else
  INGEST_LOG_FILE="${REPO_DIR}/logs/ips.log"
fi

exec python3 "${SCRIPT_DIR}/ingest_logs.py" \
  --log-file "${INGEST_LOG_FILE}" \
  --db-file "${SCRIPT_DIR}/ips_events.db"
