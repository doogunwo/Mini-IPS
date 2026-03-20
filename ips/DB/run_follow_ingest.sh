#!/usr/bin/env sh
set -e

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_DIR=$(CDPATH= cd -- "${SCRIPT_DIR}/.." && pwd)

if [ -n "${LOG_FILE:-}" ]; then
  FOLLOW_LOG_FILE="${LOG_FILE}"
elif [ -f "${REPO_DIR}/logs/ips.log" ]; then
  FOLLOW_LOG_FILE="${REPO_DIR}/logs/ips.log"
elif [ -f "/logs/ips.log" ]; then
  FOLLOW_LOG_FILE="/logs/ips.log"
else
  FOLLOW_LOG_FILE="${REPO_DIR}/logs/ips.log"
fi

exec python3 "${SCRIPT_DIR}/follow_ingest.py" \
  --log-file "${FOLLOW_LOG_FILE}" \
  --db-file "${SCRIPT_DIR}/ips_events.db"
