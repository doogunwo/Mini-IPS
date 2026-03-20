#!/usr/bin/env sh
set -e

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_DIR=$(CDPATH= cd -- "${SCRIPT_DIR}/.." && pwd)

if [ -n "${MONITOR_LOG_FILE:-}" ]; then
  MONITOR_LOG_PATH="${MONITOR_LOG_FILE}"
elif [ -f "${REPO_DIR}/logs/monitor.log" ]; then
  MONITOR_LOG_PATH="${REPO_DIR}/logs/monitor.log"
elif [ -f "/logs/monitor.log" ]; then
  MONITOR_LOG_PATH="/logs/monitor.log"
else
  MONITOR_LOG_PATH="${REPO_DIR}/logs/monitor.log"
fi

exec python3 "${SCRIPT_DIR}/monitor.py" \
  --log-file "${MONITOR_LOG_PATH}" \
  --host 0.0.0.0 \
  --port 8091
