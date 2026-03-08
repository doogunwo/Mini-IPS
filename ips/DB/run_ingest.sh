#!/usr/bin/env sh
set -e

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

exec python3 "${SCRIPT_DIR}/ingest_logs.py" \
  --log-file "/logs/ips.log" \
  --db-file "${SCRIPT_DIR}/ips_events.db"
