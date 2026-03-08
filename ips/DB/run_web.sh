#!/usr/bin/env sh
set -e

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

exec python3 "${SCRIPT_DIR}/web.py" \
  --db-file "${SCRIPT_DIR}/ips_events.db" \
  --host 0.0.0.0 \
  --port 8090
