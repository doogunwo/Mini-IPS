#!/usr/bin/env sh
set -e

IFACE="${IFACE:-eth0}"
BPF="${BPF:-tcp and host 172.31.0.60 and port 8080}"
MODE="${MODE:-sniffing}"
LOG_FILE="${LOG_FILE:-/logs/ips.log}"
MONITOR_LOG_FILE="${MONITOR_LOG_FILE:-/logs/monitor.log}"
DB_FILE="${DB_FILE:-/app/DB/ips_events.db}"
WEB_HOST="${WEB_HOST:-0.0.0.0}"
WEB_PORT="${WEB_PORT:-8090}"
ENGINE="${1:-pcre}"
MAIN_CPU="${MAIN_CPU:-0}"
INGEST_CPU="${INGEST_CPU:-1}"
WEB_CPU="${WEB_CPU:-2}"
PIDS=""

export IFACE
export BPF
export MODE
export LOG_FILE
export MONITOR_LOG_FILE
export DB_FILE
export WEB_HOST
export WEB_PORT
export ENGINE
export MAIN_CPU
export INGEST_CPU
export WEB_CPU

cleanup() {
  for pid in $PIDS; do
    if kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null || true
    fi
  done
  wait
}

trap cleanup INT TERM EXIT

mkdir -p /logs /app/DB

taskset -c "${MAIN_CPU}" /app/build/main -mode="${MODE}" -iface="${IFACE}" -bpf="${BPF}" -engine="${ENGINE}" >>"${LOG_FILE}" 2>&1 &
PIDS="$PIDS $!"

taskset -c "${INGEST_CPU}" python3 /app/DB/follow_ingest.py \
  --log-file "${LOG_FILE}" \
  --db-file "${DB_FILE}" &
PIDS="$PIDS $!"

taskset -c "${WEB_CPU}" python3 /app/DB/web.py \
  --db-file "${DB_FILE}" \
  --host "${WEB_HOST}" \
  --port "${WEB_PORT}" &
PIDS="$PIDS $!"

wait
