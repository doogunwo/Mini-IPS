#!/usr/bin/env sh
set -e

mkdir -p /logs
LOG_FILE="${LOG_FILE:-/logs/server.log}"

exec /app/start.sh >>"${LOG_FILE}" 2>&1
