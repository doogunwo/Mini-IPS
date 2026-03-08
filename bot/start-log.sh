#!/usr/bin/env sh
set -e

mkdir -p /logs
LOG_FILE="${LOG_FILE:-/logs/bot.log}"

exec /app/start.sh >>"${LOG_FILE}" 2>&1
