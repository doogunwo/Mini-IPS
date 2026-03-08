#!/usr/bin/env sh
set -e

BOT_IP="${BOT_IP:-172.31.0.60}"
BOT_PORT="${BOT_PORT:-8080}"
BOT_ATTACK="${BOT_ATTACK:-SQLI}"
BOT_SEED="${BOT_SEED:-10}"
BOT_VERBOSE="${BOT_VERBOSE:-1}"

ARGS="-attack ${BOT_ATTACK} -seed ${BOT_SEED}"
if [ "${BOT_VERBOSE}" = "1" ]; then
  ARGS="${ARGS} -verbose"
fi

exec /app/bot "${BOT_IP}" "${BOT_PORT}" ${ARGS}
