#!/usr/bin/env sh
set -e

BOT_IP="${BOT_IP:-172.31.0.60}"
BOT_PORT="${BOT_PORT:-8080}"
BOT_MODE="${BOT_MODE:-url}"
BOT_PAYLOAD="${BOT_PAYLOAD:-sqli}"
BOT_URI_SIZE="${BOT_URI_SIZE:-8192}"
BOT_BODY_SIZE="${BOT_BODY_SIZE:-1048576}"
BOT_HEADER_SIZE="${BOT_HEADER_SIZE:-4096}"
BOT_PREFIX="${BOT_PREFIX:-}"
BOT_SUFFIX="${BOT_SUFFIX:-}"
BOT_SEED="${BOT_SEED:-10}"
BOT_VERBOSE="${BOT_VERBOSE:-1}"
BOT_COUNT="${BOT_COUNT:-20}"

set -- \
  /app/bot \
  "${BOT_IP}" \
  "${BOT_PORT}" \
  -mode "${BOT_MODE}" \
  -payload "${BOT_PAYLOAD}" \
  -uri-size "${BOT_URI_SIZE}" \
  -body-size "${BOT_BODY_SIZE}" \
  -header-size "${BOT_HEADER_SIZE}" \
  -count "${BOT_COUNT}" \
  -seed "${BOT_SEED}"

if [ -n "${BOT_PREFIX}" ]; then
  set -- "$@" -prefix "${BOT_PREFIX}"
fi

if [ -n "${BOT_SUFFIX}" ]; then
  set -- "$@" -suffix "${BOT_SUFFIX}"
fi

if [ "${BOT_VERBOSE}" = "1" ]; then
  set -- "$@" -verbose
fi

exec "$@"
