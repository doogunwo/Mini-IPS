#!/usr/bin/env sh
set -e

CLIENT_MODE="${CLIENT_MODE:-normal}"
TARGET_HOST="${TARGET_HOST:-10.10.0.20}"
TARGET_PORT="${TARGET_PORT:-50080}"
CLIENT_CPU="${CLIENT_CPU:-0}"
CLIENT_VERBOSE="${CLIENT_VERBOSE:-1}"
CLIENT_HOST_HEADER="${CLIENT_HOST_HEADER:-server}"
CLIENT_PATH="${CLIENT_PATH:-/}"
CLIENT_READ_RESPONSE="${CLIENT_READ_RESPONSE:-1}"
CLIENT_INTERVAL_SEC="${CLIENT_INTERVAL_SEC:-0.5}"

BOT_MODE="${BOT_MODE:-url}"
BOT_PAYLOAD="${BOT_PAYLOAD:-sqli}"
BOT_URI_SIZE="${BOT_URI_SIZE:-8192}"
BOT_BODY_SIZE="${BOT_BODY_SIZE:-1048576}"
BOT_HEADER_SIZE="${BOT_HEADER_SIZE:-4096}"
BOT_PREFIX="${BOT_PREFIX:-}"
BOT_SUFFIX="${BOT_SUFFIX:-}"
BOT_SEED="${BOT_SEED:-10}"
BOT_COUNT="${BOT_COUNT:-20}"
BOT_INTERVAL_MS="${BOT_INTERVAL_MS:-1000}"

case "${CLIENT_MODE}" in
  normal)
    set -- \
      python3 /app/normal_client.py \
      "${TARGET_HOST}" \
      "${TARGET_PORT}" \
      --host-header "${CLIENT_HOST_HEADER}" \
      --path "${CLIENT_PATH}" \
      --timeout 3 \
      --interval "${CLIENT_INTERVAL_SEC}"

    if [ "${CLIENT_READ_RESPONSE}" = "1" ]; then
      set -- "$@" --read-response
    fi

    if [ "${CLIENT_VERBOSE}" = "1" ]; then
      set -- "$@" --verbose
    fi
    ;;
  bot)
    set -- \
      /app/bot \
      "${TARGET_HOST}" \
      "${TARGET_PORT}" \
      -mode "${BOT_MODE}" \
      -payload "${BOT_PAYLOAD}" \
      -uri-size "${BOT_URI_SIZE}" \
      -body-size "${BOT_BODY_SIZE}" \
      -header-size "${BOT_HEADER_SIZE}" \
      -count "${BOT_COUNT}" \
      -interval-ms "${BOT_INTERVAL_MS}" \
      -seed "${BOT_SEED}"

    if [ -n "${BOT_PREFIX}" ]; then
      set -- "$@" -prefix "${BOT_PREFIX}"
    fi

    if [ -n "${BOT_SUFFIX}" ]; then
      set -- "$@" -suffix "${BOT_SUFFIX}"
    fi

    if [ "${CLIENT_VERBOSE}" = "1" ]; then
      set -- "$@" -verbose
    fi
    ;;
  idle)
    exec sh -c "trap : TERM INT; sleep infinity & wait"
    ;;
  *)
    echo "unsupported CLIENT_MODE: ${CLIENT_MODE}" >&2
    exit 1
    ;;
esac

exec taskset -c "${CLIENT_CPU}" "$@"
