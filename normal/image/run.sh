#!/usr/bin/env sh
set -e

SERVER_IP="${SERVER_IP:-172.31.0.60}"
SERVER_PORT="${SERVER_PORT:-8080}"
CLIENT_VERBOSE="${CLIENT_VERBOSE:-1}"

ARGS=""
if [ "${CLIENT_VERBOSE}" = "1" ]; then
  ARGS="--verbose"
fi

exec python3 /app/normal_client.py "${SERVER_IP}" "${SERVER_PORT}" ${ARGS}
