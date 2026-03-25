#!/usr/bin/env sh
set -e

if [ $# -ne 1 ]; then
  echo "usage: $0 <client|server|ips>" >&2
  exit 1
fi

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT_DIR=$(CDPATH= cd -- "${SCRIPT_DIR}/.." && pwd)
SERVICE="$1"

cd "${ROOT_DIR}"
if [ -f .env.docker ]; then
  set -a
  . ./.env.docker
  set +a
fi
exec docker compose exec "${SERVICE}" sh
