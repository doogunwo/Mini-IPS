#!/usr/bin/env sh
set -e

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT_DIR=$(CDPATH= cd -- "${SCRIPT_DIR}/.." && pwd)

cd "${ROOT_DIR}"
if [ -f .env.docker ]; then
  set -a
  . ./.env.docker
  set +a
fi
docker compose up --build -d server
