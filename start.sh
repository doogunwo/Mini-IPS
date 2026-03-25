#!/usr/bin/env sh
set -e

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "${SCRIPT_DIR}"

if [ -f .env.docker ]; then
  set -a
  . ./.env.docker
  set +a
fi

CLIENT_SUBNET="${CLIENT_SUBNET:-20.0.1.0/24}"
SERVER_SUBNET="${SERVER_SUBNET:-10.0.1.0/24}"

remove_networks_by_subnet() {
  target_subnet="$1"
  [ -n "${target_subnet}" ] || return 0

  docker network ls -q | while read -r net_id; do
    [ -n "${net_id}" ] || continue

    net_name="$(docker network inspect -f '{{.Name}}' "${net_id}" 2>/dev/null || true)"
    case "${net_name}" in
      ""|bridge|host|none)
        continue
        ;;
    esac

    subnet="$(docker network inspect -f '{{range .IPAM.Config}}{{if .Subnet}}{{.Subnet}}{{end}}{{end}}' "${net_id}" 2>/dev/null || true)"
    if [ "${subnet}" = "${target_subnet}" ]; then
      docker network rm "${net_id}" >/dev/null 2>&1 || true
    fi
  done
}

# Always clear existing compose resources and stale networks first.
docker compose --profile manual down --remove-orphans >/dev/null 2>&1 || true
remove_networks_by_subnet "${CLIENT_SUBNET}"
remove_networks_by_subnet "${SERVER_SUBNET}"

# Build all required images explicitly, including manual profile services.
docker compose build server
docker compose --profile manual build router ips client

# Start containers in detached mode.
docker compose up -d server
docker compose --profile manual up -d router ips client
