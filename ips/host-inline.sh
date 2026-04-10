#!/usr/bin/env bash
set -euo pipefail

ENV_FILE="${1:-.env.host-inline}"
ACTION="${2:-${1:-}}"

if [[ "$ENV_FILE" == "up" || "$ENV_FILE" == "down" || "$ENV_FILE" == "status" ]]; then
  ACTION="$ENV_FILE"
  ENV_FILE=".env.host-inline"
fi

if [[ ! -f "$ENV_FILE" ]]; then
  echo "ENV file not found: $ENV_FILE" >&2
  exit 1
fi

# shellcheck disable=SC1090
source "$ENV_FILE"

required_vars=(
  CLIENT_IF
  SERVER_IF
  CLIENT_IF_CIDR
  SERVER_IF_CIDR
  CLIENT_SUBNET
  SERVER_SUBNET
  CLIENT_IP
  SERVER_IP
  SERVER_PORT
  TPROXY_PORT
  FWMARK
  ROUTE_TABLE
)

for v in "${required_vars[@]}"; do
  if [[ -z "${!v:-}" ]]; then
    echo "Missing required env: $v" >&2
    exit 1
  fi
done

TPROXY_MASK="${TPROXY_MASK:-0x1}"
IPTABLES_BIN="${IPTABLES_BIN:-iptables}"

check_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    echo "Run as root" >&2
    exit 1
  fi
}

load_modules() {
  local required_modules=(
    xt_TPROXY
    nf_tproxy_ipv4
    xt_socket
  )
  local module

  if ! command -v modprobe >/dev/null 2>&1; then
    return 0
  fi

  for module in "${required_modules[@]}"; do
    modprobe "${module}" || true
  done
}

setup_interfaces() {
  ip link show "${CLIENT_IF}" >/dev/null
  ip link show "${SERVER_IF}" >/dev/null

  ip link set "${CLIENT_IF}" up
  ip link set "${SERVER_IF}" up

  ip addr flush dev "${CLIENT_IF}" || true
  ip addr flush dev "${SERVER_IF}" || true

  ip addr add "${CLIENT_IF_CIDR}" dev "${CLIENT_IF}"
  ip addr add "${SERVER_IF_CIDR}" dev "${SERVER_IF}"

  ip route replace "${CLIENT_SUBNET}" dev "${CLIENT_IF}" src "${CLIENT_IF_CIDR%%/*}" 2>/dev/null \
    || ip route replace "${CLIENT_SUBNET}" dev "${CLIENT_IF}"
  ip route replace "${SERVER_SUBNET}" dev "${SERVER_IF}" src "${SERVER_IF_CIDR%%/*}" 2>/dev/null \
    || ip route replace "${SERVER_SUBNET}" dev "${SERVER_IF}"
}

setup_sysctl() {
  sysctl -q -w net.ipv4.ip_forward=1
  sysctl -q -w net.ipv4.conf.all.route_localnet=1
  sysctl -q -w net.ipv4.conf.all.rp_filter=0
  sysctl -q -w net.ipv4.conf.default.rp_filter=0
  sysctl -q -w "net.ipv4.conf.${CLIENT_IF}.rp_filter=0"
  sysctl -q -w "net.ipv4.conf.${SERVER_IF}.rp_filter=0"
}

setup_policy_routing() {
  ip rule del fwmark "${FWMARK}" lookup "${ROUTE_TABLE}" 2>/dev/null || true
  ip rule add fwmark "${FWMARK}" lookup "${ROUTE_TABLE}"

  ip route flush table "${ROUTE_TABLE}" 2>/dev/null || true
  ip route add local 0.0.0.0/0 dev lo table "${ROUTE_TABLE}"
}

setup_iptables() {
  ${IPTABLES_BIN} -t mangle -N DIVERT 2>/dev/null || true
  ${IPTABLES_BIN} -t mangle -F DIVERT

  ${IPTABLES_BIN} -t mangle -C DIVERT -j MARK --set-mark "${FWMARK}" 2>/dev/null \
    || ${IPTABLES_BIN} -t mangle -A DIVERT -j MARK --set-mark "${FWMARK}"
  ${IPTABLES_BIN} -t mangle -C DIVERT -j ACCEPT 2>/dev/null \
    || ${IPTABLES_BIN} -t mangle -A DIVERT -j ACCEPT

  ${IPTABLES_BIN} -t mangle -C PREROUTING -p tcp -m socket -j DIVERT 2>/dev/null \
    || ${IPTABLES_BIN} -t mangle -A PREROUTING -p tcp -m socket -j DIVERT

  ${IPTABLES_BIN} -t mangle -C PREROUTING \
    -i "${CLIENT_IF}" -p tcp -s "${CLIENT_IP}" -d "${SERVER_IP}" --dport "${SERVER_PORT}" \
    -j TPROXY --on-port "${TPROXY_PORT}" --tproxy-mark "${FWMARK}/${TPROXY_MASK}" 2>/dev/null \
    || ${IPTABLES_BIN} -t mangle -A PREROUTING \
      -i "${CLIENT_IF}" -p tcp -s "${CLIENT_IP}" -d "${SERVER_IP}" --dport "${SERVER_PORT}" \
      -j TPROXY --on-port "${TPROXY_PORT}" --tproxy-mark "${FWMARK}/${TPROXY_MASK}"
}

cleanup() {
  ${IPTABLES_BIN} -t mangle -D PREROUTING \
    -i "${CLIENT_IF}" -p tcp -s "${CLIENT_IP}" -d "${SERVER_IP}" --dport "${SERVER_PORT}" \
    -j TPROXY --on-port "${TPROXY_PORT}" --tproxy-mark "${FWMARK}/${TPROXY_MASK}" 2>/dev/null || true

  ${IPTABLES_BIN} -t mangle -D PREROUTING -p tcp -m socket -j DIVERT 2>/dev/null || true
  ${IPTABLES_BIN} -t mangle -F DIVERT 2>/dev/null || true
  ${IPTABLES_BIN} -t mangle -X DIVERT 2>/dev/null || true

  ip rule del fwmark "${FWMARK}" lookup "${ROUTE_TABLE}" 2>/dev/null || true
  ip route flush table "${ROUTE_TABLE}" 2>/dev/null || true
}

show_status() {
  echo
  echo "=== interfaces ==="
  ip -br addr show dev "${CLIENT_IF}" || true
  ip -br addr show dev "${SERVER_IF}" || true
  echo
  echo "=== main routes ==="
  ip route show "${CLIENT_SUBNET}" || true
  ip route show "${SERVER_SUBNET}" || true
  echo
  echo "=== iptables mangle ==="
  ${IPTABLES_BIN} -t mangle -L -n -v --line-numbers
  echo
  echo "=== ip rule ==="
  ip rule show
  echo
  echo "=== route table ${ROUTE_TABLE} ==="
  ip route show table "${ROUTE_TABLE}"
  echo
  echo "TPROXY path: ${CLIENT_IP} -> ${SERVER_IP}:${SERVER_PORT} => local :${TPROXY_PORT}"
  echo "Client-facing NIC: ${CLIENT_IF}"
  echo "Server-facing NIC: ${SERVER_IF}"
}

usage() {
  cat <<EOF
Usage:
  $0 [.env.host-inline] up
  $0 [.env.host-inline] down
  $0 [.env.host-inline] status

VirtualBox recommendation:
  Host Windows <-> Host-Only Adapter <-> IPS VM (${CLIENT_IF})
  IPS VM (${SERVER_IF}) <-> Internal Network <-> Server VM

Notes:
  - Use dedicated NICs for CLIENT_IF and SERVER_IF.
  - This script configures the IPS VM as an L3 inline box with TPROXY.
  - "down" removes TPROXY policy/iptables rules, but keeps interface addressing in place.
EOF
}

main() {
  check_root
  load_modules

  case "${ACTION:-}" in
    up)
      setup_interfaces
      setup_sysctl
      setup_policy_routing
      setup_iptables
      show_status
      ;;
    down)
      cleanup
      ;;
    status)
      show_status
      ;;
    *)
      usage
      exit 1
      ;;
  esac
}

main "$@"
