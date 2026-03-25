#!/usr/bin/env bash
set -euo pipefail

ENV_FILE="${1:-.env}"

if [[ ! -f "$ENV_FILE" ]]; then
  echo "ENV file not found: $ENV_FILE" >&2
  exit 1
fi

# shellcheck disable=SC1090
source "$ENV_FILE"

required_vars=(
  BRIDGE_NAME
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
PORT_A=""
PORT_B=""

check_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    echo "Run as root" >&2
    exit 1
  fi
}

find_bridge_ports() {
  if [[ -n "${BRIDGE_PORT_A:-}" && -n "${BRIDGE_PORT_B:-}" ]]; then
    PORT_A="${BRIDGE_PORT_A}"
    PORT_B="${BRIDGE_PORT_B}"
    return 0
  fi

  mapfile -t ports < <(
    ip -o link show | awk -F': ' -v br="${BRIDGE_NAME}" '
      $2 !~ /^lo(@|$)/ && $2 !~ ("^" br "(@|$)") { print $2 }
    ' | cut -d@ -f1
  )

  if [[ "${#ports[@]}" -lt 2 ]]; then
    echo "Need at least two non-loopback interfaces to build the IPS bridge." >&2
    exit 1
  fi

  PORT_A="${ports[0]}"
  PORT_B="${ports[1]}"
}

load_modules() {
  local required_modules=(
    br_netfilter
    xt_TPROXY
    nf_tproxy_ipv4
    xt_socket
  )
  local missing_modules=()
  local module

  for module in "${required_modules[@]}"; do
    if ! grep -q "^${module} " /proc/modules 2>/dev/null; then
      missing_modules+=("${module}")
    fi
  done

  if ! command -v modprobe >/dev/null 2>&1; then
    if [[ "${#missing_modules[@]}" -gt 0 ]]; then
      echo "Required kernel modules are not loaded on the host." >&2
      echo "Run these commands on the host first:" >&2
      for module in "${missing_modules[@]}"; do
        echo "  sudo modprobe ${module}" >&2
      done
      exit 1
    fi
    return 0
  fi

  for module in "${required_modules[@]}"; do
    modprobe "${module}" || true
  done
}

check_sysctl_value() {
  local key="$1"
  local expected="$2"
  local current
  local proc_path="/proc/sys/${key//./\/}"

  if [[ ! -r "$proc_path" ]]; then
    echo "Missing sysctl path: $key" >&2
    return 1
  fi

  current="$(cat "$proc_path")"
  if [[ "$current" != "$expected" ]]; then
    echo "Required sysctl is not set: ${key}=${current} (expected ${expected})" >&2
    return 1
  fi

  return 0
}

setup_sysctl() {
  local failed=0

  check_sysctl_value net.bridge.bridge-nf-call-iptables 1 || failed=1
  check_sysctl_value net.ipv4.conf.all.route_localnet 1 || failed=1
  check_sysctl_value net.ipv4.conf.all.rp_filter 0 || failed=1

  if [[ "$failed" -ne 0 ]]; then
    cat >&2 <<EOF
Set the missing sysctls before running this script.

Host-level:
  sudo sysctl -w net.bridge.bridge-nf-call-iptables=1

Container-level:
  net.ipv4.conf.all.route_localnet=1
  net.ipv4.conf.all.rp_filter=0
EOF
    exit 1
  fi
}

setup_bridge() {
  find_bridge_ports

  if ! ip link show "$BRIDGE_NAME" >/dev/null 2>&1; then
    ip link add "$BRIDGE_NAME" type bridge
  fi

  ip addr flush dev "$PORT_A" || true
  ip addr flush dev "$PORT_B" || true

  ip link set "$PORT_A" master "$BRIDGE_NAME"
  ip link set "$PORT_B" master "$BRIDGE_NAME"

  ip link set "$PORT_A" up
  ip link set "$PORT_B" up
  ip link set "$BRIDGE_NAME" up
}

setup_iptables() {
  iptables -t mangle -N DIVERT 2>/dev/null || true
  iptables -t mangle -F DIVERT

  iptables -t mangle -C PREROUTING -p tcp -m socket -j DIVERT 2>/dev/null \
    || iptables -t mangle -A PREROUTING -p tcp -m socket -j DIVERT

  iptables -t mangle -C DIVERT -j MARK --set-mark "${FWMARK}" 2>/dev/null \
    || iptables -t mangle -A DIVERT -j MARK --set-mark "${FWMARK}"

  iptables -t mangle -C DIVERT -j ACCEPT 2>/dev/null \
    || iptables -t mangle -A DIVERT -j ACCEPT

  iptables -t mangle -C PREROUTING \
    -p tcp -s "${CLIENT_IP}" -d "${SERVER_IP}" --dport "${SERVER_PORT}" \
    -j TPROXY --on-port "${TPROXY_PORT}" --tproxy-mark "${FWMARK}/${TPROXY_MASK}" 2>/dev/null \
    || iptables -t mangle -A PREROUTING \
      -p tcp -s "${CLIENT_IP}" -d "${SERVER_IP}" --dport "${SERVER_PORT}" \
      -j TPROXY --on-port "${TPROXY_PORT}" --tproxy-mark "${FWMARK}/${TPROXY_MASK}"
}

setup_routing() {
  ip rule del fwmark "${FWMARK}" lookup "${ROUTE_TABLE}" 2>/dev/null || true
  ip rule add fwmark "${FWMARK}" lookup "${ROUTE_TABLE}"

  ip route flush table "${ROUTE_TABLE}" 2>/dev/null || true
  ip route add local 0.0.0.0/0 dev lo table "${ROUTE_TABLE}"
}

validate_routing() {
  local fwmark_hex

  fwmark_hex="$(printf '0x%x' "$((FWMARK))")"

  if ! ip rule show | grep -Eq "fwmark[[:space:]]+(${FWMARK}|${fwmark_hex})(/[0-9xa-fA-F]+)?([[:space:]]+.*)?[[:space:]]+lookup[[:space:]]+${ROUTE_TABLE}"; then
    echo "missing policy routing rule for fwmark ${FWMARK} -> table ${ROUTE_TABLE}" >&2
    echo "--- ip rule show ---" >&2
    ip rule show >&2
    exit 1
  fi

  if ! ip route show table "${ROUTE_TABLE}" | grep -Eq '^local default dev lo($| )'; then
    echo "missing local route in table ${ROUTE_TABLE}: expected 'local default dev lo'" >&2
    echo "--- ip route show table ${ROUTE_TABLE} ---" >&2
    ip route show table "${ROUTE_TABLE}" >&2
    exit 1
  fi
}

show_status() {
  echo
  echo "=== bridge ==="
  ip -br link show dev "$BRIDGE_NAME" || true
  if [[ -n "$PORT_A" ]]; then ip -br link show dev "$PORT_A" || true; fi
  if [[ -n "$PORT_B" ]]; then ip -br link show dev "$PORT_B" || true; fi
  echo
  echo "=== ip addr ==="
  ip -br addr show dev "$BRIDGE_NAME" || true
  if [[ -n "$PORT_A" ]]; then ip -br addr show dev "$PORT_A" || true; fi
  if [[ -n "$PORT_B" ]]; then ip -br addr show dev "$PORT_B" || true; fi
  echo
  echo "=== iptables mangle ==="
  iptables -t mangle -L -n -v --line-numbers
  echo
  echo "=== ip rule ==="
  ip rule show
  echo
  echo "=== route table ${ROUTE_TABLE} ==="
  ip route show table "${ROUTE_TABLE}"
  echo
  echo "TPROXY target: ${CLIENT_IP} -> ${SERVER_IP}:${SERVER_PORT} => local :${TPROXY_PORT}"
}

cleanup() {
  iptables -t mangle -D PREROUTING \
    -p tcp -s "${CLIENT_IP}" -d "${SERVER_IP}" --dport "${SERVER_PORT}" \
    -j TPROXY --on-port "${TPROXY_PORT}" --tproxy-mark "${FWMARK}/${TPROXY_MASK}" 2>/dev/null || true

  iptables -t mangle -D PREROUTING -p tcp -m socket -j DIVERT 2>/dev/null || true
  iptables -t mangle -F DIVERT 2>/dev/null || true
  iptables -t mangle -X DIVERT 2>/dev/null || true

  ip rule del fwmark "${FWMARK}" lookup "${ROUTE_TABLE}" 2>/dev/null || true
  ip route flush table "${ROUTE_TABLE}" 2>/dev/null || true
}

usage() {
  cat <<EOF
Usage:
  $0 [.env] up
  $0 [.env] down
  $0 [.env] status
EOF
}

main() {
  check_root

  local action="${2:-${1:-}}"

  if [[ "$ENV_FILE" == "up" || "$ENV_FILE" == "down" || "$ENV_FILE" == "status" ]]; then
    action="$ENV_FILE"
    ENV_FILE=".env"
    # shellcheck disable=SC1090
    source "$ENV_FILE"
  fi

  case "${action:-}" in
    up)
      load_modules
      setup_sysctl
      setup_bridge
      setup_iptables
      setup_routing
      validate_routing
      show_status
      ;;
    down)
      cleanup
      find_bridge_ports || true
      show_status
      ;;
    status)
      find_bridge_ports || true
      show_status
      ;;
    *)
      usage
      exit 1
      ;;
  esac
}

main "$@"
