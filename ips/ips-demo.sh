#!/usr/bin/env bash
set -euo pipefail

ACTION="${1:-status}"

REPO_DIR="${REPO_DIR:-/home/doogunwo/training/Mini-IPS}"
IFACE="${IFACE:-eth0}"

CLIENT_IP="${CLIENT_IP:-10.0.0.55}"
SERVER_NEXT_HOP="${SERVER_NEXT_HOP:-10.0.0.51}"
SERVICE_IP="${SERVICE_IP:-20.0.1.100}"
SERVICE_PORT="${SERVICE_PORT:-8080}"

TPROXY_PORT="${TPROXY_PORT:-50080}"
FWMARK="${FWMARK:-1}"
TABLE="${TABLE:-100}"
MASK="${MASK:-0x1}"

IPTABLES_BIN="${IPTABLES_BIN:-iptables}"
INLINE_BIN="${INLINE_BIN:-${REPO_DIR}/ips/build/bin/inline-ips}"

ensure_root() {
  [[ "${EUID}" -eq 0 ]] || { echo "run as root"; exit 1; }
}

load_modules() {
  command -v modprobe >/dev/null 2>&1 || return 0
  modprobe xt_TPROXY || true
  modprobe nf_tproxy_ipv4 || true
  modprobe xt_socket || true
}

up() {
  ip link show "${IFACE}" >/dev/null

  sysctl -q -w net.ipv4.conf.all.route_localnet=1
  sysctl -q -w net.ipv4.conf.all.rp_filter=0
  sysctl -q -w net.ipv4.conf.default.rp_filter=0
  sysctl -q -w "net.ipv4.conf.${IFACE}.rp_filter=0"
  sysctl -q -w net.ipv4.conf.all.send_redirects=0
  sysctl -q -w net.ipv4.conf.default.send_redirects=0
  sysctl -q -w "net.ipv4.conf.${IFACE}.send_redirects=0"

  ip route replace "${SERVICE_IP}/32" via "${SERVER_NEXT_HOP}" dev "${IFACE}"

  ip rule del fwmark "${FWMARK}" lookup "${TABLE}" 2>/dev/null || true
  ip rule add fwmark "${FWMARK}" lookup "${TABLE}"
  ip route flush table "${TABLE}" 2>/dev/null || true
  ip route add local 0.0.0.0/0 dev lo table "${TABLE}"

  ${IPTABLES_BIN} -t mangle -N DIVERT 2>/dev/null || true
  ${IPTABLES_BIN} -t mangle -F DIVERT

  ${IPTABLES_BIN} -t mangle -C DIVERT -j MARK --set-mark "${FWMARK}" 2>/dev/null \
    || ${IPTABLES_BIN} -t mangle -A DIVERT -j MARK --set-mark "${FWMARK}"
  ${IPTABLES_BIN} -t mangle -C DIVERT -j ACCEPT 2>/dev/null \
    || ${IPTABLES_BIN} -t mangle -A DIVERT -j ACCEPT

  ${IPTABLES_BIN} -t mangle -C PREROUTING -p tcp -m socket -j DIVERT 2>/dev/null \
    || ${IPTABLES_BIN} -t mangle -A PREROUTING -p tcp -m socket -j DIVERT

  ${IPTABLES_BIN} -t mangle -C PREROUTING \
    -i "${IFACE}" -p tcp -s "${CLIENT_IP}" -d "${SERVICE_IP}" --dport "${SERVICE_PORT}" \
    -j TPROXY --on-port "${TPROXY_PORT}" --tproxy-mark "${FWMARK}/${MASK}" 2>/dev/null \
    || ${IPTABLES_BIN} -t mangle -A PREROUTING \
      -i "${IFACE}" -p tcp -s "${CLIENT_IP}" -d "${SERVICE_IP}" --dport "${SERVICE_PORT}" \
      -j TPROXY --on-port "${TPROXY_PORT}" --tproxy-mark "${FWMARK}/${MASK}"

  echo "ips demo path ready"
}

run_ips() {
  [[ -x "${INLINE_BIN}" ]] || make -C "${REPO_DIR}/ips" inline-ips
  cd "${REPO_DIR}/ips"
  exec "${INLINE_BIN}"
}

down() {
  ${IPTABLES_BIN} -t mangle -D PREROUTING \
    -i "${IFACE}" -p tcp -s "${CLIENT_IP}" -d "${SERVICE_IP}" --dport "${SERVICE_PORT}" \
    -j TPROXY --on-port "${TPROXY_PORT}" --tproxy-mark "${FWMARK}/${MASK}" 2>/dev/null || true
  ${IPTABLES_BIN} -t mangle -D PREROUTING -p tcp -m socket -j DIVERT 2>/dev/null || true
  ${IPTABLES_BIN} -t mangle -F DIVERT 2>/dev/null || true
  ${IPTABLES_BIN} -t mangle -X DIVERT 2>/dev/null || true

  ip rule del fwmark "${FWMARK}" lookup "${TABLE}" 2>/dev/null || true
  ip route flush table "${TABLE}" 2>/dev/null || true
  ip route del "${SERVICE_IP}/32" via "${SERVER_NEXT_HOP}" dev "${IFACE}" 2>/dev/null || true
}

status() {
  echo "=== iface ==="
  ip -br addr show dev "${IFACE}" || true
  echo
  echo "=== route ==="
  ip route show "${SERVICE_IP}/32" || true
  echo
  echo "=== mangle ==="
  ${IPTABLES_BIN} -t mangle -L PREROUTING -n -v --line-numbers || true
  echo
  echo "=== policy ==="
  ip rule show | grep -E "fwmark|lookup ${TABLE}" || true
  ip route show table "${TABLE}" || true
}

ensure_root
load_modules
case "${ACTION}" in
  up) up ;;
  run) run_ips ;;
  down) down ;;
  status) status ;;
  *) echo "usage: $0 {up|run|down|status}" ; exit 1 ;;
esac

