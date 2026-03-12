#!/usr/bin/env sh
set -e

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
SERVER_APP="${SERVER_APP:-${SCRIPT_DIR}/server.py}"
IFACE="${IFACE:-eth0}"
SERVER_IP="${SERVER_IP:-172.31.0.60}"
SERVER_PORT="${SERVER_PORT:-8080}"
SERVER_GATEWAY="${SERVER_GATEWAY:-172.31.0.59}"
SERVER_CPU="${SERVER_CPU:-3}"
SERVER_LATENCY_MS="${1:-${SERVER_LATENCY_MS:-0}}"

iptables -w -t mangle -C PREROUTING -i "${IFACE}" -p tcp -m tcp -d "${SERVER_IP}" --dport "${SERVER_PORT}" -j TEE --gateway "${SERVER_GATEWAY}" 2>/dev/null || \
  iptables -w -t mangle -A PREROUTING -i "${IFACE}" -p tcp -m tcp -d "${SERVER_IP}" --dport "${SERVER_PORT}" -j TEE --gateway "${SERVER_GATEWAY}"
iptables -w -t mangle -C OUTPUT -o "${IFACE}" -p tcp -m tcp -s "${SERVER_IP}" --sport "${SERVER_PORT}" -j TEE --gateway "${SERVER_GATEWAY}" 2>/dev/null || \
  iptables -w -t mangle -A OUTPUT -o "${IFACE}" -p tcp -m tcp -s "${SERVER_IP}" --sport "${SERVER_PORT}" -j TEE --gateway "${SERVER_GATEWAY}"

exec taskset -c "${SERVER_CPU}" python3 "${SERVER_APP}" \
  --host 0.0.0.0 \
  --port "${SERVER_PORT}" \
  --latency-ms "${SERVER_LATENCY_MS}" \
  --verbose
