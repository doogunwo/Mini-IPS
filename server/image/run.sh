#!/usr/bin/env sh
set -e

SERVER_IP="${SERVER_IP:-172.31.0.60}"
SERVER_PORT="${SERVER_PORT:-8080}"
SERVER_GATEWAY="${SERVER_GATEWAY:-172.31.0.59}"

iptables -w -t mangle -C PREROUTING -i eth0 -p tcp -m tcp -d "${SERVER_IP}" --dport "${SERVER_PORT}" -j TEE --gateway "${SERVER_GATEWAY}" 2>/dev/null || \
  iptables -w -t mangle -A PREROUTING -i eth0 -p tcp -m tcp -d "${SERVER_IP}" --dport "${SERVER_PORT}" -j TEE --gateway "${SERVER_GATEWAY}"
iptables -w -t mangle -C OUTPUT -o eth0 -p tcp -m tcp -s "${SERVER_IP}" --sport "${SERVER_PORT}" -j TEE --gateway "${SERVER_GATEWAY}" 2>/dev/null || \
  iptables -w -t mangle -A OUTPUT -o eth0 -p tcp -m tcp -s "${SERVER_IP}" --sport "${SERVER_PORT}" -j TEE --gateway "${SERVER_GATEWAY}"

exec python3 /app/server.py --host 0.0.0.0 --port "${SERVER_PORT}" --verbose
