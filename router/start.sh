#!/usr/bin/env sh
set -eu

sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true

exec sh -c "trap : TERM INT; sleep infinity & wait"
