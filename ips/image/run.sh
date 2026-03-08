#!/usr/bin/env sh
set -e

IFACE="${IFACE:-eth0}"
BPF="${BPF:-tcp and host 172.31.0.60 and port 8080}"
MODE="${MODE:-sniffing}"

exec /app/main -mode="${MODE}" -iface="${IFACE}" -bpf="${BPF}"
