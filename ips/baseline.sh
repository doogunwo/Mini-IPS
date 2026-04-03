#!/usr/bin/env bash
set -euo pipefail

setup_up() {
    setup_down >/dev/null 2>&1 || true

    echo "[1/4] 네임스페이스 및 veth 생성..."
    ip netns add ns_client
    ip netns add ns_proxy
    ip netns add ns_server

    ip link add veth_c type veth peer name veth_p_c
    ip link add veth_p_s type veth peer name veth_s

    ip link set veth_c netns ns_client
    ip link set veth_p_c netns ns_proxy
    ip link set veth_p_s netns ns_proxy
    ip link set veth_s netns ns_server

    echo "[2/4] client/server 설정..."
    ip netns exec ns_client ip link set lo up
    ip netns exec ns_client ip addr add 20.0.1.100/24 dev veth_c
    ip netns exec ns_client ip link set veth_c up
    ip netns exec ns_client ip route replace default via 20.0.1.1 dev veth_c

    ip netns exec ns_server ip link set lo up
    ip netns exec ns_server ip addr add 10.0.1.100/24 dev veth_s
    ip netns exec ns_server ip link set veth_s up
    ip netns exec ns_server ip route replace default via 10.0.1.1 dev veth_s

    echo "[3/4] proxy(L3 baseline) 설정..."
    ip netns exec ns_proxy ip link set lo up
    ip netns exec ns_proxy ip addr add 20.0.1.1/24 dev veth_p_c
    ip netns exec ns_proxy ip link set veth_p_c up
    ip netns exec ns_proxy ip addr add 10.0.1.1/24 dev veth_p_s
    ip netns exec ns_proxy ip link set veth_p_s up
    ip netns exec ns_proxy sysctl -q -w net.ipv4.ip_forward=1

    echo "[4/4] 완료. baseline 라우팅:"
    ip netns exec ns_client ip route
    ip netns exec ns_proxy ip route
    ip netns exec ns_server ip route
    echo "✅ baseline 환경 구축 완료!"
}

setup_down() {
    echo "🧹 네임스페이스 삭제 중..."
    ip netns del ns_client 2>/dev/null || true
    ip netns del ns_proxy 2>/dev/null || true
    ip netns del ns_server 2>/dev/null || true
    echo "✅ 삭제 완료!"
}

show_status() {
    echo "--- [Proxy ip_forward] ---"
    ip netns exec ns_proxy sysctl net.ipv4.ip_forward
    echo "--- [Addresses] ---"
    ip netns exec ns_client ip -br addr
    ip netns exec ns_proxy ip -br addr
    ip netns exec ns_server ip -br addr
    echo "--- [Routes] ---"
    ip netns exec ns_client ip route
    ip netns exec ns_proxy ip route
    ip netns exec ns_server ip route
}

case "${1:-}" in
    up) setup_up ;;
    down) setup_down ;;
    status) show_status ;;
    *) echo "Usage: $0 {up|down|status}" ;;
esac
