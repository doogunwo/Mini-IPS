#!/usr/bin/env bash
set -euo pipefail

setup_up() {
    setup_down >/dev/null 2>&1 || true

    echo "[1/5] 네임스페이스 및 veth 생성..."
    ip netns add ns_client
    ip netns add ns_router
    ip netns add ns_server
    ip netns add ns_sniffing

    ip link add veth_c type veth peer name veth_r_c
    ip link add veth_r_s type veth peer name veth_s
    ip link add veth_r_snf type veth peer name veth_snf

    ip link set veth_c netns ns_client
    ip link set veth_r_c netns ns_router
    ip link set veth_r_s netns ns_router
    ip link set veth_s netns ns_server
    ip link set veth_r_snf netns ns_router
    ip link set veth_snf netns ns_sniffing

    echo "[2/5] client/server 설정..."
    ip netns exec ns_client ip link set lo up
    ip netns exec ns_client ip addr add 20.0.1.100/24 dev veth_c
    ip netns exec ns_client ip link set veth_c up
    ip netns exec ns_client ip route replace default via 20.0.1.1 dev veth_c

    ip netns exec ns_server ip link set lo up
    ip netns exec ns_server ip addr add 10.0.1.100/24 dev veth_s
    ip netns exec ns_server ip link set veth_s up
    ip netns exec ns_server ip route replace default via 10.0.1.1 dev veth_s

    echo "[3/5] router 설정..."
    ip netns exec ns_router ip link set lo up
    ip netns exec ns_router ip addr add 20.0.1.1/24 dev veth_r_c
    ip netns exec ns_router ip link set veth_r_c up
    ip netns exec ns_router ip addr add 10.0.1.1/24 dev veth_r_s
    ip netns exec ns_router ip link set veth_r_s up
    ip netns exec ns_router ip link set veth_r_snf up
    ip netns exec ns_router sysctl -q -w net.ipv4.ip_forward=1

    echo "[4/5] sniffing 네임스페이스 및 미러링 설정..."
    ip netns exec ns_sniffing ip link set lo up
    ip netns exec ns_sniffing ip link set veth_snf up

    ip netns exec ns_router tc qdisc add dev veth_r_c clsact 2>/dev/null || true
    ip netns exec ns_router tc qdisc add dev veth_r_s clsact 2>/dev/null || true

    ip netns exec ns_router tc filter add dev veth_r_c ingress matchall \
        action mirred egress mirror dev veth_r_snf 2>/dev/null || true
    ip netns exec ns_router tc filter add dev veth_r_s ingress matchall \
        action mirred egress mirror dev veth_r_snf 2>/dev/null || true

    echo "[5/5] 완료. sniffing 실행 예시:"
    echo "  sudo ip netns exec ns_sniffing /home/doogunwo/training/Mini-IPS/ips/build/bin/sniffing-ips -iface=veth_snf -bpf='tcp and port 8080'"
    echo "✅ sniffing 비교 환경 구축 완료!"
}

setup_down() {
    echo "🧹 네임스페이스 삭제 중..."
    ip netns del ns_client 2>/dev/null || true
    ip netns del ns_router 2>/dev/null || true
    ip netns del ns_server 2>/dev/null || true
    ip netns del ns_sniffing 2>/dev/null || true
    echo "✅ 삭제 완료!"
}

show_status() {
    echo "--- [Router ip_forward] ---"
    ip netns exec ns_router sysctl net.ipv4.ip_forward
    echo "--- [Addresses] ---"
    ip netns exec ns_client ip -br addr
    ip netns exec ns_router ip -br addr
    ip netns exec ns_server ip -br addr
    ip netns exec ns_sniffing ip -br addr
    echo "--- [Routes] ---"
    ip netns exec ns_client ip route
    ip netns exec ns_router ip route
    ip netns exec ns_server ip route
    echo "--- [Mirror Filters] ---"
    ip netns exec ns_router tc filter show dev veth_r_c ingress
    ip netns exec ns_router tc filter show dev veth_r_s ingress
    echo "--- [Capture Hint] ---"
    echo "sniffing namespace: ns_sniffing"
    echo "sniffing iface: veth_snf"
    echo "recommended bpf: tcp and port 8080"
}

case "${1:-}" in
    up) setup_up ;;
    down) setup_down ;;
    status) show_status ;;
    *) echo "Usage: $0 {up|down|status}" ;;
esac
