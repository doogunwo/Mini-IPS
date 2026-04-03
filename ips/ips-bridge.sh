#!/usr/bin/env bash
set -euo pipefail

setup_up() {
    setup_down >/dev/null 2>&1 || true

    echo "[1/5] 네임스페이스 및 veth 생성..."
    ip netns add ns_client
    ip netns add ns_proxy
    ip netns add ns_server

    ip link add veth_c type veth peer name veth_p_c
    ip link add veth_p_s type veth peer name veth_s

    ip link set veth_c netns ns_client
    ip link set veth_p_c netns ns_proxy
    ip link set veth_p_s netns ns_proxy
    ip link set veth_s netns ns_server

    echo "[2/5] client/server 설정..."
    ip netns exec ns_client ip link set lo up
    ip netns exec ns_client ip addr add 20.0.1.100/24 dev veth_c
    ip netns exec ns_client ip link set veth_c up
    ip netns exec ns_client ip route replace default via 20.0.1.1 dev veth_c

    ip netns exec ns_server ip link set lo up
    ip netns exec ns_server ip addr add 10.0.1.100/24 dev veth_s
    ip netns exec ns_server ip link set veth_s up
    ip netns exec ns_server ip route replace default via 10.0.1.1 dev veth_s

    echo "[3/5] proxy(L3 + TPROXY) 설정..."
    ip netns exec ns_proxy ip link set lo up
    ip netns exec ns_proxy ip addr add 20.0.1.1/24 dev veth_p_c
    ip netns exec ns_proxy ip link set veth_p_c up
    ip netns exec ns_proxy ip addr add 10.0.1.1/24 dev veth_p_s
    ip netns exec ns_proxy ip link set veth_p_s up

    ip netns exec ns_proxy sysctl -q -w net.ipv4.ip_forward=1
    ip netns exec ns_proxy sysctl -q -w net.ipv4.conf.all.route_localnet=1
    ip netns exec ns_proxy sysctl -q -w net.ipv4.conf.all.rp_filter=0
    ip netns exec ns_proxy sysctl -q -w net.ipv4.conf.default.rp_filter=0
    ip netns exec ns_proxy sysctl -q -w net.ipv4.conf.veth_p_c.rp_filter=0
    ip netns exec ns_proxy sysctl -q -w net.ipv4.conf.veth_p_s.rp_filter=0

    echo "[4/5] TPROXY policy/iptables 설정..."
    ip netns exec ns_proxy ip rule del fwmark 1 lookup 100 2>/dev/null || true
    ip netns exec ns_proxy ip rule add fwmark 1 lookup 100
    ip netns exec ns_proxy ip route flush table 100 2>/dev/null || true
    ip netns exec ns_proxy ip route add local 0.0.0.0/0 dev lo table 100

    ip netns exec ns_proxy iptables -t mangle -N DIVERT 2>/dev/null || true
    ip netns exec ns_proxy iptables -t mangle -F DIVERT
    ip netns exec ns_proxy iptables -t mangle -C DIVERT -j MARK --set-mark 1 2>/dev/null \
        || ip netns exec ns_proxy iptables -t mangle -A DIVERT -j MARK --set-mark 1
    ip netns exec ns_proxy iptables -t mangle -C DIVERT -j ACCEPT 2>/dev/null \
        || ip netns exec ns_proxy iptables -t mangle -A DIVERT -j ACCEPT
    ip netns exec ns_proxy iptables -t mangle -C PREROUTING -p tcp -m socket -j DIVERT 2>/dev/null \
        || ip netns exec ns_proxy iptables -t mangle -A PREROUTING -p tcp -m socket -j DIVERT
    ip netns exec ns_proxy iptables -t mangle -C PREROUTING \
        -p tcp -s 20.0.1.100 -d 10.0.1.100 --dport 8080 \
        -j TPROXY --on-port 50080 --tproxy-mark 1/0x1 2>/dev/null \
        || ip netns exec ns_proxy iptables -t mangle -A PREROUTING \
            -p tcp -s 20.0.1.100 -d 10.0.1.100 --dport 8080 \
            -j TPROXY --on-port 50080 --tproxy-mark 1/0x1

    echo "[5/5] 완료. 핵심 라우팅:"
    ip netns exec ns_client ip route
    ip netns exec ns_proxy ip route
    ip netns exec ns_server ip route
    echo "✅ 단일 ns_proxy 라우터/TPROXY 환경 구축 완료!"
}

setup_down() {
    echo "🧹 네임스페이스 삭제 중..."
    ip netns del ns_client 2>/dev/null || true
    ip netns del ns_proxy 2>/dev/null || true
    ip netns del ns_server 2>/dev/null || true
    echo "✅ 삭제 완료!"
}

show_status() {
    echo "--- [Proxy mangle PREROUTING] ---"
    ip netns exec ns_proxy iptables -t mangle -L PREROUTING -v -n
    echo "--- [Proxy ip rule] ---"
    ip netns exec ns_proxy ip rule show | grep fwmark || true
    echo "--- [Proxy table 100] ---"
    ip netns exec ns_proxy ip route show table 100
    echo "--- [Proxy ip_forward] ---"
    ip netns exec ns_proxy sysctl net.ipv4.ip_forward
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
