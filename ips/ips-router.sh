#!/usr/bin/env bash
set -euo pipefail

# ===== 설정 (수정 가능) =====
NS_CLIENT="ns_client"
NS_ROUTER="ns_router"
NS_PROXY="ns_proxy"
NS_SERVER="ns_server"

# client <-> router
C_IP="20.0.1.100"
C_GW_IP="20.0.1.1"

# router <-> proxy transit
RP_R_IP="172.16.0.1"
RP_P_IP="172.16.0.2"

# proxy <-> server
S_IP="10.0.1.100"
S_GW_IP="10.0.1.1"

S_PORT="8080"
P_PORT="50080"

FWMARK="1"
TPROXY_MASK="0x1"
TABLE="100"

# 인터페이스 이름
VETH_C="veth_c"; VETH_RC="veth_r_c"
VETH_RP="veth_r_p"; VETH_PR="veth_p_r"
VETH_PS="veth_p_s"; VETH_S="veth_s"

setup_up() {
    setup_down >/dev/null 2>&1 || true

    echo "[1/6] 네임스페이스/인터페이스 생성..."
    ip netns add "$NS_CLIENT"
    ip netns add "$NS_ROUTER"
    ip netns add "$NS_PROXY"
    ip netns add "$NS_SERVER"

    ip link add "$VETH_C" type veth peer name "$VETH_RC"
    ip link add "$VETH_RP" type veth peer name "$VETH_PR"
    ip link add "$VETH_PS" type veth peer name "$VETH_S"

    ip link set "$VETH_C" netns "$NS_CLIENT"
    ip link set "$VETH_RC" netns "$NS_ROUTER"
    ip link set "$VETH_RP" netns "$NS_ROUTER"
    ip link set "$VETH_PR" netns "$NS_PROXY"
    ip link set "$VETH_PS" netns "$NS_PROXY"
    ip link set "$VETH_S" netns "$NS_SERVER"

    echo "[2/6] client/server 설정..."
    ip netns exec "$NS_CLIENT" ip link set lo up
    ip netns exec "$NS_CLIENT" ip addr add "$C_IP/24" dev "$VETH_C"
    ip netns exec "$NS_CLIENT" ip link set "$VETH_C" up
    ip netns exec "$NS_CLIENT" ip route replace "10.0.1.0/24" via "$C_GW_IP" dev "$VETH_C"

    ip netns exec "$NS_SERVER" ip link set lo up
    ip netns exec "$NS_SERVER" ip addr add "$S_IP/24" dev "$VETH_S"
    ip netns exec "$NS_SERVER" ip link set "$VETH_S" up
    ip netns exec "$NS_SERVER" ip route replace "20.0.1.0/24" via "$S_GW_IP" dev "$VETH_S"

    echo "[3/6] router(L3) 설정..."
    ip netns exec "$NS_ROUTER" ip link set lo up
    ip netns exec "$NS_ROUTER" ip addr add "$C_GW_IP/24" dev "$VETH_RC"
    ip netns exec "$NS_ROUTER" ip link set "$VETH_RC" up
    ip netns exec "$NS_ROUTER" ip addr add "$RP_R_IP/30" dev "$VETH_RP"
    ip netns exec "$NS_ROUTER" ip link set "$VETH_RP" up
    ip netns exec "$NS_ROUTER" sysctl -q -w net.ipv4.ip_forward=1
    ip netns exec "$NS_ROUTER" ip route replace "10.0.1.0/24" via "$RP_P_IP" dev "$VETH_RP"

    echo "[4/6] proxy(L3 + TPROXY) 설정..."
    ip netns exec "$NS_PROXY" ip link set lo up
    ip netns exec "$NS_PROXY" ip addr add "$RP_P_IP/30" dev "$VETH_PR"
    ip netns exec "$NS_PROXY" ip link set "$VETH_PR" up
    ip netns exec "$NS_PROXY" ip addr add "$S_GW_IP/24" dev "$VETH_PS"
    ip netns exec "$NS_PROXY" ip link set "$VETH_PS" up

    ip netns exec "$NS_PROXY" sysctl -q -w net.ipv4.ip_forward=1
    ip netns exec "$NS_PROXY" sysctl -q -w net.ipv4.conf.all.route_localnet=1
    ip netns exec "$NS_PROXY" sysctl -q -w net.ipv4.conf.all.rp_filter=0
    ip netns exec "$NS_PROXY" sysctl -q -w net.ipv4.conf.default.rp_filter=0
    ip netns exec "$NS_PROXY" sysctl -q -w "net.ipv4.conf.${VETH_PR}.rp_filter=0"
    ip netns exec "$NS_PROXY" sysctl -q -w "net.ipv4.conf.${VETH_PS}.rp_filter=0"
    sysctl -q -w net.bridge.bridge-nf-call-iptables=1 || true

    ip netns exec "$NS_PROXY" ip route replace "20.0.1.0/24" via "$RP_R_IP" dev "$VETH_PR"

    echo "[5/6] TPROXY policy/iptables 설정..."
    ip netns exec "$NS_PROXY" ip rule del fwmark "$FWMARK" lookup "$TABLE" 2>/dev/null || true
    ip netns exec "$NS_PROXY" ip rule add fwmark "$FWMARK" lookup "$TABLE"
    ip netns exec "$NS_PROXY" ip route flush table "$TABLE" 2>/dev/null || true
    ip netns exec "$NS_PROXY" ip route add local 0.0.0.0/0 dev lo table "$TABLE"

    ip netns exec "$NS_PROXY" iptables -t mangle -N DIVERT 2>/dev/null || true
    ip netns exec "$NS_PROXY" iptables -t mangle -F DIVERT
    ip netns exec "$NS_PROXY" iptables -t mangle -C DIVERT -j MARK --set-mark "$FWMARK" 2>/dev/null \
        || ip netns exec "$NS_PROXY" iptables -t mangle -A DIVERT -j MARK --set-mark "$FWMARK"
    ip netns exec "$NS_PROXY" iptables -t mangle -C DIVERT -j ACCEPT 2>/dev/null \
        || ip netns exec "$NS_PROXY" iptables -t mangle -A DIVERT -j ACCEPT
    ip netns exec "$NS_PROXY" iptables -t mangle -C PREROUTING -p tcp -m socket -j DIVERT 2>/dev/null \
        || ip netns exec "$NS_PROXY" iptables -t mangle -A PREROUTING -p tcp -m socket -j DIVERT
    ip netns exec "$NS_PROXY" iptables -t mangle -C PREROUTING \
        -p tcp -s "$C_IP" -d "$S_IP" --dport "$S_PORT" \
        -j TPROXY --on-port "$P_PORT" --tproxy-mark "$FWMARK/$TPROXY_MASK" 2>/dev/null \
        || ip netns exec "$NS_PROXY" iptables -t mangle -A PREROUTING \
            -p tcp -s "$C_IP" -d "$S_IP" --dport "$S_PORT" \
            -j TPROXY --on-port "$P_PORT" --tproxy-mark "$FWMARK/$TPROXY_MASK"

    echo "[6/6] 완료. 핵심 라우팅:"
    ip netns exec "$NS_CLIENT" ip route
    ip netns exec "$NS_ROUTER" ip route
    ip netns exec "$NS_PROXY" ip route
    ip netns exec "$NS_SERVER" ip route
    echo "✅ router mode 환경 구축 완료!"
}

setup_down() {
    echo "🧹 네임스페이스 삭제 중..."
    ip netns del "$NS_CLIENT" 2>/dev/null || true
    ip netns del "$NS_ROUTER" 2>/dev/null || true
    ip netns del "$NS_PROXY" 2>/dev/null || true
    ip netns del "$NS_SERVER" 2>/dev/null || true
    echo "✅ 삭제 완료!"
}

show_status() {
    echo "--- [Proxy mangle PREROUTING] ---"
    ip netns exec "$NS_PROXY" iptables -t mangle -L PREROUTING -v -n
    echo "--- [Proxy ip rule] ---"
    ip netns exec "$NS_PROXY" ip rule show | grep fwmark || true
    echo "--- [Proxy table ${TABLE}] ---"
    ip netns exec "$NS_PROXY" ip route show table "$TABLE"
    echo "--- [ip_forward] ---"
    ip netns exec "$NS_ROUTER" sysctl net.ipv4.ip_forward
    ip netns exec "$NS_PROXY" sysctl net.ipv4.ip_forward
    echo "--- [Routes] ---"
    ip netns exec "$NS_CLIENT" ip route
    ip netns exec "$NS_ROUTER" ip route
    ip netns exec "$NS_PROXY" ip route
    ip netns exec "$NS_SERVER" ip route
}

case "${1:-}" in
    up) setup_up ;;
    down) setup_down ;;
    status) show_status ;;
    *) echo "Usage: $0 {up|down|status}" ;;
esac
