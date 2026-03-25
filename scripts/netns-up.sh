#!/usr/bin/env sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

NS_CLIENT="${NS_CLIENT:-ns_client}"
NS_PROXY="${NS_PROXY:-ns_proxy}"
NS_SERVER="${NS_SERVER:-ns_server}"

VETH_CLIENT="${VETH_CLIENT:-veth_client}"
VETH_PROXY_C="${VETH_PROXY_C:-veth_proxy_c}"
VETH_SERVER="${VETH_SERVER:-veth_server}"
VETH_PROXY_S="${VETH_PROXY_S:-veth_proxy_s}"

BRIDGE_NAME="${BRIDGE_NAME:-br0}"

CLIENT_IP_CIDR="${CLIENT_IP_CIDR:-20.0.1.100/24}"
PROXY_CLIENT_GW_CIDR="${PROXY_CLIENT_GW_CIDR:-20.0.1.1/24}"
SERVER_IP_CIDR="${SERVER_IP_CIDR:-10.0.1.100/24}"
PROXY_SERVER_GW_CIDR="${PROXY_SERVER_GW_CIDR:-10.0.1.1/24}"

CLIENT_TO_SERVER_SUBNET="${CLIENT_TO_SERVER_SUBNET:-10.0.1.0/24}"
SERVER_TO_CLIENT_SUBNET="${SERVER_TO_CLIENT_SUBNET:-20.0.1.0/24}"

require_root() {
  if [ "$(id -u)" -ne 0 ]; then
    echo "Run as root: sudo $0" >&2
    exit 1
  fi
}

require_root

# Reset previous topology if present.
"${SCRIPT_DIR}/netns-down.sh" >/dev/null 2>&1 || true

ip netns add "${NS_CLIENT}"
ip netns add "${NS_PROXY}"
ip netns add "${NS_SERVER}"

ip -n "${NS_CLIENT}" link set lo up
ip -n "${NS_PROXY}" link set lo up
ip -n "${NS_SERVER}" link set lo up

ip link add "${VETH_CLIENT}" type veth peer name "${VETH_PROXY_C}"
ip link add "${VETH_SERVER}" type veth peer name "${VETH_PROXY_S}"

ip link set "${VETH_CLIENT}" netns "${NS_CLIENT}"
ip link set "${VETH_PROXY_C}" netns "${NS_PROXY}"
ip link set "${VETH_SERVER}" netns "${NS_SERVER}"
ip link set "${VETH_PROXY_S}" netns "${NS_PROXY}"

ip -n "${NS_CLIENT}" addr add "${CLIENT_IP_CIDR}" dev "${VETH_CLIENT}"
ip -n "${NS_CLIENT}" link set "${VETH_CLIENT}" up
ip -n "${NS_CLIENT}" route add "${CLIENT_TO_SERVER_SUBNET}" \
  via "${PROXY_CLIENT_GW_CIDR%/*}" dev "${VETH_CLIENT}"

ip -n "${NS_SERVER}" addr add "${SERVER_IP_CIDR}" dev "${VETH_SERVER}"
ip -n "${NS_SERVER}" link set "${VETH_SERVER}" up
ip -n "${NS_SERVER}" route add "${SERVER_TO_CLIENT_SUBNET}" \
  via "${PROXY_SERVER_GW_CIDR%/*}" dev "${VETH_SERVER}"

ip -n "${NS_PROXY}" link add "${BRIDGE_NAME}" type bridge
ip -n "${NS_PROXY}" link set "${BRIDGE_NAME}" up
ip -n "${NS_PROXY}" link set "${VETH_PROXY_C}" master "${BRIDGE_NAME}"
ip -n "${NS_PROXY}" link set "${VETH_PROXY_S}" master "${BRIDGE_NAME}"
ip -n "${NS_PROXY}" link set "${VETH_PROXY_C}" up
ip -n "${NS_PROXY}" link set "${VETH_PROXY_S}" up
ip -n "${NS_PROXY}" addr add "${PROXY_CLIENT_GW_CIDR}" dev "${BRIDGE_NAME}"
ip -n "${NS_PROXY}" addr add "${PROXY_SERVER_GW_CIDR}" dev "${BRIDGE_NAME}"

ip netns exec "${NS_PROXY}" sysctl -q -w net.ipv4.ip_forward=1

cat <<EOF
Topology is up:
  ${NS_CLIENT} (${CLIENT_IP_CIDR%/*}) -> ${NS_PROXY}/${BRIDGE_NAME} -> ${NS_SERVER} (${SERVER_IP_CIDR%/*})

Quick checks:
  sudo ip netns exec ${NS_CLIENT} ping -c 1 ${PROXY_CLIENT_GW_CIDR%/*}
  sudo ip netns exec ${NS_CLIENT} ping -c 1 ${SERVER_IP_CIDR%/*}
  sudo ip netns exec ${NS_SERVER} python3 -m http.server 80 --bind ${SERVER_IP_CIDR%/*}
  sudo ip netns exec ${NS_CLIENT} curl -v http://${SERVER_IP_CIDR%/*}:80/
EOF
