#!/usr/bin/env sh
set -eu

NS_CLIENT="${NS_CLIENT:-ns_client}"
NS_PROXY="${NS_PROXY:-ns_proxy}"
NS_SERVER="${NS_SERVER:-ns_server}"
BRIDGE_NAME="${BRIDGE_NAME:-br0}"

print_ns() {
  ns="$1"
  if ! ip netns list | awk '{print $1}' | grep -qx "${ns}"; then
    echo "[$ns] not found"
    return
  fi

  echo "[$ns] links"
  ip -n "${ns}" -br link
  echo "[$ns] addr"
  ip -n "${ns}" -br addr
  echo "[$ns] routes"
  ip -n "${ns}" route
  echo
}

echo "Namespaces:"
ip netns list || true
echo

print_ns "${NS_CLIENT}"
print_ns "${NS_PROXY}"
print_ns "${NS_SERVER}"

if ip netns list | awk '{print $1}' | grep -qx "${NS_PROXY}"; then
  echo "[${NS_PROXY}] sysctl"
  ip netns exec "${NS_PROXY}" sysctl net.ipv4.ip_forward || true
  echo
  echo "[${NS_PROXY}] bridge detail (${BRIDGE_NAME})"
  ip -n "${NS_PROXY}" -d link show "${BRIDGE_NAME}" 2>/dev/null || true
fi
