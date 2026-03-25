#!/usr/bin/env sh
set -eu

NS_CLIENT="${NS_CLIENT:-ns_client}"
NS_PROXY="${NS_PROXY:-ns_proxy}"
NS_SERVER="${NS_SERVER:-ns_server}"

require_root() {
  if [ "$(id -u)" -ne 0 ]; then
    echo "Run as root: sudo $0" >&2
    exit 1
  fi
}

delete_ns_if_exists() {
  ns="$1"
  if ip netns list | awk '{print $1}' | grep -qx "${ns}"; then
    ip netns del "${ns}"
  fi
}

require_root

delete_ns_if_exists "${NS_CLIENT}"
delete_ns_if_exists "${NS_PROXY}"
delete_ns_if_exists "${NS_SERVER}"

echo "Removed namespaces: ${NS_CLIENT}, ${NS_PROXY}, ${NS_SERVER}"
