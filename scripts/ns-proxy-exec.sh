#!/usr/bin/env sh
set -eu

NS_PROXY="${NS_PROXY:-ns_proxy}"

if ! ip netns list | awk '{print $1}' | grep -qx "${NS_PROXY}"; then
  echo "Namespace not found: ${NS_PROXY}" >&2
  exit 1
fi

if [ "$#" -eq 0 ]; then
  exec ip netns exec "${NS_PROXY}" sh
fi

exec ip netns exec "${NS_PROXY}" "$@"
