#!/usr/bin/env sh
set -e

SERVER_CPU="${SERVER_CPU:-0}"

mkdir -p /run/nginx

CPU_COUNT="$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 1)"

case "${SERVER_CPU}" in
    ''|*[!0-9]*)
        exec nginx -g "daemon off;"
        ;;
esac

if [ "${SERVER_CPU}" -lt "${CPU_COUNT}" ]; then
    exec taskset -c "${SERVER_CPU}" nginx -g "daemon off;"
fi

exec nginx -g "daemon off;"
