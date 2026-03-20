#!/usr/bin/env bash
set -euo pipefail

ROOT="/home/doogunwo/training/Mini-IPS"
IPS_DIR="$ROOT/ips"
BENCH_SRC="$IPS_DIR/benchmark/test_regex_load_bench.c"
TMPDIR="$(mktemp -d)"
OLD_SRC="$TMPDIR/regex_old.c"
OLD_INCLUDE_DIR="$TMPDIR/include"
CURRENT_BIN="$TMPDIR/regex_current"
OLD_BIN="$TMPDIR/regex_old"

cleanup() {
    rm -rf "$TMPDIR"
}
trap cleanup EXIT

mkdir -p "$OLD_INCLUDE_DIR"

git -C "$ROOT" show HEAD:ips/src/regex.c > "$OLD_SRC"
git -C "$ROOT" show HEAD:ips/include/regex.h > "$OLD_INCLUDE_DIR/regex.h"

gcc -D_DEFAULT_SOURCE -O2 -Wall -Wextra -std=c11 \
    -I"$IPS_DIR/include" \
    "$BENCH_SRC" "$IPS_DIR/src/regex.c" \
    -o "$CURRENT_BIN"

gcc -D_DEFAULT_SOURCE -O2 -Wall -Wextra -std=c11 \
    -DREGEX_LOAD_FN=regex_load_signatures \
    -DREGEX_UNLOAD_FN=regex_unload_signatures \
    -I"$OLD_INCLUDE_DIR" \
    "$BENCH_SRC" "$OLD_SRC" \
    -o "$OLD_BIN"

echo "[current]"
if "$CURRENT_BIN"; then
    echo "current: pass"
else
    echo "current: fail"
fi

echo "[old]"
if "$OLD_BIN"; then
    echo "old: pass"
else
    echo "old: fail"
fi
