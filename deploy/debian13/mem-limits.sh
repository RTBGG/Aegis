#!/usr/bin/env bash
# Print container memory limits sized as fractions of this host's total RAM, so
# caps scale with the server instead of being fixed absolute values. Values are
# Docker memory units; the Go GOMEMLIMIT is a soft heap target and is kept below
# the edge's hard cap.
#
# Non-Linux hosts (no /proc/meminfo) print nothing, letting compose fall back to
# its built-in defaults.
set -euo pipefail

[ -r /proc/meminfo ] || exit 0

total_kb=$(awk '/^MemTotal:/{print $2}' /proc/meminfo)
total_mb=$(( total_kb / 1024 ))

# pct <percent> <floor_mb> -> "<n>" clamped to the floor.
pct() {
  local v=$(( total_mb * $1 / 100 ))
  [ "$v" -lt "$2" ] && v=$2
  printf '%s' "$v"
}

printf 'CADDY_GOMEMLIMIT=%sMiB\n' "$(pct 30 512)"
printf 'CADDY_MEM_LIMIT=%sm\n'    "$(pct 40 768)"
printf 'CLICKHOUSE_MEM_LIMIT=%sm\n' "$(pct 30 512)"
