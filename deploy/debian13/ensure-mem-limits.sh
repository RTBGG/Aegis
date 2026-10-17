#!/usr/bin/env bash
# Add host-RAM-relative memory limits to .env, but only when the keys are
# absent — so an operator's explicit overrides are never overwritten. Run by the
# installer, the updater, and `make up`. To re-size after a RAM upgrade, delete
# the CADDY_*/CLICKHOUSE_* limit lines from .env and re-run `make up`.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"
[ -f .env ] || exit 0

while IFS='=' read -r key val; do
  [ -n "$key" ] || continue
  grep -q "^${key}=" .env || printf '%s=%s\n' "$key" "$val" >> .env
done < <(bash deploy/debian13/mem-limits.sh)
