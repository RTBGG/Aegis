#!/usr/bin/env bash
# Validate the all-in-one and modular Compose configurations without starting
# anything. Requires the Docker Compose plugin (>= 2.20 for `include`).
#
# Run from anywhere:  bash deploy/compose/validate.sh
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"

# `docker compose config` interpolates ${...} from .env; provide the example on
# a fresh checkout so the check works in CI (these are placeholders, not secrets).
[ -f .env ] || cp .env.example .env

COMMON=(--project-name aegis --env-file "$root/.env")
BASE=(-f deploy/compose/base.yml)
DNS=(-f deploy/compose/dns.yml)
CP=(-f deploy/compose/control-plane.yml)
EDGE=(-f deploy/compose/edge.yml)

check() {
  local label=$1; shift
  echo "==> ${label}"
  docker compose "${COMMON[@]}" "$@" config -q
}

check "all-in-one (Mode A)" -f docker-compose.yml
check "base infrastructure only" "${BASE[@]}"
check "DNS plane (base + dns)" "${BASE[@]}" "${DNS[@]}"
check "control plane (base + dns + control-plane)" "${BASE[@]}" "${DNS[@]}" "${CP[@]}"
check "full modular stack (base + dns + control-plane + edge)" "${BASE[@]}" "${DNS[@]}" "${CP[@]}" "${EDGE[@]}"

echo "OK: all compose configurations are valid"
