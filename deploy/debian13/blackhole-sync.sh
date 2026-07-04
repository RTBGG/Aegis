#!/usr/bin/env bash
# Aegis — sync the control plane's auto-ban list into the host nftables 'aegis'
# blackhole set (true L3 drop). The edge auto-bans confirmed flooders at L7 and
# records them; this runs on the host (where it can touch nftables) to escalate
# them to a kernel-level drop. Invoked periodically by aegis-blackhole.timer.
#
# Config (via /etc/default/aegis-blackhole):
#   AEGIS_BLACKHOLE_URL  control-plane endpoint (default localhost api port)
#   AEGIS_AGENT_TOKEN    shared agent token for /edge/v1 auth
set -euo pipefail

URL="${AEGIS_BLACKHOLE_URL:-http://127.0.0.1:8080/edge/v1/blackhole}"
TOKEN="${AEGIS_AGENT_TOKEN:-}"

# No firewall / set present -> nothing to do.
command -v nft >/dev/null 2>&1 || exit 0
nft list set inet aegis blackhole >/dev/null 2>&1 || exit 0

hdr=()
[ -n "$TOKEN" ] && hdr=(-H "Authorization: Bearer ${TOKEN}")
list="$(curl -fsS --max-time 5 "${hdr[@]}" "$URL" 2>/dev/null || true)"

# Keep only well-formed addresses (defence in depth against injection into nft).
v4="$(printf '%s\n' "$list" | grep -E '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' || true)"
v6="$(printf '%s\n' "$list" | grep -E '^[0-9a-fA-F:]+$' || true)"

# Atomically replace the set contents: flush, then re-add the current list.
rules="flush set inet aegis blackhole
flush set inet aegis blackhole6"
if [ -n "$v4" ]; then rules+=$'\n'"add element inet aegis blackhole { $(paste -sd, <<<"$v4") }"; fi
if [ -n "$v6" ]; then rules+=$'\n'"add element inet aegis blackhole6 { $(paste -sd, <<<"$v6") }"; fi

printf '%s\n' "$rules" | nft -f - 2>/dev/null || true
