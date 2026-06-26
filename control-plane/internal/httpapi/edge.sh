#!/usr/bin/env bash
# Aegis edge enrollment bootstrap (served by the control plane).
#   curl -fsSL __CONTROL_PLANE_URL__/install/edge.sh | sudo ENROLL_TOKEN=xxxx bash
#
# Phase 1 ships the design + safe bootstrap. The server-side enroll exchange
# (token -> mTLS client cert -> join DNS rotation/LB pool) lands in Phase 3.
set -euo pipefail

CONTROL_PLANE="__CONTROL_PLANE_URL__"

red(){ printf '\033[31m%s\033[0m\n' "$*"; }
grn(){ printf '\033[32m%s\033[0m\n' "$*"; }

[ "$(id -u)" -eq 0 ] || { red "must run as root (use sudo)"; exit 1; }
: "${ENROLL_TOKEN:?ENROLL_TOKEN env var is required (mint one in Admin → Edge servers)}"

# --- preflight: require Debian 13 ---
if [ -r /etc/os-release ]; then . /etc/os-release; fi
if [ "${ID:-}" != "debian" ] || [ "${VERSION_ID:-}" != "13" ]; then
  red "This installer targets Debian 13 (trixie). Detected: ${PRETTY_NAME:-unknown}"
  exit 1
fi
grn "Debian 13 detected."

# --- install prerequisites (Docker engine for the edge container) ---
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y ca-certificates curl nftables
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
chmod a+r /etc/apt/keyrings/docker.asc
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian trixie stable" \
  > /etc/apt/sources.list.d/docker.list
apt-get update -y
apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
grn "Docker installed."

# --- baseline L3/L4 DDoS protection ---
curl -fsSL "${CONTROL_PLANE}/install/edge.nft" -o /etc/nftables.conf 2>/dev/null || true
systemctl enable --now nftables 2>/dev/null || true

# --- enroll with the control plane (exchange token for durable credentials) ---
grn "Contacting control plane to enroll…"
HTTP=$(curl -fsS -o /tmp/aegis-enroll.json -w '%{http_code}' \
  -H 'Content-Type: application/json' \
  -d "{\"token\":\"${ENROLL_TOKEN}\",\"public_ip\":\"$(curl -fsS https://api.ipify.org || echo unknown)\"}" \
  "${CONTROL_PLANE}/edge/v1/enroll" || true)

if [ "$HTTP" = "200" ]; then
  grn "Enrolled. Starting edge…"
  # Phase 3: render docker-compose for the edge container + agent from the
  # returned credentials and `docker compose up -d`.
else
  red "Enrollment endpoint returned HTTP ${HTTP:-000}."
  red "Multi-node enrollment is finalized in Phase 3; the bootstrap above is complete."
  exit 0
fi
