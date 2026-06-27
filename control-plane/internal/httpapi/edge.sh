#!/usr/bin/env bash
# Aegis edge enrollment bootstrap (served by the control plane).
#   curl -fsSL __CONTROL_PLANE_URL__/install/edge.sh | sudo ENROLL_TOKEN=xxxx bash
#
# Preflights the host, installs Docker, exchanges the single-use ENROLL_TOKEN for
# a durable per-node agent token, writes the edge config, and starts the edge.
set -euo pipefail

CONTROL_PLANE="__CONTROL_PLANE_URL__"
EDGE_IMAGE="${AEGIS_EDGE_IMAGE:-ghcr.io/rtbgg/aegis-edge:latest}"
CONF_DIR="/etc/aegis"

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
if ! command -v docker >/dev/null 2>&1; then
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
  chmod a+r /etc/apt/keyrings/docker.asc
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian trixie stable" \
    > /etc/apt/sources.list.d/docker.list
  apt-get update -y
  apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
fi
grn "Docker ready."

# --- baseline L3/L4 DDoS protection ---
curl -fsSL "${CONTROL_PLANE}/install/edge.nft" -o /etc/nftables.conf 2>/dev/null \
  && systemctl enable --now nftables 2>/dev/null || true

# --- enroll: exchange the single-use token for a durable per-node agent token ---
grn "Contacting control plane to enroll…"
PUBLIC_IP="$(curl -fsS https://api.ipify.org || true)"
[ -n "$PUBLIC_IP" ] || { red "could not determine this host's public IP"; exit 1; }

HTTP=$(curl -fsS -o /tmp/aegis-enroll.json -w '%{http_code}' \
  -H 'Content-Type: application/json' \
  -d "{\"token\":\"${ENROLL_TOKEN}\",\"name\":\"$(hostname -s)\",\"public_ip\":\"${PUBLIC_IP}\"}" \
  "${CONTROL_PLANE}/edge/v1/enroll" || true)
if [ "$HTTP" != "200" ]; then
  red "Enrollment failed (HTTP ${HTTP:-000}): $(cat /tmp/aegis-enroll.json 2>/dev/null)"
  exit 1
fi

jget(){ sed -n "s/.*\"$1\":\"\([^\"]*\)\".*/\1/p" /tmp/aegis-enroll.json; }
AGENT_TOKEN="$(jget agent_token)"
EDGE_NAME="$(jget name)"
CHALLENGE_SECRET="$(jget challenge_secret)"
[ -n "$AGENT_TOKEN" ] || { red "enroll response missing agent_token"; exit 1; }
rm -f /tmp/aegis-enroll.json
grn "Enrolled as '${EDGE_NAME}'."

# --- write edge config + compose, then start ---
mkdir -p "$CONF_DIR"
umask 077
cat > "${CONF_DIR}/edge.env" <<EOF
CONTROL_PLANE_URL=${CONTROL_PLANE}
AGENT_TOKEN=${AGENT_TOKEN}
EDGE_NAME=${EDGE_NAME}
EDGE_PUBLIC_IP=${PUBLIC_IP}
CHALLENGE_SECRET=${CHALLENGE_SECRET}
AEGIS_REDIS=redis:6379
EDGE_TLS_MODE=acme
ACME_EMAIL=${ACME_EMAIL:-admin@${EDGE_NAME}}
EOF

cat > "${CONF_DIR}/docker-compose.yml" <<EOF
name: aegis-edge
services:
  redis:
    image: redis:7-alpine
    command: ["redis-server","--save","","--appendonly","no"]
    restart: unless-stopped
  edge:
    image: ${EDGE_IMAGE}
    env_file: ${CONF_DIR}/edge.env
    depends_on: [redis]
    ports: ["80:80","443:443"]
    volumes:
      - caddydata:/data
      - caddyconfig:/config
    restart: unless-stopped
volumes:
  caddydata:
  caddyconfig:
EOF

grn "Starting edge…"
docker compose -f "${CONF_DIR}/docker-compose.yml" up -d
grn "Done. This node will appear in Admin → Edge servers and join the DNS rotation once healthy."
