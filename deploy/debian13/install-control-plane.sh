#!/usr/bin/env bash
# Install the Aegis all-in-one stack on a fresh Debian 13 (trixie) host.
# Run from the repository root:  sudo bash deploy/debian13/install-control-plane.sh
set -euo pipefail

red(){ printf '\033[31m%s\033[0m\n' "$*"; }
grn(){ printf '\033[32m%s\033[0m\n' "$*"; }

[ "$(id -u)" -eq 0 ] || { red "Run as root (sudo)."; exit 1; }
[ -f docker-compose.yml ] || { red "Run from the repository root (docker-compose.yml not found)."; exit 1; }

if [ -r /etc/os-release ]; then . /etc/os-release; fi
if [ "${ID:-}" != "debian" ] || [ "${VERSION_ID:-}" != "13" ]; then
  red "This installer targets Debian 13 (trixie). Detected: ${PRETTY_NAME:-unknown}"
  red "Continuing anyway in 3s (Ctrl-C to abort)…"; sleep 3
fi

# --- Docker engine + compose plugin ---
if ! command -v docker >/dev/null 2>&1; then
  grn "Installing Docker…"
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get install -y ca-certificates curl gnupg openssl
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
  chmod a+r /etc/apt/keyrings/docker.asc
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian trixie stable" \
    > /etc/apt/sources.list.d/docker.list
  apt-get update -y
  apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
  systemctl enable --now docker
fi
grn "Docker $(docker --version)"

# --- .env with generated secrets ---
if [ ! -f .env ]; then
  grn "Generating .env with random secrets…"
  cp .env.example .env
  gen(){ openssl rand -hex 32; }
  set_kv(){ sed -i "s|^$1=.*|$1=$2|" .env; }
  set_kv SESSION_SECRET "$(gen)"
  set_kv CSRF_SECRET "$(gen)"
  set_kv CHALLENGE_SECRET "$(gen)"
  set_kv AGENT_TOKEN "$(gen)"
  set_kv PDNS_API_KEY "$(gen)"
  set_kv POSTGRES_PASSWORD "$(openssl rand -hex 16)"
  set_kv PDNS_DB_PASSWORD "$(openssl rand -hex 16)"
  set_kv BOOTSTRAP_ADMIN_PASSWORD "$(openssl rand -base64 18)"
  # Keep DATABASE_URL password in sync with POSTGRES_PASSWORD
  PGPW=$(grep '^POSTGRES_PASSWORD=' .env | cut -d= -f2-)
  PGUSER=$(grep '^POSTGRES_USER=' .env | cut -d= -f2-)
  PGDB=$(grep '^POSTGRES_DB=' .env | cut -d= -f2-)
  set_kv DATABASE_URL "postgres://${PGUSER}:${PGPW}@postgres:5432/${PGDB}?sslmode=disable"
  red "Admin password (save it):"; grep '^BOOTSTRAP_ADMIN_PASSWORD=' .env
fi

grn "Building and starting the stack…"
docker compose up -d --build

grn "Done. Dashboard: $(grep '^CONTROL_PLANE_URL=' .env | cut -d= -f2-)"
grn "Check status with: docker compose ps"
