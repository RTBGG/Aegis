#!/usr/bin/env bash
# Install the Aegis all-in-one stack on a fresh Debian 13 (trixie) host.
# Run from the repository root:  sudo bash deploy/debian13/install-control-plane.sh
set -euo pipefail

red(){ printf '\033[31m%s\033[0m\n' "$*"; }
grn(){ printf '\033[32m%s\033[0m\n' "$*"; }
ylw(){ printf '\033[33m%s\033[0m\n' "$*"; }

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
  # Domain the dashboard/API is served on (replaces the cp.localtest.me default).
  # Override non-interactively with AEGIS_DOMAIN=… (and optionally AEGIS_ACME_EMAIL=…).
  DEFAULT_DOMAIN="cp.localtest.me"
  DOMAIN="${AEGIS_DOMAIN:-}"
  if [ -z "$DOMAIN" ] && [ -t 0 ]; then
    printf 'Domain for the Aegis dashboard/API (must resolve to this host) [%s]: ' "$DEFAULT_DOMAIN"
    read -r DOMAIN || true
  fi
  DOMAIN="$(printf '%s' "${DOMAIN:-$DEFAULT_DOMAIN}" | tr 'A-Z' 'a-z' | tr -d '[:space:]')"
  if ! printf '%s' "$DOMAIN" | grep -qE '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$'; then
    red "'${DOMAIN}' is not a valid domain; using ${DEFAULT_DOMAIN}."
    DOMAIN="$DEFAULT_DOMAIN"
  fi

  grn "Generating .env with random secrets for https://${DOMAIN} …"
  cp .env.example .env
  gen(){ openssl rand -hex 32; }
  set_kv(){ sed -i "s|^$1=.*|$1=$2|" .env; }

  # Point every dashboard/API URL at the chosen domain.
  set_kv CONTROL_PLANE_URL "https://${DOMAIN}"
  set_kv DASHBOARD_URL "https://${DOMAIN}"
  set_kv CONTROL_PLANE_HOST "${DOMAIN}"
  set_kv NEXT_PUBLIC_API_URL "https://${DOMAIN}"

  # A real (non-localtest) domain gets a trusted cert via ACME/Let's Encrypt;
  # localtest.me / localhost keep the self-signed internal CA (no public DNS).
  case "$DOMAIN" in
    *.localtest.me | localhost)
      grn "TLS: self-signed internal CA (fine for ${DOMAIN})." ;;
    *)
      ACME_EMAIL_DEF="admin@${DOMAIN}"
      ACME_EMAIL="${AEGIS_ACME_EMAIL:-}"
      if [ -z "$ACME_EMAIL" ] && [ -t 0 ]; then
        printf "Email for ACME/Let's Encrypt certificates [%s]: " "$ACME_EMAIL_DEF"
        read -r ACME_EMAIL || true
      fi
      ACME_EMAIL="${ACME_EMAIL:-$ACME_EMAIL_DEF}"
      set_kv EDGE_TLS_MODE "acme"
      set_kv ACME_EMAIL "$ACME_EMAIL"
      set_kv CP_TLS "$ACME_EMAIL"
      grn "TLS: ACME (Let's Encrypt) for ${DOMAIN}. Point ${DOMAIN} at this host and open ports 80/443." ;;
  esac

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

# --- L3/L4 firewall (nftables), Docker-safe ---
# Adds a per-source SYN-flood/volumetric cap on 80/443 plus a control-plane
# blackhole set, without flushing Docker's rules. Skip with AEGIS_SKIP_NFTABLES=1.
if [ "${AEGIS_SKIP_NFTABLES:-}" = "1" ]; then
  ylw "AEGIS_SKIP_NFTABLES=1 — skipping firewall setup."
elif [ -f deploy/debian13/nftables/allinone.nft ]; then
  grn "Applying L3/L4 firewall (nftables)…"
  apt-get install -y nftables >/dev/null 2>&1 || true
  install -m 0644 deploy/debian13/nftables/allinone.nft /etc/nftables.conf
  if systemctl enable --now nftables >/dev/null 2>&1 && nft -f /etc/nftables.conf 2>/dev/null; then
    grn "Firewall active (per-source cap on 80/443; drop set 'aegis blackhole')."
  else
    ylw "Could not enable nftables automatically; review /etc/nftables.conf and run: nft -f /etc/nftables.conf"
  fi

  # L3 auto-blackhole: a host-side timer syncs the control plane's auto-ban list
  # (IPs the edge banned during a flood) into the nftables 'aegis' blackhole set.
  grn "Installing L3 auto-blackhole sync…"
  install -m 0755 deploy/debian13/blackhole-sync.sh /usr/local/bin/aegis-blackhole-sync
  ( umask 077; cat > /etc/default/aegis-blackhole <<EOF
AEGIS_BLACKHOLE_URL=http://127.0.0.1:8080/edge/v1/blackhole
AEGIS_AGENT_TOKEN=$(grep '^AGENT_TOKEN=' .env | cut -d= -f2-)
EOF
  )
  install -m 0644 deploy/debian13/systemd/aegis-blackhole.service /etc/systemd/system/aegis-blackhole.service
  install -m 0644 deploy/debian13/systemd/aegis-blackhole.timer /etc/systemd/system/aegis-blackhole.timer
  systemctl daemon-reload
  systemctl enable --now aegis-blackhole.timer >/dev/null 2>&1 \
    && grn "L3 auto-blackhole active (aegis-blackhole.timer, every 30s)." \
    || ylw "Could not enable aegis-blackhole.timer; enable it manually."
fi

grn "Done. Dashboard: $(grep '^CONTROL_PLANE_URL=' .env | cut -d= -f2-)"
grn "Check status with: docker compose ps"
