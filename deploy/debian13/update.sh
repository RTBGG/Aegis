#!/usr/bin/env bash
# Update an existing Aegis all-in-one deployment in place.
# Run from the repository root:  sudo bash deploy/debian13/update.sh
#
# Steps: git pull (fast-forward) -> back up Postgres -> warn about new
# .env.example keys -> rebuild & restart the stack. Database migrations run
# automatically when the api container starts. Your .env and the data volumes
# (Postgres, ClickHouse, Caddy certs) are preserved.
#
# Env toggles:
#   AEGIS_SKIP_PULL=1        leave the git checkout as-is (you manage it yourself)
#   AEGIS_SKIP_BACKUP=1      don't pg_dump before rebuilding
#   AEGIS_BACKUP_DIR=<dir>   where to write the DB dump (default: ./backups)
set -euo pipefail

red(){ printf '\033[31m%s\033[0m\n' "$*"; }
grn(){ printf '\033[32m%s\033[0m\n' "$*"; }
ylw(){ printf '\033[33m%s\033[0m\n' "$*"; }

[ -f docker-compose.yml ] || { red "Run from the repository root (docker-compose.yml not found)."; exit 1; }
[ -f .env ] || { red ".env not found — nothing to update. Use install-control-plane.sh on a fresh host."; exit 1; }
command -v docker >/dev/null 2>&1 || { red "docker not found."; exit 1; }

# --- 1. Pull the new code --------------------------------------------------
OLD_REV="$(git rev-parse HEAD 2>/dev/null || echo '')"
if [ "${AEGIS_SKIP_PULL:-}" = "1" ]; then
  ylw "AEGIS_SKIP_PULL=1 — leaving the checkout as-is."
elif [ -z "$OLD_REV" ]; then
  ylw "Not a git checkout — skipping pull (rebuilding the current tree)."
else
  # Running as root over a repo owned by another user trips git's ownership guard.
  if [ "$(id -u)" = 0 ]; then
    here="$(pwd)"
    git config --global --get-all safe.directory 2>/dev/null | grep -qxF "$here" \
      || git config --global --add safe.directory "$here"
  fi
  grn "Pulling latest code…"
  if ! git pull --ff-only; then
    red "git pull failed (local changes or a diverged branch). Resolve it, or set"
    red "AEGIS_SKIP_PULL=1 to rebuild the current checkout without pulling."
    exit 1
  fi
fi
NEW_REV="$(git rev-parse HEAD 2>/dev/null || echo '')"

if [ -n "$OLD_REV" ] && [ -n "$NEW_REV" ] && [ "$OLD_REV" != "$NEW_REV" ]; then
  grn "Updating ${OLD_REV:0:9} -> ${NEW_REV:0:9}:"
  git --no-pager log --oneline "$OLD_REV..$NEW_REV" | sed 's/^/  /'
elif [ "${AEGIS_SKIP_PULL:-}" != "1" ] && [ -n "$OLD_REV" ]; then
  grn "Already at the latest commit — rebuilding to apply any local/image changes."
fi

# --- 2. Warn about new .env keys ------------------------------------------
# Uncommented keys present in .env.example but not set in your .env.
NEWKEYS="$(comm -23 \
  <(grep -oE '^[A-Za-z_][A-Za-z0-9_]*=' .env.example | sort -u) \
  <(grep -oE '^[A-Za-z_][A-Za-z0-9_]*=' .env         | sort -u) || true)"
if [ -n "$NEWKEYS" ]; then
  ylw "New settings exist in .env.example that your .env doesn't set:"
  printf '%s\n' "$NEWKEYS" | sed 's/=$//; s/^/  - /'
  ylw "They fall back to built-in defaults; add any you want to .env and re-run."
fi

# --- 3. Back up Postgres ---------------------------------------------------
if [ "${AEGIS_SKIP_BACKUP:-}" = "1" ]; then
  ylw "AEGIS_SKIP_BACKUP=1 — skipping DB backup."
elif docker compose ps postgres 2>/dev/null | grep -qiE '\b(up|running)\b'; then
  BDIR="${AEGIS_BACKUP_DIR:-backups}"; mkdir -p "$BDIR"
  PGUSER="$(grep -E '^POSTGRES_USER=' .env | cut -d= -f2-)"; PGUSER="${PGUSER:-aegis}"
  PGDB="$(grep -E '^POSTGRES_DB=' .env | cut -d= -f2-)"; PGDB="${PGDB:-aegis}"
  OUT="$BDIR/aegis-db-$(date +%Y%m%d-%H%M%S).sql"
  grn "Backing up database '$PGDB' -> $OUT …"
  if docker compose exec -T postgres pg_dump -U "$PGUSER" "$PGDB" > "$OUT"; then
    grn "Backup written ($(wc -c < "$OUT" | tr -d ' ') bytes)."
  else
    rm -f "$OUT"
    red "pg_dump failed. Fix it, or set AEGIS_SKIP_BACKUP=1 to update without a backup."
    exit 1
  fi
else
  ylw "Postgres isn't running — nothing to back up (skipping)."
fi

# --- 4. Rebuild + restart --------------------------------------------------
grn "Rebuilding and restarting the stack (migrations run on api start)…"
docker compose up -d --build

grn "Waiting for the API to become healthy…"
for _ in $(seq 1 40); do
  case "$(docker compose ps api --format '{{.Status}}' 2>/dev/null || true)" in
    *healthy*) break ;;
  esac
  sleep 3
done
docker compose ps
grn "Update complete. Dashboard: $(grep -E '^CONTROL_PLANE_URL=' .env | cut -d= -f2-)"
