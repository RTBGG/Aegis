# Deployment modes: all-in-one (A) and modular (B)

Aegis has **one implementation** and **two deployment topologies**. The service
definitions live in `deploy/compose/*.yml`; the all-in-one entrypoint simply
includes them, so fixes and features are identical in both modes.

| | Mode A — all-in-one | Mode B — modular |
|---|---|---|
| Entrypoint | `docker-compose.yml` (includes all modules) | pick the `deploy/compose/*.yml` files you need |
| Best for | single-host installs, demos, getting started | separate hosts, independent updates, minimal installs |
| Command | `make up` / `docker compose up -d --build` | `make up-modular` or explicit `-f` files (below) |
| Dev extras | included (`dev.yml`) | not included |

Both modes use the **same Docker project name (`aegis`) and volumes**, so you can
switch between them without losing data.

> Requires Docker Compose **v2.20+** (the all-in-one file uses `include`). The
> Debian installer ships a current Compose plugin.

## Components and boundaries

| Compose file | Services | Responsibility | Depends on | Published ports |
|---|---|---|---|---|
| `base.yml` | `postgres`, `redis`, `clickhouse` | stateful infrastructure (truth, sessions/pubsub, analytics) | — | internal only |
| `dns.yml` | `powerdns` | authoritative DNS (gpgsql + GeoIP) | `base` | `53/udp`, `53/tcp` |
| `control-plane.yml` | `api`, `dashboard` | Go API + Next.js UI | `base`, `dns` | `8080` (API), `8443` (edge mTLS), `3000` (dashboard) |
| `edge.yml` | `caddy-edge` | node-agent + Caddy (JA4, rate-limit, WAF, challenge, cache, proxy) | `base`, `control-plane` | `80`, `443` |
| `dev.yml` | `demo-origin`, `mailpit` | demo origin + dev mail catcher | — | `8025` |

The edge and dashboard are served to end users through the edge on ports 80/443;
`api:8080`, `dashboard:3000`, PowerDNS `:8081`, Postgres/Redis/ClickHouse are
internal to the compose network (do not expose them publicly).

Persistence (named volumes): `pgdata` (Postgres, including the PowerDNS
`gpgsql` database), `chdata` (ClickHouse), `caddydata`/`caddyconfig` (edge
certificates + Caddy state). Secrets and tunables live in `.env` only.

## Mode A — all-in-one

```bash
cp .env.example .env      # edit secrets
make up                   # docker compose up -d --build
make ps
```

`Dockerfile`-level components are built by Compose. The Debian installer
(`deploy/debian13/install-control-plane.sh`) and updater (`update.sh`) use this
same entrypoint, so existing installs need no migration.

## Mode B — modular

Run from the repository root. Always pass the same project name and `.env` so
volumes and configuration match Mode A. Start each layer in order:

```bash
# 1. shared infrastructure
docker compose -p aegis --env-file "$PWD/.env" -f deploy/compose/base.yml up -d

# 2. DNS plane
docker compose -p aegis --env-file "$PWD/.env" \
  -f deploy/compose/base.yml -f deploy/compose/dns.yml up -d

# 3. control plane (API + dashboard)
docker compose -p aegis --env-file "$PWD/.env" \
  -f deploy/compose/base.yml -f deploy/compose/dns.yml \
  -f deploy/compose/control-plane.yml up -d --build

# 4. edge (same host / same compose network)
docker compose -p aegis --env-file "$PWD/.env" \
  -f deploy/compose/base.yml -f deploy/compose/dns.yml \
  -f deploy/compose/control-plane.yml -f deploy/compose/edge.yml up -d --build
```

`make up-modular` runs step 4 (all modular layers, no dev extras).
`make down-modular` stops them (volumes are kept).

Rebuild only one component without touching the rest, e.g. the dashboard:

```bash
docker compose -p aegis --env-file "$PWD/.env" \
  -f deploy/compose/base.yml -f deploy/compose/dns.yml \
  -f deploy/compose/control-plane.yml up -d --build --no-deps dashboard
```

### Remote edges (separate host)

For an edge on another machine, do **not** use `edge.yml`; use the enrollment
flow (Admin → Edge servers). The served script
(`<CONTROL_PLANE_URL>/install/edge.sh`) exchanges a single-use token for a
per-node agent token, writes per-node mTLS certificates, installs nftables, and
runs the edge. It dials the control plane over the mTLS endpoint (`:8443`).
The `edge.yml` overrides `EDGE_CONTROL_PLANE_URL`, `EDGE_REDIS_ADDR`,
`EDGE_CERT_FILE`, `EDGE_KEY_FILE`, `EDGE_CA_FILE` for advanced same-network
setups.

### Validate configurations

```bash
make compose-check            # or: bash deploy/compose/validate.sh
```

This runs `docker compose config -q` for the all-in-one stack and for each
modular combination (base, base+dns, +control-plane, +edge) without starting
anything.

## Switching modes

Both modes share the project name `aegis` and the same volumes:

```bash
make down           # stop Mode A (volumes kept)
make up-modular     # start Mode B using the same .env and data
# ... later ...
make down-modular
make up
```

Remote edges keep serving and reconnect automatically; no data is lost. If you
switch modes on a host that also runs the edge, expect a brief interruption
while containers are recreated.

## Migrating an existing install

The all-in-one entrypoint and installer are unchanged, so an existing deployment
is already "Mode A":

1. `git pull` and `make update` (or `deploy/debian13/update.sh`).
2. Migration `0010_dns_mode` adds `domains.dns_mode` with default `'ns'`; no
   existing domain changes behaviour and no data is removed.
3. To run modularly, stop the stack and start the desired `deploy/compose/*.yml`
   combination with `-p aegis` (above). Your `.env`, Postgres/ClickHouse data and
   edge certificates are reused because the project name and volumes match.

## Configuration

- **Single source of truth**: `.env` (see `.env.example`). Compose interpolates
  it; the API also reads it via `env_file`. Do not add a second config file.
- **CNAME domains**: set `CNAME_TARGET` to the hostname users point CNAMEs at
  (defaults to the control-plane host). See `docs/cname-domains.md`.
- **Memory limits**: `deploy/debian13/mem-limits.sh` derives
  `CADDY_*`/`CLICKHOUSE_MEM_LIMIT` from host RAM; the installer, updater and
  `make up`/`make up-modular` fill them in if missing.
- **Edge mTLS** (remote edges): `EDGE_CERT_FILE`, `EDGE_KEY_FILE`,
  `EDGE_CA_FILE`; the enrollment script writes them to `/etc/aegis`.
