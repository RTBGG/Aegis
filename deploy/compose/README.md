# Modular compose files

These are the real service definitions, used by **both** deployment modes:

| File | Services |
|------|----------|
| `base.yml` | PostgreSQL, Redis, ClickHouse |
| `dns.yml` | PowerDNS (authoritative) |
| `control-plane.yml` | Go API + Next.js dashboard |
| `edge.yml` | node-agent + Caddy edge |
| `dev.yml` | demo origin + Mailpit (development only) |

The repository-root `docker-compose.yml` is **Mode A** and only `include`s these
files. For **Mode B** (independent components), remote edges, dependencies,
ports, persistence and mode-switching/migration instructions, see
[`docs/modular-deployment.md`](../../docs/modular-deployment.md).
