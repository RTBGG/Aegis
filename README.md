# Aegis

> Self-hosted, Cloudflare-style edge platform: per-domain DNS, a reverse proxy with automatic TLS, WAF (Coraza + OWASP CRS), rate-limiting, and bot/DDoS protection — managed from a multi-tenant dashboard.

**Aegis** lets you point a domain's nameservers at your own infrastructure and flip a
per-record "proxy" switch to route traffic through an edge that adds automatic SSL/TLS
and HTTP→HTTPS, a Web Application Firewall (OWASP Core Rule Set via Coraza), customizable
rate-limiting, JA4(H) fingerprinting, proof-of-work bot challenges, caching, and
health-checked origin load-balancing. A Go control plane (PostgreSQL source of truth)
drives PowerDNS for authoritative DNS and renders config to a Caddy data plane via a
lightweight node-agent. Deploys all-in-one on Debian 13 with Docker Compose.

> ⚠️ **Phase 1 — Foundation + Security stack** (this repo). Multi-node edge enrollment,
> per-node mTLS, and ClickHouse analytics are designed and land in Phases 2–3. See
> `docs/architecture.md`.

**Topics:** `waf` · `reverse-proxy` · `dns` · `cloudflare-alternative` · `coraza` · `owasp-crs` · `caddy` · `powerdns` · `ddos-protection` · `bot-detection` · `self-hosted` · `golang` · `nextjs`

## Architecture (3 planes)

| Plane | Components |
|-------|-----------|
| **Control plane** | Go API (`control-plane/`) + Next.js dashboard (`dashboard/`), PostgreSQL (truth), Redis |
| **DNS plane** | PowerDNS Authoritative (driven via its HTTP API) |
| **Data plane (edge)** | Caddy + Coraza/CRS + Souin cache + rate-limit + threat-feed IP blocklist + custom `ja4`/`botscore`/`challenge` modules (`edge/`), plus a `node-agent` (`node-agent/`) |

The control plane is the source of truth. It renders a **Caddyfile bundle**
per edge; the `node-agent` pulls it (long-poll over HTTP, push-triggered via
Redis), writes it, and runs `caddy reload` through Caddy's admin API.

```
visitor ──DNS──> PowerDNS (returns edge IP for proxied records)
visitor ──TLS──> Caddy edge: nftables(L3/4) → ja4 → rate_limit → botscore
                  → challenge → coraza(CRS) → cache → reverse_proxy → origin
```

## Quickstart (all-in-one, Debian 13 or any Docker host)

```bash
cp .env.example .env          # then edit the secrets
make up                       # docker compose up -d --build
make ps                       # wait for healthy
```

Open the dashboard at `CONTROL_PLANE_URL` (default `https://cp.localtest.me`,
which resolves to 127.0.0.1). Log in with `BOOTSTRAP_ADMIN_*` from `.env`.

On a fresh Debian 13 box, `deploy/debian13/install-control-plane.sh` installs
Docker + compose and brings the stack up. See `docs/runbook-debian13.md`.

## Local compile checks (no Docker)

Toolchains can live in userspace:
```bash
export PATH="$HOME/.local/go/bin:$HOME/.local/node/bin:$HOME/go/bin:$PATH"
make build      # compiles control-plane, node-agent, edge modules, dashboard
make test
```

## Layout

```
control-plane/   Go API: auth, domains, dns, security, config, admin, store
node-agent/      Go agent: config sync + apply to Caddy + telemetry
edge/            Custom Caddy modules: ja4 (JA4H), botscore, challenge (PoW)
dashboard/       Next.js + TS + Tailwind dashboard & admin
deploy/          Caddy xcaddy build, docker-compose, Debian 13 scripts, nftables
docs/            architecture, threat model, runbook
```

## Security note

Aegis is **defensive** infrastructure (WAF, rate-limiting, bot/DDoS protection
for sites you operate or host). The edge-enrollment mechanism performs
intentional remote provisioning and ships with single-use signed tokens,
TLS-pinned bootstrap, and mTLS post-enrollment. See `docs/threat-model.md`.
