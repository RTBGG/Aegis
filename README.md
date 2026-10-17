# Aegis

> Self-hosted, Cloudflare-style edge platform: per-domain DNS, a reverse proxy with automatic TLS, WAF (Coraza + OWASP CRS), rate-limiting, and bot/DDoS protection — managed from a multi-tenant dashboard.

**Aegis** lets you point a domain's nameservers at your own infrastructure and flip a
per-record "proxy" switch to route traffic through an edge that adds automatic SSL/TLS
and HTTP→HTTPS, a Web Application Firewall (OWASP Core Rule Set via Coraza), customizable
rate-limiting, JA4(H) fingerprinting, proof-of-work bot challenges, caching, and
health-checked origin load-balancing. A Go control plane (PostgreSQL source of truth)
drives PowerDNS for authoritative DNS and renders config to a Caddy data plane via a
lightweight node-agent. Deploys all-in-one on Debian 13 with Docker Compose.

> **Status:** Phase 1 (foundation + security stack) and Phase 2 (depth) are complete;
> Phase 3 (scale-out) is well underway. Built: threat-feed auto-blocklists, DNSSEC,
> audited impersonation, real SMTP, per-route WAF tuning + custom SecRules, richer bot
> scoring + managed/CAPTCHA challenges, per-domain Under Attack Mode (challenge every
> visitor), and ClickHouse per-request analytics with GeoIP country/ASN breakdowns plus a
> live per-second traffic view. For multi-node: copy-paste edge enrollment, per-node mTLS
> with automatic cert rotation + revocation, and weighted + GeoDNS edge distribution.
> **Remaining:** HA control plane, signed artifact distribution, optional anycast/BGP;
> billing/quotas is intentionally deferred (the platform is free for now).
> See `docs/plan.md` and `docs/architecture.md`.

**Topics:** `waf` · `reverse-proxy` · `dns` · `cloudflare-alternative` · `coraza` · `owasp-crs` · `caddy` · `powerdns` · `ddos-protection` · `bot-detection` · `self-hosted` · `golang` · `nextjs`

## Architecture (3 planes)

| Plane | Components |
|-------|-----------|
| **Control plane** | Go API (`control-plane/`) + Next.js dashboard (`dashboard/`), PostgreSQL (truth), Redis, ClickHouse (per-request analytics), an internal ECDSA CA for edge mTLS |
| **DNS plane** | PowerDNS Authoritative (driven via its HTTP API): per-domain records, DNSSEC, and weighted + GeoDNS edge distribution via client-subnet-aware Lua records |
| **Data plane (edge)** | Caddy + Coraza/CRS + Souin cache + rate-limit + threat-feed IP blocklist + custom `ja4`/`botscore`/`challenge` modules (`edge/`), plus a `node-agent` (`node-agent/`). A single all-in-one node or a fleet of mTLS-enrolled edges. |

The control plane is the source of truth. It renders a **Caddyfile bundle**
per edge; the `node-agent` pulls it (long-poll over HTTP, push-triggered via
Redis), writes it, and runs `caddy reload` through Caddy's admin API.

```
visitor ──DNS──> PowerDNS (returns edge IP for proxied records)
visitor ──TLS──> host nftables (L3/4) → Caddy edge:
                  ja4 → rate_limit → coraza(CRS) → botscore → challenge → cache
                  → reverse_proxy → origin
```

## Features

**Edge / traffic security**
- Automatic TLS (Caddy internal CA for local testing, ACME/Let's Encrypt for real
  domains) + HTTP→HTTPS redirect
- WAF: Coraza + OWASP Core Rule Set, per-domain paranoia level & block/detect mode,
  per-route overrides, and custom SecLang rules (validated against an allowlist)
- Per-IP rate limiting, JA4(H) TLS/HTTP fingerprinting
- Bot scoring with a proof-of-work managed challenge or pluggable CAPTCHA
  (Cloudflare Turnstile / hCaptcha / reCAPTCHA), plus a verified-search-bot allowlist
- Per-domain **Under Attack Mode**: challenge every uncleared visitor (Cloudflare-style),
  while normal mode only challenges traffic the bot scorer flags
- Auto-ban of IPs that repeatedly fail the challenge, escalated to a host-level nftables
  blackhole (L3 drop) with automatic expiry
- Threat-feed IP blocklists (Spamhaus DROP, FireHOL L1) enforced at the edge
- Edge caching (Souin) and health-checked origin load-balancing

**DNS**
- Authoritative per-domain DNS with a per-record "proxy" toggle
- One-click DNSSEC (publish the generated DS record at your registrar)
- Weighted edge distribution and GeoDNS by client location (continent), client-subnet aware

**Dashboard & control plane**
- Multi-tenant accounts, users, domains, DNS records, and per-domain security policy
- Per-request analytics (ClickHouse): traffic, unique visitors, top paths, status
  codes, and top countries / networks (ASN) — falls back to coarse counters without it
- Live traffic view: per-second total / passed / blocked requests for the last two
  minutes, refreshed every few seconds
- Admin: user management, audited impersonation, threat-feed control, SMTP email
  config + test send, and edge-fleet management (weights, regions, revocation)
- Domain onboarding shows delegation nameservers + a TXT record, re-viewable any time

**Multi-node (Phase 3)**
- Copy-paste edge enrollment via a single-use signed token with TLS-pinned bootstrap
- Per-node mTLS with automatic certificate rotation and revocation
- Add/drain edges by weight and continent; DNS reconciles the pool automatically

## Quickstart (all-in-one, Debian 13 or any Docker host)

```bash
cp .env.example .env          # then edit the secrets
make up                       # docker compose up -d --build
make ps                       # wait for healthy
```

Open the dashboard at `CONTROL_PLANE_URL` (default `https://cp.localtest.me`,
which resolves to 127.0.0.1). Log in with `BOOTSTRAP_ADMIN_*` from `.env`.

On a fresh Debian 13 box, `deploy/debian13/install-control-plane.sh` installs
Docker + compose, **prompts for the domain** to serve the dashboard/API on
(defaulting to `cp.localtest.me`, switching a real domain to ACME/Let's Encrypt),
generates secrets, brings the stack up, and applies the host L3 firewall
(per-source flood cap) plus the auto-blackhole sync timer. See `docs/runbook-debian13.md`.

## Local compile checks (no Docker)

Toolchains can live in userspace:
```bash
export PATH="$HOME/.local/go/bin:$HOME/.local/node/bin:$HOME/go/bin:$PATH"
make build      # compiles control-plane, node-agent, edge modules, dashboard
make test
```

## Layout

```
control-plane/   Go API: auth, domains, dns, security, config, admin, store,
                 analytics (clickhouse/geoip), threatfeed, mailer, pki (edge CA)
node-agent/      Go agent: config sync + apply to Caddy + telemetry, mTLS + cert renewal
edge/            Custom Caddy modules: ja4 (JA4H), botscore, challenge (PoW/CAPTCHA)
dashboard/       Next.js + TS + Tailwind dashboard & admin
deploy/          Caddy xcaddy build, PowerDNS (gpgsql+geoip) image, docker-compose,
                 Debian 13 install + edge-enrollment scripts, nftables
docs/            architecture, plan, threat model, runbook
```

## Security note

Aegis is **defensive** infrastructure (WAF, rate-limiting, bot/DDoS protection
for sites you operate or host). The edge-enrollment mechanism performs
intentional remote provisioning and ships with single-use signed tokens,
TLS-pinned bootstrap, and mTLS post-enrollment with automatic certificate
rotation and revocation. See `docs/threat-model.md`.
