# Plan: "Aegis" — a self-hosted Cloudflare-style edge platform

> Working name `aegis` (placeholder — rename freely). Greenfield monorepo in a new repo under `/home/rtb/Projekte/aegis`.

## Context

The goal is a fully-fledged Cloudflare competitor: per-domain DNS management, a toggleable reverse proxy with automatic SSL/TLS and HTTP→HTTPS, caching, a WAF driven by free rule-list providers, DDoS protection (fingerprinting, customizable rate-limiting, anomalous-traffic detection), anti-bot challenges, a multi-tenant dashboard with auth + easy domain onboarding, an admin area, and one-command enrollment of new edge servers into the load balancer. Target deployment is Debian 13 ("Trixie").

This is a multi-month system, so the **entire architecture is designed here**, but it is built in phases. Per your choices: **Phase 1 builds Foundation + the Security stack** as a working vertical slice, in **Go (API + agent) + Next.js (dashboard)**, deployed **all-in-one via Docker Compose on one Debian 13 box**. Multi-node edge enrollment is fully designed now and built in Phase 3.

Dev box is CachyOS (Arch, 16 cores / 62 GB) with only Python 3.14 + git installed — so the build will install Docker, Go, Node, and `xcaddy` on the dev machine to produce **Debian-13-ready** images and provisioning scripts.

### Why these foundations (verified during planning)
- **Caddy** as the data plane: automatic HTTPS + automatic HTTP→HTTPS by default, health-checked `reverse_proxy` load balancing, and a Go plugin model we extend via `xcaddy`.
- **Coraza** WAF (not ModSecurity — EOL since July 2024): pure-Go, passes 100% of the OWASP CRS v4 suite, production-ready `coraza-caddy` middleware.
- **OWASP CRS 4.27** (4.25 is the LTS line) as the primary free WAF rule-list provider.
- **PowerDNS Authoritative**: API-first JSON/REST per-zone management + DNSSEC, Postgres backend.
- **cache-handler/Souin** (Redis-backed) for caching; **caddy-ratelimit** for rate limiting; **JA4/JA4H** TLS fingerprinting via a custom Caddy module (no off-the-shelf one exists).

---

## System architecture (whole system)

Three planes, one control-plane source of truth (Postgres), config pushed to edges over mTLS gRPC.

```
                         ┌──────────────────────── Control Plane ────────────────────────┐
   Browser (admin/user)  │  Next.js dashboard  ──►  Go API (chi)  ──►  Postgres (truth)   │
        │  HTTPS          │                              │   │  ▲         Redis (sessions, │
        ▼                 │                              │   │  │          ratelimit, cache,│
   Dashboard/API edge ◄───┤     PowerDNS API client ◄────┘   │  │          pubsub, challenge)│
                          │     config-bundle renderer ──────┘  │                          │
                          │     gRPC edge server (mTLS) ◄────────┘  telemetry/health        │
                          └──────────────┬───────────────────────────────────┬─────────────┘
                                         │ config stream                      │
            ┌────────── DNS Plane ───────┴───┐              ┌──── Data Plane (edge pool) ────┐
   visitor  │  PowerDNS Authoritative (gpgsql)│   visitor    │  nftables/eBPF (L3/L4)         │
   DNS  ───►│  serves customer zones; proxied │   HTTPS  ───►│  Caddy: ACME TLS, JA4 fp,      │
   query    │  records point at edge IP(s)    │              │  IP/ASN filter, ratelimit,     │
            └─────────────────────────────────┘              │  botscore, challenge, Coraza   │
                                                             │  +CRS, Souin cache, reverse_   │
                                                             │  proxy→origin (health-checked) │
                                                             │  node-agent (enroll/sync/tele) │
                                                             └────────────────────────────────┘
```

### Request lifecycle (proxied domain)
1. Visitor resolves `app.customer.com` → our PowerDNS returns edge IP(s). Edge selection via authoritative DNS (weighted/round-robin now, GeoDNS later; anycast is a scale-stage option that needs an ASN/BGP).
2. Packet hits an edge → **L3/L4** nftables (SYN cookies, conntrack + per-IP connection caps, blocklists; optional XDP/eBPF drop later).
3. **TLS** handshake: Caddy serves the auto-provisioned ACME cert; custom **JA4/JA4H** module fingerprints the ClientHello → request context.
4. **L7 handler order:** IP/ASN/geo blocklist → `rate_limit` (per-domain/route rules) → `botscore` (JA4 reputation + heuristics) → `challenge` (PoW/JS interstitial if suspicious) → **Coraza WAF** (CRS) → **Souin cache** lookup → `reverse_proxy` to origin pool (health checks, retries). HTTP→HTTPS redirect is automatic.
5. Response cached per rules; telemetry streamed to control plane.

### Requirement → component map
| Requirement | Implementation |
|---|---|
| DNS management per domain | PowerDNS Auth + HTTP API; `internal/dns` client; dashboard DNS UI; DNSSEC (Phase 2) |
| Toggleable reverse proxy | Per-record "proxied" flag → proxied points DNS at edge IP & enables Caddy `reverse_proxy`; DNS-only points at origin |
| Automatic SSL/TLS | Caddy on-demand ACME (Let's Encrypt/ZeroSSL); internal CA for local test mode |
| HTTP→HTTPS rewrites | Caddy automatic redirect (default) |
| Caching | `cache-handler`/Souin, Redis-backed, per-domain rules + purge API |
| DDoS: fingerprinting | `ja4` module (JA4/JA4H/JA4T) + reputation lookups |
| DDoS: customizable rate-limiting | `caddy-ratelimit`, per-domain/route token buckets keyed by IP/JA4/header, edited in dashboard |
| Harmful/unrealistic traffic detection | `botscore` anomaly engine (rate, path entropy, UA↔JA4 mismatch, missing headers, ASN reputation) → dynamic blocklists |
| Anti-bot | `challenge` module: JS + Proof-of-Work interstitial, managed-challenge cookie; pluggable CAPTCHA (Phase 2) |
| WAF via free list providers | Coraza engine + OWASP CRS (primary); ingest additional free SecLang lists + IP threat feeds (Spamhaus DROP, FireHOL L1) → blocklists |
| Dashboard + auth + onboarding | Next.js + Go API; argon2id, TOTP MFA, Redis sessions, RBAC; domain onboarding wizard |
| Admin area | `(admin)` routes + `internal/admin`: all users + domains/usage/status/last-login, audited impersonation, enrollment tokens, global policy |
| Add servers to LB via copy-paste script | `deploy/debian13/edge.sh` + enrollment-token flow (Phase 3, designed below) |

### Config distribution (control plane → edge)
Postgres is the source of truth. On change, the **bundle renderer** (`internal/config`) produces a per-edge bundle: Caddy JSON (applied via Caddy Admin API `:2019/load`), Coraza/CRS policy, rate-limit rules, blocklists, origin pools, ACME settings. The **node-agent** authenticates with its mTLS client cert, receives the bundle over a gRPC stream (Redis pub/sub triggers push), applies it locally, and streams health + telemetry back.

### Edge enrollment — the copy-paste script (designed now, built Phase 3)
1. Admin area → "Add edge server" → mints a **single-use, TTL-scoped enrollment token**; UI shows:
   `curl -fsSL https://cp.example.com/install/edge.sh | sudo ENROLL_TOKEN=xxxx bash`
2. `edge.sh` on the new Debian 13 host: preflight (Debian 13, root, arch, ports) → pulls **signed** Caddy (modules baked in) + node-agent binaries + systemd units + `nftables` ruleset → agent calls `POST /api/v1/edges/enroll` with the token → control plane verifies, creates the edge record, **exchanges the token for a durable mTLS client cert** → agent fetches initial bundle, starts Caddy, passes health check.
3. Control plane marks the node healthy → adds its IP to the proxied-record DNS rotation (PowerDNS) + LB pools → node serves live traffic.
4. **Safeguards (this is RCE-by-design, so it must be locked down):** single-use + short-TTL tokens, secret passed via env (not URL/logs), TLS-pinned bootstrap, signed binaries + checksums, mTLS for all post-enroll traffic, least-privilege systemd units, token passed to `sudo` not embedded in a world-readable file.

### Two load-balancing layers (clarifies "the load balancer")
- **Edge pool LB** (what enrollment grows): authoritative DNS hands visitors an edge IP from the healthy rotation.
- **Origin LB** (per edge): Caddy `reverse_proxy` balances across a customer's origin servers with health checks/policies.

---

## Tech stack (decided)
| Layer | Choice |
|---|---|
| Control-plane API | Go + `chi` router; `pgx` + `sqlc` (type-safe queries); `goose` migrations |
| Auth | `argon2id` (`golang.org/x/crypto`), TOTP (`pquerna/otp`), Redis sessions, CSRF, RBAC |
| Edge↔CP transport | gRPC (`buf`/protobuf) over mTLS; Redis pub/sub for push triggers |
| Node agent | Go (shares `proto/` contracts with API) |
| Edge proxy | Caddy via `xcaddy` + `coraza-caddy`(+CRS) + `cache-handler` + `caddy-ratelimit` + custom `ja4`/`botscore`/`challenge` |
| DNS | PowerDNS Authoritative + `gpgsql` backend; control plane drives the HTTP API |
| Dashboard | Next.js (App Router) + TypeScript + Tailwind + shadcn/ui + TanStack Query + Tremor/Recharts |
| Datastores | PostgreSQL 17 (truth), Redis 7 (sessions/ratelimit/cache/pubsub/challenge) |
| Observability | Prometheus + Grafana (optional in compose); ClickHouse for high-volume analytics in Phase 2 |
| Deploy | Docker Compose (all-in-one now); native systemd binaries on real edges via `edge.sh` |

---

## Repository layout
```
aegis/
├── docker-compose.yml          # all-in-one: postgres, redis, powerdns, api, dashboard, caddy-edge, agent
├── .env.example  Makefile  README.md
├── deploy/
│   ├── debian13/{install-control-plane.sh, edge.sh, systemd/*.service, nftables/edge.nft}
│   └── caddy/{Dockerfile(xcaddy build), Caddyfile.base}
├── proto/                      # gRPC contracts (config stream, telemetry, enroll)
├── control-plane/
│   ├── cmd/{api,migrate}/main.go
│   ├── migrations/             # goose SQL
│   └── internal/{auth,domains,dns,edges,security,analytics,admin,config,grpc,store,httpapi}/
├── node-agent/
│   ├── cmd/agent/main.go
│   └── internal/{enroll,configsync,caddyadmin,telemetry,health}/
├── edge/modules/{ja4,botscore,challenge}/   # custom Caddy Go modules
└── dashboard/
    ├── app/{(auth),(dashboard),(admin)}/...
    ├── lib/api/                # typed client
    └── components/
```

---

## Phase 1 — Foundation + Security stack (BUILD NOW)

A working all-in-one deployment where a user signs up, onboards a domain, manages DNS, toggles the proxy, and gets automatic TLS + caching + WAF + rate-limiting + basic bot/DDoS — plus a basic admin area.

**A. Scaffold & infra**
- Monorepo + `docker-compose.yml` (postgres, redis, powerdns+gpgsql, control-plane api, dashboard, caddy-edge, node-agent), `.env.example`, `Makefile`, README.
- `deploy/caddy/Dockerfile` builds Caddy with `xcaddy` bundling coraza-caddy+CRS, cache-handler, caddy-ratelimit, and our 3 modules.

**B. Control-plane API (Go)**
- Schema/migrations: `accounts`, `users`, `sessions`, `mfa_totp`, `domains`, `dns_records`, `edges`, `security_policies`, `rate_limit_rules`, `waf_settings`, `cache_rules`, `blocklists`, `enrollment_tokens`, `audit_log`, `analytics_rollup`.
- **Auth** (`internal/auth`): signup/login/logout, argon2id, email verify (dev mailer to console/Mailpit), TOTP MFA, Redis session middleware, CSRF, RBAC (`user`/`admin`/`superadmin`).
- **Domains** (`internal/domains`): onboarding wizard backend — add domain → display assigned nameservers → verification check → activate.
- **DNS** (`internal/dns`): PowerDNS API client; record CRUD; the **proxied toggle** (proxied → edge IP + proxy enabled; DNS-only → origin IP).
- **Security** (`internal/security`): CRUD for WAF (on/off, CRS paranoia level, rule toggles), rate-limit rules, cache rules, bot/DDoS sensitivity.
- **Config** (`internal/config` + `internal/grpc`): bundle renderer + gRPC push; telemetry ingest.
- **Admin** (`internal/admin`): list all users with domains/status/last-login; manage enrollment tokens (UI present, multi-node activ. in P3).

**C. Edge (Caddy)** — image with automatic HTTPS + HTTP→HTTPS, `reverse_proxy` (health checks), Coraza+CRS, Souin cache, caddy-ratelimit, and:
- `ja4`: compute JA4/JA4H from ClientHello → context + log.
- `botscore`: minimal-but-functional heuristic score (rate, UA↔JA4 mismatch, missing headers, ASN list) → allow/challenge/block.
- `challenge`: PoW + JS interstitial, managed-challenge cookie.
- `deploy/debian13/nftables/edge.nft`: SYN cookies, conntrack/per-IP caps, blocklist set.

**D. Node-agent (Go)** — in compose uses a pre-shared dev token; config sync via gRPC; applies to Caddy Admin API (`localhost:2019`); health/telemetry back.

**E. Dashboard (Next.js)** — auth screens (signup/login/MFA), domain onboarding wizard, DNS records table + proxied toggle, security settings (WAF / rate-limit / caching / bot sensitivity), basic analytics (requests, blocked, cache hit-rate), account settings, and a basic **Admin** users table.

**F. Debian 13 all-in-one** — `deploy/debian13/install-control-plane.sh` (install Docker engine + compose plugin, clone, `.env`, `docker compose up -d`); the edge Caddy also fronts the dashboard+API over TLS; `docs/runbook-debian13.md`.

---

## Phases 2–3 (designed now, built later)
- **Phase 2 — depth:** ClickHouse analytics; richer botscore + managed challenges + pluggable CAPTCHA; threat-feed ingestion (Spamhaus DROP, FireHOL L1) → auto-blocklists; per-route WAF tuning UI + custom SecRules import; DNSSEC; audited impersonation; billing/plans/quotas; email via real SMTP.
- **Phase 3 — scale-out:** the `edge.sh` copy-paste enrollment on real Debian 13 hosts; mTLS PKI + cert rotation; GeoDNS/weighted edge distribution; autoscaling health-checked LB pools; HA control plane; optional anycast/BGP.

---

## Security & scope note
This is legitimate **defensive** infrastructure (WAF, rate-limiting, bot/DDoS protection for sites the operator controls or hosts). The enrollment mechanism performs intentional remote provisioning, so it ships with single-use signed tokens, TLS pinning, and mTLS as above. No offensive/abuse tooling is included. A `docs/threat-model.md` will document trust boundaries.

## Verification (end-to-end, on the dev box first, then Debian 13)
1. `make up` / `docker compose up -d` → all services healthy (`docker compose ps`, `/healthz`).
2. **Auth:** sign up, verify email (Mailpit), log in, enable TOTP, re-login with code.
3. **Local test mode:** onboard `demo.nip.io`-style domain using Caddy's **internal CA** (no public DNS needed); confirm assigned-nameservers + verification flow.
4. **DNS:** add an A record via UI → `dig @powerdns demo... A` returns it; flip **proxied** → record resolves to the edge IP.
5. **Proxy + TLS + redirect:** `curl -I http://app...` → 308 to HTTPS; `curl -k https://app...` reaches a demo origin; cert served by edge.
6. **WAF:** `curl 'https://app.../?id=1%20OR%201=1'` (or an SQLi/path-traversal probe) → **403** from Coraza/CRS; visible in dashboard analytics.
7. **Rate-limit:** loop curl past the configured limit → **429**.
8. **Bot/DDoS:** a request with a mismatched UA/JA4 or flagged ASN → **PoW challenge** page; passing sets the managed-challenge cookie.
9. **Caching:** repeat a cacheable GET → second response shows cache **HIT**; purge via API → next is **MISS**.
10. **Admin:** log in as admin → users table lists the test user with domain/status/last-login.
11. Re-run 1–10 on a fresh **Debian 13** VM via `install-control-plane.sh` to confirm the deploy target.

## Risks / realism
- Full parity with Cloudflare is a multi-team, multi-quarter effort; Phase 1 delivers a genuinely working slice, not feature-parity.
- Public ACME needs a real domain + reachable ports 80/443; local verification uses Caddy's internal CA to avoid that dependency.
- Anycast/BGP (true global edge) is out of scope until Phase 3+ and requires an ASN and IP allocations.
- JA4 fingerprinting requires reading the raw ClientHello — feasible in a Caddy listener wrapper but is custom code and the main technical risk in the security stack.
