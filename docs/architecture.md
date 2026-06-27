# Architecture

Aegis separates a **control plane** (source of truth + UI), a **DNS plane**
(authoritative DNS), and a **data plane** (the edge that sits in front of
customer traffic).

```
                ┌──────────────── Control plane ─────────────────┐
  dashboard ───▶│ Go API (chi)  ─▶ Postgres (truth)              │
   (Next.js)    │   ├─ auth/domains/dns/security/admin           │
                │   ├─ config renderer ─▶ config_bundles         │
                │   └─ edge API  ◀── long-poll / telemetry        │
                │ Redis: sessions, ratelimit, pub/sub, counters  │
                └───────┬──────────────────────┬────────────────-┘
            PowerDNS API│           config pull │ (Bearer; mTLS in P3)
                        ▼                       ▼
                 ┌─────────────┐        ┌──────────────── Edge ───────────────┐
   visitor DNS ─▶│  PowerDNS   │ visitor│ nftables → Caddy:                   │
                 │ (gpgsql)    │  HTTPS ▶│  ja4 → rate_limit → botscore →      │
                 └─────────────┘        │  challenge → coraza(CRS) → cache →  │
                                        │  reverse_proxy → origin             │
                                        │ node-agent (writes Caddyfile, reload)│
                                        └──────────────────────────────────────┘
```

## Source of truth & config flow

1. Dashboard/API mutations write to **Postgres**.
2. Any change that affects the edge calls `config.Renderer.Rebuild`, which
   renders the customer **Caddyfile**, stores it as a new `config_bundles` row
   (versioned + checksummed), and publishes a poke on Redis `edge:config`.
3. The **node-agent** long-polls `GET /edge/v1/config?since=<v>`; the poke wakes
   the poll. It writes `/etc/caddy/sites/dynamic.caddy` and runs `caddy reload`
   (via Caddy's admin API). Missed pokes self-heal because the agent re-polls.
4. The agent drains Redis counters set by the edge modules and posts them to
   `POST /edge/v1/telemetry`, which records heartbeats + metrics.

## Proxied vs DNS-only records

- **DNS-only**: PowerDNS serves the record's real content.
- **Proxied** (A/AAAA/CNAME): PowerDNS serves the **edge IP**; the record's real
  content is kept as the proxy **origin**, and a Caddy site block is rendered for
  that hostname. This is the "orange-cloud" toggle. Zone reconciliation lives in
  `control-plane/internal/domains/service.go` (`syncZone`).

## DNSSEC (Phase 2)

Per-zone DNSSEC is driven through PowerDNS's cryptokeys API; PowerDNS remains the
source of truth for key material (the control plane never stores private keys).

- **Backend**: `gpgsql-dnssec=yes` + `default-api-rectify=yes` in
  `deploy/powerdns/pdns.conf` (the DNSSEC schema tables ship in
  `pdns-gpgsql-schema.sql`).
- **Client** (`internal/dns/dnssec.go`): `EnableDNSSEC` adds an active CSK
  (idempotent), `DisableDNSSEC` removes all keys, `DNSSECStatus` reports the
  signed state plus the active keys' DS/DNSKEY records.
- **API** (`internal/domains/dnssec.go`): owner-scoped `GET/POST/DELETE
  /domains/{id}/dnssec`; enable/disable are audited. Enabling returns the DS
  records (digest types 1/2/4) the operator publishes at their registrar to
  complete the chain of trust; SHA-256 (type 2) is recommended.
- **Edge impact**: none — DNSSEC lives entirely in the DNS plane.

## Request pipeline (edge)

`nftables (L3/4)` → `ja4` (JA4H fingerprint → `{http.vars.ja4h}`) →
`rate_limit` (per-IP) → `botscore` (heuristics + per-IP rate → block / flag) →
`challenge` (PoW interstitial for flagged clients) → `coraza_waf` (OWASP CRS) →
`cache` (Souin) → `reverse_proxy` (health-checked origin pool). Automatic HTTPS
and HTTP→HTTPS are Caddy defaults.

## Components

| Path | Role |
|------|------|
| `control-plane/` | Go API: auth (argon2id, TOTP, Redis sessions, RBAC, CSRF), domains, DNS (PowerDNS client), security policy, config renderer, edge API, admin, analytics |
| `edge/modules/{ja4,botscore,challenge}` | Custom Caddy v2 handlers |
| `node-agent/` | Manages Caddy on each edge: config sync + telemetry |
| `dashboard/` | Next.js + Tailwind UI + admin |
| `deploy/` | xcaddy Dockerfile + base Caddyfile, Postgres/PowerDNS init, Debian 13 scripts, nftables |

## Deviations from the original plan (Phase 1, pragmatic)

- **Config transport** is authenticated HTTP long-poll (not gRPC). It is the
  same model functionally; gRPC + per-node **mTLS** is the Phase 3 hardening.
- **Edge config** is delivered as a rendered **Caddyfile** the agent reloads,
  rather than hand-assembled Caddy JSON — this uses documented third-party
  directives (Coraza/cache/ratelimit) and is far easier to debug.
- **JA4** is the HTTP-layer **JA4H** today (fully derivable from the request);
  TLS-ClientHello JA4 needs a listener wrapper and lands in Phase 2.
- **Data access** uses hand-written `pgx` queries instead of `sqlc` codegen.

## Threat-feed ingestion (Phase 2)

Free IP-reputation feeds are pulled on a schedule and enforced at the edge as a
global blocklist, separate from the operator-managed `blocklists` table.

- **Source of truth**: `threat_feeds` (one row per provider; seeded with Spamhaus
  DROP + FireHOL Level 1) and `threat_feed_entries` (one row per CIDR per feed).
- **Fetcher** (`internal/threatfeed`): a background `Syncer` started from
  `cmd/api` (gated by `THREATFEED_SYNC`). Every minute it picks feeds whose last
  successful sync is older than their `refresh_interval`, downloads them
  (size-capped, timeout-bounded), parses CIDRs (tolerant of both `.netset` and
  Spamhaus DROP formats), validates/de-dupes/sorts them, and swaps each feed's
  entries atomically. A failed fetch is recorded on the feed row and leaves the
  last-known-good entries in place.
- **Enforcement**: `config.Renderer` emits the union of all *enabled* feeds'
  CIDRs **once** as a reusable Caddyfile snippet (`(aegis_threatfeeds)`) and
  `import`s it into every proxied site — so thousands of networks are not
  duplicated per host. Listed clients get a hard `403`.
- **Control**: Admin → Threat feeds lists each feed's status/entry-count/last
  sync, toggles it on/off, and triggers an immediate refresh. Toggling or
  refreshing re-renders config and pokes the edges.

## Phases 2–3 (remaining)

- P2: ClickHouse analytics, richer bot scoring + CAPTCHA, per-route WAF tuning +
  custom SecRules import, billing. (Threat-feed ingestion → auto-blocklists,
  DNSSEC, audited admin impersonation, and real SMTP email are **built**.)
- P3: multi-node edge enrollment over the served `install/edge.sh`, per-node
  mTLS PKI, GeoDNS/weighted edge distribution, HA control plane, anycast option.
