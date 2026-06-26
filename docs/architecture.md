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

## Phases 2–3 (designed, not built)

- P2: ClickHouse analytics, richer bot scoring + CAPTCHA, threat-feed ingestion
  (Spamhaus DROP, FireHOL), DNSSEC, per-route WAF tuning, billing.
- P3: multi-node edge enrollment over the served `install/edge.sh`, per-node
  mTLS PKI, GeoDNS/weighted edge distribution, HA control plane, anycast option.
