# Threat model (Phase 1)

Aegis is **defensive** infrastructure: it protects sites the operator hosts or
controls. This document records trust boundaries and the security posture.

## Trust boundaries

| Boundary | Control |
|----------|---------|
| Visitor → edge | nftables (L3/4), JA4H fingerprinting, rate limiting, bot scoring, PoW challenge, Coraza+CRS WAF |
| Browser → control plane | Argon2id passwords, TOTP MFA, Redis sessions (httpOnly+Secure+SameSite=Lax cookies), double-submit CSRF, RBAC |
| Agent → control plane | Bearer agent token over the internal network (Phase 1). **Phase 3: single-use enrollment token exchanged for per-node mTLS** |
| Control plane → PowerDNS | API key over the internal network |
| Control plane → threat-feed providers | Outbound HTTPS only; responses are untrusted input — see "Threat-feed ingestion" |
| Tenant isolation | Every domain/record/policy query is scoped by `account_id`; ownership re-checked on each request |

## Authentication & sessions

- Passwords: argon2id (64 MiB, t=3, p=2), constant-time verify, dummy-hash on
  unknown email to blunt user enumeration.
- Sessions: opaque 256-bit IDs in Redis with TTL; MFA-pending sessions cannot
  access protected routes until the TOTP step completes.
- CSRF: state-changing requests require `X-CSRF-Token` matching the readable
  `aegis_csrf` cookie. Auth bootstrap endpoints (signup/login/mfa/verify) are
  intentionally exempt (no session yet) and rate-limited at the edge.

## Edge enrollment (RCE by design)

The served `install/edge.sh` provisions a new host, so it is hardened:

- Enrollment tokens are **single-use** and **short-TTL**, stored **hashed**
  (SHA-256); the consume is atomic (one transaction), so a token cannot enroll
  two nodes or be replayed.
- The secret is passed via **env var** (`ENROLL_TOKEN`), never in a URL/log.
- `/edge/v1/enroll` exchanges the token for a **durable per-node agent token**
  (also stored hashed); every subsequent edge call authenticates with it, so a
  node has its own revocable identity rather than a shared secret. The challenge
  secret returned at enrollment is delivered only over the token-authenticated
  HTTPS exchange.
- Telemetry/metrics are attributed to the **authenticated** edge, so a node
  cannot spoof another's identity via the self-reported name.
- The edge `systemd` unit runs least-privilege (`NoNewPrivileges`,
  `ProtectSystem=full`, only `CAP_NET_BIND_SERVICE`).
- **Remaining hardening**: per-node **mTLS** (replacing the bearer token), signed
  binary/image distribution, and edge revocation UI.

## Threat-feed ingestion (Phase 2)

The control plane fetches third-party IP-reputation feeds. Their bodies are
**untrusted input** and a feed could be unreachable, truncated, or malicious:

- **Bounded I/O**: each fetch has a 30s timeout and the body is read through a
  32 MiB `io.LimitReader`; at most 300k CIDRs are kept per feed.
- **Strict parsing**: only tokens that pass `netip` CIDR/address validation are
  stored, normalised to canonical masked form. Malformed lines are skipped and
  counted, never trusted as-is — so a feed cannot inject arbitrary Caddyfile
  text (entries only ever appear as `remote_ip` matcher arguments).
- **Fail-safe**: a failed sync is recorded on the feed (`last_error`) and leaves
  the previous good entry set in place; it never wipes protection on a transient
  error or empty response.
- **Egress control**: the background fetcher is gated by `THREATFEED_SYNC`; set
  it `off` for air-gapped deployments. Feed management is admin-only (RBAC).
- **Availability note**: feeds default to a global hard `403`. An over-broad
  upstream feed could block legitimate traffic — feeds are individually toggle-
  able and entry counts are surfaced so operators can audit blast radius.

## DNSSEC (Phase 2)

- **Key custody**: PowerDNS generates and stores all DNSSEC private keys; the
  control plane only ever reads public DS/DNSKEY records. The private key
  PowerDNS returns when a key is created is deliberately not modelled by the API
  client, so it cannot leak through the dashboard or logs.
- **Authorization**: enable/disable is owner-scoped (same account check as DNS
  records) and both actions are written to the audit log.
- **Operational caveat**: disabling DNSSEC (or deleting a signed domain) while a
  DS record is still published at the registrar breaks resolution. The dashboard
  warns the operator to remove the DS record first.

## Admin impersonation (Phase 2)

Admins can assume a user's identity for support, with guardrails:

- **No privilege escalation**: only role `user` accounts may be impersonated, so
  an impersonator can never gain rights it didn't already hold. Self- and
  nested-impersonation are rejected.
- **Reduced privilege while impersonating**: the session's effective user becomes
  the target (role `user`), so admin routes are unreachable until the admin
  returns — impersonation cannot be used to perform admin actions as a tenant.
- **Reversible, same session**: the real admin id is stored on the server-side
  session (never trusted from the client) and restored on "Return to admin"; no
  new credentials are issued.
- **Audited & visible**: every start/stop writes an `admin.impersonate_*` audit
  row (actor, target, IP), surfaced in Admin → Audit log. A persistent banner
  shows the operator they are impersonating.

## Custom WAF rules import (Phase 2)

Tenants can import SecLang rules and per-route WAF overrides, which feed the
shared edge Coraza engine — a sensitive surface:

- **Directive allowlist**: only `SecRule`, `SecAction`, `SecMarker`, and the
  `SecRule{Remove,Update}*` family are accepted. Directives that do I/O, fetch
  remote rules, or change engine-wide behaviour (`Include`, `SecRuleEngine`,
  `SecRemoteRules`, `SecAuditLog*`, `Sec*Dir`, …) are rejected.
- **Injection containment**: input is size-capped, must not contain backticks
  (which would break out of the Caddyfile string), and each directive's quotes
  must balance — catching the syntax errors most likely to fail edge config
  loading. Override paths are validated and rule IDs must be numeric, so they
  cannot break out of the generated `SecRule` operator argument.
- **Residual risk**: validation is structural, not a full Coraza compile, so a
  semantically-invalid rule could still fail provisioning at the edge. Caddy's
  `/load` is atomic — it keeps the last-good config — so live traffic is
  unaffected, but config propagation stalls until the rule is fixed. Operators
  should stage rules with the per-route/global "Detect only" mode first.
- **Authorization**: all WAF tuning is scoped to the owning account; overrides
  delete by `(id, domain_id)`.

## Bot scoring + CAPTCHA (Phase 2)

- **Verified-bot allowlist is advisory**: crawlers are matched by User-Agent,
  which is spoofable. It is an availability convenience (don't challenge
  Googlebot), not a security control — scoring/WAF/blocklists still apply to
  everything else, and operators can disable the allowlist per domain.
- **CAPTCHA secret handling**: the provider secret is write-only over the API
  (never returned; a blank value on update keeps the stored one) and is rendered
  into the edge config bundle, which is delivered over the authenticated edge API
  — the same trust boundary as the rest of the config. Token verification happens
  server-side at the edge, so a forged client response cannot grant clearance.
- **Clearance cookie**: HMAC-signed over client IP + UA + expiry with the
  per-edge `CHALLENGE_SECRET`; it is `HttpOnly`, `Secure` (on TLS), time-boxed,
  and not transferable to a different IP/UA.

## Per-request analytics (Phase 2, ClickHouse)

- **PII / retention**: request events include the client IP and User-Agent (for
  unique-visitor counts and debugging). They live in ClickHouse with a 30-day
  TTL and are scoped per account on read (domain ownership enforced). Operators
  with stricter requirements can shorten the TTL or disable ClickHouse entirely
  (`CLICKHOUSE_URL` unset) and keep only the aggregate Postgres counters.
- **Injection**: events are inserted via `JSONEachRow` (values parsed, never
  concatenated into SQL); analytics queries use ClickHouse query parameters.
  Path/UA are length-capped at the edge.
- **Trust boundary**: the events endpoint is authenticated with the agent token
  (same as config/telemetry); ClickHouse is reached only over the internal
  network.
- **GeoIP**: country/ASN are resolved by a local in-memory lookup against the
  public-domain iptoasn.com database (refreshed daily over HTTPS by the control
  plane). No visitor IP is ever sent to a third-party geo service; the only
  egress is the periodic database download. Disable with `GEOIP_ENABLED=off`.

## Known Phase 1 limitations (hardening backlog)

- Enrolled edges authenticate with a durable per-node bearer token; the
  all-in-one local edge still uses the shared token. Per-node mTLS is the next
  hardening step (P3).
- The Caddy admin API is bound to `127.0.0.1` and the agent is co-located in the
  edge container so it is never network-exposed.
- WAF block counts aren't yet attributed per-domain in telemetry (global
  counters only); ClickHouse-backed per-route analytics is P2.
- The PoW challenge deters commodity bots; it is not a substitute for a managed
  CAPTCHA against determined adversaries (pluggable CAPTCHA is P2).
- Secrets live in `.env`; use a secrets manager in production.

## Reporting

This is a self-hosted project; operators are responsible for patching the base
images (Caddy, Postgres, PowerDNS, Node) and rotating `.env` secrets.
