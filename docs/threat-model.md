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

- Tokens are **single-use** and **short-TTL**, stored **hashed** (SHA-256).
- The secret is passed via **env var** (`ENROLL_TOKEN`), never in a URL/log.
- Bootstrap pulls signed artifacts; post-enrollment traffic uses **mTLS** (P3).
- The edge `systemd` unit runs least-privilege (`NoNewPrivileges`,
  `ProtectSystem=full`, only `CAP_NET_BIND_SERVICE`).

## Known Phase 1 limitations (hardening backlog)

- Agent auth is a shared bearer token, not per-node mTLS (P3).
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
