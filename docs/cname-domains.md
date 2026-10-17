# Connecting a domain via CNAME (external DNS)

Aegis supports two ways to connect a domain:

| Mode | DNS hosted by | How traffic reaches Aegis |
|------|---------------|---------------------------|
| `ns` (default) | Aegis (PowerDNS) | Delegate the zone's nameservers to `ns1`/`ns2.<apex>` |
| `cname` | **Your own provider** | Point `CNAME` records (or `ALIAS`/`ANAME` at the apex) at an Aegis target hostname |

CNAME mode is for users who must keep DNS at their current provider (or cannot
delegate nameservers). Aegis does **not** create or publish a DNS zone for these
domains; it only proves ownership and renders the edge routing.

> The connection mode is fixed when the domain is created. There is no in-place
> switch between `ns` and `cname` in this release — delete and re-add the domain
> to change it (domain records are per-domain).

## The CNAME target

The target hostname is configured by the operator as `CNAME_TARGET`. It defaults
to the control-plane host (which already resolves to the edge), so it works out
of the box. It only needs to resolve to the edge — it is **not** used for TLS.

```bash
# Check what the target resolves to (should be your edge IP):
dig +short edge.example.com
```

## Required DNS records

For a subdomain (e.g. `app.customer.com`):

```
app.customer.com.        CNAME   edge.example.com.
_aegis-challenge.customer.com.  TXT  aegis-verify-…   # ownership proof
```

For an apex domain (`customer.com`): **a plain CNAME at the apex is invalid**
(DNS forbids a CNAME where NS/SOA exist). Use one of:

- an **ALIAS / ANAME** record (supported by many providers and DNS hosts),
- an **A/AAAA** record pointing at the edge, or
- onboard a subdomain instead.

> TTLs: use a short TTL while setting up so changes propagate quickly. CNAME
> chains are followed normally by resolvers; keep chains short.

## Step by step

1. **Add the domain** in the dashboard (**Domains → Add**) and choose
   **“CNAME / external DNS”**. The response shows:
   - the **CNAME target** to point at,
   - the **TXT ownership record** (`_aegis-challenge.<domain>` = token).
2. **Create the DNS records** at your provider:
   - a CNAME (or ALIAS/ANAME at the apex) for each hostname you want proxied,
     pointing at the CNAME target,
   - the TXT challenge for ownership.
3. **Add routing records** on the domain (DNS tab). A **proxied** record defines
   a hostname and its origin, e.g. `app` → `demo-origin`. Only proxied records
   are served by the edge in CNAME mode (non-proxied records are ignored because
   Aegis does not publish your DNS).
4. **Verify** the domain. Aegis checks DNS (with retries to tolerate propagation)
   and activates the domain when ownership is proven.

### How verification works

In `cname` mode a domain is verified if **either**:

- the TXT record `_aegis-challenge.<domain>` contains the domain's token, **or**
- the registered hostname itself is a CNAME to `CNAME_TARGET` (convenient when
  onboarding a single subdomain).

Verification performs several lookups spaced a second apart to tolerate DNS
propagation and transient failures. If DNS has not propagated yet, wait and click
**Verify** again. In `EDGE_TLS_MODE=internal` (development) verification
auto-passes so local setups without public DNS still work.

## HTTPS / certificates

A CNAME record alone does not provide a certificate. Once the hostname resolves
to the edge, Caddy issues certificates automatically:

- `EDGE_TLS_MODE=acme` — Let's Encrypt/ZeroSSL via ACME. The hostname resolves
  (via your CNAME) to the edge, so HTTP-01/TLS-ALPN validation succeeds.
- `EDGE_TLS_MODE=internal` — Caddy's local CA (dev only; browsers warn).

Make sure ports 80 and 443 reach the edge. Certificates are renewed by Caddy
automatically.

## Routing and safety

- The edge serves only **active** (verified) domains and their **proxied**
  records. Each request is matched by the exact `Host` header and TLS SNI; an
  unknown or forged host gets no site (404), so a spoofed `Host` cannot reach a
  customer backend.
- A domain can only be registered once, and activation requires DNS control
  (TXT or CNAME). An unverified (pending) claim never routes traffic.
- Pending, unverified domains can block a name; an admin can delete them.

## Troubleshooting

```bash
# Does the target resolve to the edge?
dig +short edge.example.com

# Is the CNAME in place (follow the chain)?
dig +short app.customer.com CNAME
dig +short app.customer.com A

# Is the ownership TXT visible to public resolvers?
dig +short TXT _aegis-challenge.customer.com @1.1.1.1
```

- **Verify still fails** — DNS may not have propagated; check with `1.1.1.1` and
  `8.8.8.8`, then retry. Shared/caching resolvers can lag.
- **Certificate errors** — the hostname must resolve to the edge before ACME can
  succeed; check the CNAME/ALIAS and that 80/443 are open.
- **503 / no upstream** — a proxied origin must be reachable, and must not point
  back at the same edge hostname (that creates a self-referential loop).
