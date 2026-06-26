# Runbook — deploy & verify on Debian 13

## 1. Bring up the stack

```bash
# from the repo root
sudo bash deploy/debian13/install-control-plane.sh     # installs Docker, writes .env, builds & starts
# or, if Docker is already present and you wrote .env yourself:
make up
docker compose ps        # wait until api/postgres/redis are healthy
```

First build is slow (xcaddy compiles Caddy + Coraza + CRS). Subsequent builds are cached.

The installer prints the generated **admin password** — save it. The admin email is `BOOTSTRAP_ADMIN_EMAIL` in `.env` (`admin@example.com` by default).

## 2. Reach the dashboard

The edge serves the dashboard/API on `CONTROL_PLANE_HOST` (default `cp.localtest.me`, which
resolves to `127.0.0.1`). TLS uses Caddy's **internal CA** in dev, so expect a cert warning
or use `-k`.

- Dashboard: `https://cp.localtest.me/`
- API health: `curl -k https://cp.localtest.me/healthz`
- Direct API (debug): `http://localhost:8080/healthz`
- Mail catcher (if `MAILER=smtp`): `http://localhost:8025`

## 3. End-to-end checks

```bash
# Auth
curl -k -c jar -b jar -X POST https://cp.localtest.me/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@example.com","password":"<from installer>"}'

# Add a domain (use the CSRF cookie value in X-CSRF-Token; the dashboard does this for you)
# Create a PROXIED A record:  name=app  type=A  content=demo-origin  proxied=true
#   -> our PowerDNS publishes app.<domain> -> EDGE_PUBLIC_IP
#   -> the edge reverse-proxies to the demo-origin container

# DNS published by PowerDNS:
dig @127.0.0.1 -p 5300 app.<domain> A +short

# Through the edge (map the test host to the edge):
curl -k --resolve app.<domain>:443:127.0.0.1 https://app.<domain>/        # whoami origin

# WAF (Coraza + OWASP CRS) should 403 an attack probe:
curl -k --resolve app.<domain>:443:127.0.0.1 "https://app.<domain>/?q=<script>alert(1)</script>"

# Rate limit -> 429 after the configured RPM:
for i in $(seq 1 50); do curl -k -s -o /dev/null -w '%{http_code}\n' \
  --resolve app.<domain>:443:127.0.0.1 https://app.<domain>/; done

# Bot challenge: a scripted UA gets the PoW interstitial (503 + JS):
curl -k -A 'python-requests/2.32' --resolve app.<domain>:443:127.0.0.1 https://app.<domain>/ | head
```

Admin → Users lists all accounts; Admin → Edge servers mints an enrollment token + install
command. Analytics populate from edge telemetry within ~15s.

## 4. Logs & troubleshooting

```bash
docker compose logs -f api          # control plane (migrations, bootstrap, requests)
docker compose logs -f caddy-edge   # agent + Caddy (config reloads, WAF, challenges)
docker compose logs -f powerdns
docker compose exec api /app/migrate   # re-run migrations manually
```

- **Edge has no sites**: a domain must be **active** (verified). In dev (`EDGE_TLS_MODE=internal`)
  verification auto-passes; click *Verify* (or `POST /domains/{id}/verify`).
- **Cert errors**: expected with the internal CA; use `-k` or import the Caddy root from the
  `caddydata` volume.
- **Switch to real certs**: set `EDGE_TLS_MODE=acme` + a real domain delegated to the edge with
  ports 80/443 publicly reachable.

## 5. Reset

```bash
docker compose down -v    # removes volumes (Postgres, Caddy data) — destroys all state
```
