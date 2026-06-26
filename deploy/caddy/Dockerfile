# Aegis edge image: Caddy (Coraza+CRS, cache-handler, rate-limit + custom
# ja4/botscore/challenge modules) plus the node-agent that drives it.
# Build context = repository root.

# ---- 1. Build Caddy with xcaddy ----
FROM golang:1.26-trixie AS caddy-build
ENV CGO_ENABLED=0
RUN go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest
COPY edge/ /src/edge/
RUN xcaddy build \
		--output /out/caddy \
		--with github.com/aegis/edge/modules/ja4 \
		--with github.com/aegis/edge/modules/botscore \
		--with github.com/aegis/edge/modules/challenge \
		--replace github.com/aegis/edge=/src/edge \
		--with github.com/corazawaf/coraza-caddy/v2 \
		--with github.com/caddyserver/cache-handler \
		--with github.com/mholt/caddy-ratelimit

# ---- 2. Build the node-agent ----
FROM golang:1.26-trixie AS agent-build
ENV CGO_ENABLED=0
WORKDIR /src/node-agent
COPY node-agent/go.mod node-agent/go.sum* ./
RUN go mod download || true
COPY node-agent/ ./
RUN go build -o /out/aegis-agent ./cmd/agent

# ---- 3. Fetch OWASP Coraza recommended config + CRS ruleset ----
FROM debian:trixie-slim AS rules
ARG CRS_VERSION=v4.27.0
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl tar && rm -rf /var/lib/apt/lists/*
RUN set -eux; mkdir -p /coraza/rules; \
	curl -fsSL "https://raw.githubusercontent.com/corazawaf/coraza/main/coraza.conf-recommended" -o /coraza/coraza.conf; \
	curl -fsSL "https://github.com/coreruleset/coreruleset/archive/refs/tags/${CRS_VERSION}.tar.gz" -o /tmp/crs.tgz; \
	tar -xzf /tmp/crs.tgz -C /tmp; \
	cp /tmp/coreruleset-*/crs-setup.conf.example /coraza/crs-setup.conf; \
	cp /tmp/coreruleset-*/rules/*.conf /coraza/rules/ || true; \
	cp /tmp/coreruleset-*/rules/*.data /coraza/rules/ 2>/dev/null || true; \
	rm -rf /tmp/crs.tgz /tmp/coreruleset-*

# ---- 4. Final runtime image ----
FROM debian:trixie-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl && rm -rf /var/lib/apt/lists/*
COPY --from=caddy-build /out/caddy /usr/bin/caddy
COPY --from=agent-build /out/aegis-agent /usr/bin/aegis-agent
COPY --from=rules /coraza/ /etc/caddy/coraza/
COPY deploy/caddy/Caddyfile.base /etc/caddy/Caddyfile
RUN mkdir -p /etc/caddy/sites /data /config
ENV XDG_DATA_HOME=/data XDG_CONFIG_HOME=/config
EXPOSE 80 443
# The agent writes the dynamic config, launches Caddy, syncs config + telemetry.
ENTRYPOINT ["/usr/bin/aegis-agent"]
