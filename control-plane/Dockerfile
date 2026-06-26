# Aegis control-plane API image. Build context = ./control-plane
FROM golang:1.26-trixie AS build
ENV CGO_ENABLED=0
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . ./
RUN go build -trimpath -o /out/api ./cmd/api && \
    go build -trimpath -o /out/migrate ./cmd/migrate

FROM debian:trixie-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/api /app/api
COPY --from=build /out/migrate /app/migrate
WORKDIR /app
EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=3s --retries=10 CMD curl -fsS http://127.0.0.1:8080/healthz || exit 1
ENTRYPOINT ["/app/api"]
