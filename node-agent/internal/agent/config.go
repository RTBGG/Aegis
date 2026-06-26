// Package agent is the Aegis edge node-agent: it pulls rendered Caddyfile config
// from the control plane, applies it to a managed Caddy process, and reports
// telemetry drained from the edge's Redis counters.
package agent

import (
	"os"
	"path/filepath"
	"time"
)

const Version = "0.1.0-phase1"

type Config struct {
	ControlPlaneURL   string // internal API base, e.g. http://api:8080
	AgentToken        string
	EdgeName          string
	PublicIP          string
	CaddyBin          string
	Caddyfile         string
	SitesDir          string
	CaddyAdmin        string
	RedisAddr         string
	TelemetryInterval time.Duration
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func LoadConfig() Config {
	return Config{
		ControlPlaneURL:   env("CONTROL_PLANE_URL", "http://api:8080"),
		AgentToken:        os.Getenv("AGENT_TOKEN"),
		EdgeName:          env("EDGE_NAME", "local-edge"),
		PublicIP:          env("EDGE_PUBLIC_IP", ""),
		CaddyBin:          env("CADDY_BIN", "/usr/bin/caddy"),
		Caddyfile:         env("CADDYFILE", "/etc/caddy/Caddyfile"),
		SitesDir:          env("SITES_DIR", "/etc/caddy/sites"),
		CaddyAdmin:        env("CADDY_ADMIN", "127.0.0.1:2019"),
		RedisAddr:         env("AEGIS_REDIS", "redis:6379"),
		TelemetryInterval: 15 * time.Second,
	}
}

func (c Config) dynamicFile() string {
	return filepath.Join(c.SitesDir, "dynamic.caddy")
}
