// Package agent is the Aegis edge node-agent: it pulls rendered Caddyfile config
// from the control plane, applies it to a managed Caddy process, and reports
// telemetry drained from the edge's Redis counters.
package agent

import (
	"crypto/tls"
	"crypto/x509"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

const Version = "0.1.0-phase1"

type Config struct {
	ControlPlaneURL   string // edge API base; the mTLS URL when enrolled with certs
	AgentToken        string
	EdgeName          string
	PublicIP          string
	CaddyBin          string
	Caddyfile         string
	SitesDir          string
	CaddyAdmin        string
	RedisAddr         string
	TelemetryInterval time.Duration

	// mTLS (post-enrollment): per-node client cert/key + CA. When all three are
	// present the agent talks to the control plane over mutual TLS.
	CertFile  string
	KeyFile   string
	CAFile    string
	transport *http.Transport
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func LoadConfig() Config {
	c := Config{
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
		CertFile:          os.Getenv("EDGE_CERT_FILE"),
		KeyFile:           os.Getenv("EDGE_KEY_FILE"),
		CAFile:            os.Getenv("EDGE_CA_FILE"),
	}
	c.transport = buildTransport(c)
	return c
}

// buildTransport returns an mTLS HTTP transport when per-node certs are
// configured and loadable; otherwise nil (the default transport is used).
func buildTransport(c Config) *http.Transport {
	if c.CertFile == "" || c.KeyFile == "" || c.CAFile == "" {
		return nil
	}
	if _, err := tls.LoadX509KeyPair(c.CertFile, c.KeyFile); err != nil {
		slog.Warn("mtls: load client keypair failed; using plain transport", "err", err)
		return nil
	}
	caPEM, err := os.ReadFile(c.CAFile)
	if err != nil {
		slog.Warn("mtls: read CA failed; using plain transport", "err", err)
		return nil
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		slog.Warn("mtls: no certs in CA file; using plain transport")
		return nil
	}
	// Load the client cert per-handshake so a rotated cert is picked up on new
	// connections without restarting the agent.
	certFile, keyFile := c.CertFile, c.KeyFile
	slog.Info("edge mTLS enabled", "cert", certFile)
	return &http.Transport{TLSClientConfig: &tls.Config{
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			cert, err := tls.LoadX509KeyPair(certFile, keyFile)
			return &cert, err
		},
		RootCAs:    pool,
		MinVersion: tls.VersionTLS12,
	}}
}

func (c Config) dynamicFile() string {
	return filepath.Join(c.SitesDir, "dynamic.caddy")
}
