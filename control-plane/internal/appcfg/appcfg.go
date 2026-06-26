// Package appcfg loads runtime configuration from the environment.
package appcfg

import (
	"fmt"
	"os"
	"strings"
)

// Config holds all runtime configuration for the control-plane API.
type Config struct {
	Brand           string
	Port            string
	ControlPlaneURL string
	DashboardURL    string

	DatabaseURL string
	RedisURL    string

	SessionSecret []byte
	CSRFSecret    []byte

	BootstrapAdminEmail    string
	BootstrapAdminPassword string

	Mailer   string // "log" | "smtp"
	SMTPAddr string

	AgentToken string

	PDNSAPIURL string
	PDNSAPIKey string
	AssignedNS [2]string

	EdgePublicIP    string
	EdgeTLSMode     string // "internal" | "acme"
	ACMEEmail       string
	ChallengeSecret string
}

// Load reads configuration from the environment, applying defaults and
// validating required values.
func Load() (*Config, error) {
	c := &Config{
		Brand:                  env("AEGIS_BRAND", "Aegis"),
		Port:                   env("CONTROL_PLANE_PORT", "8080"),
		ControlPlaneURL:        env("CONTROL_PLANE_URL", "http://localhost:8080"),
		DashboardURL:           env("DASHBOARD_URL", "http://localhost:3000"),
		DatabaseURL:            os.Getenv("DATABASE_URL"),
		RedisURL:               env("REDIS_URL", "redis://localhost:6379/0"),
		BootstrapAdminEmail:    env("BOOTSTRAP_ADMIN_EMAIL", "admin@example.com"),
		BootstrapAdminPassword: os.Getenv("BOOTSTRAP_ADMIN_PASSWORD"),
		Mailer:                 env("MAILER", "log"),
		SMTPAddr:               env("SMTP_ADDR", "mailpit:1025"),
		AgentToken:             os.Getenv("AGENT_TOKEN"),
		PDNSAPIURL:             env("PDNS_API_URL", "http://powerdns:8081"),
		PDNSAPIKey:             os.Getenv("PDNS_API_KEY"),
		AssignedNS:             [2]string{env("ASSIGNED_NS1", "ns1.aegis.example"), env("ASSIGNED_NS2", "ns2.aegis.example")},
		EdgePublicIP:           env("EDGE_PUBLIC_IP", "127.0.0.1"),
		EdgeTLSMode:            env("EDGE_TLS_MODE", "internal"),
		ACMEEmail:              env("ACME_EMAIL", "admin@example.com"),
		ChallengeSecret:        os.Getenv("CHALLENGE_SECRET"),
	}
	c.SessionSecret = []byte(os.Getenv("SESSION_SECRET"))
	c.CSRFSecret = []byte(os.Getenv("CSRF_SECRET"))

	var missing []string
	if c.DatabaseURL == "" {
		missing = append(missing, "DATABASE_URL")
	}
	if len(c.SessionSecret) < 16 {
		missing = append(missing, "SESSION_SECRET(>=16 bytes)")
	}
	if len(c.CSRFSecret) < 16 {
		missing = append(missing, "CSRF_SECRET(>=16 bytes)")
	}
	if c.AgentToken == "" {
		missing = append(missing, "AGENT_TOKEN")
	}
	if c.ChallengeSecret == "" {
		missing = append(missing, "CHALLENGE_SECRET")
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("missing/invalid required env: %s", strings.Join(missing, ", "))
	}
	if c.EdgeTLSMode != "internal" && c.EdgeTLSMode != "acme" {
		return nil, fmt.Errorf("EDGE_TLS_MODE must be 'internal' or 'acme', got %q", c.EdgeTLSMode)
	}
	return c, nil
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
