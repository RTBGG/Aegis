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

	Mailer string // "log" | "smtp"
	SMTP   SMTPConfig

	AgentToken string

	PDNSAPIURL string
	PDNSAPIKey string
	AssignedNS [2]string

	EdgePublicIP    string
	EdgeTLSMode     string // "internal" | "acme"
	ACMEEmail       string
	ChallengeSecret string

	// ThreatFeedSync enables the background fetcher that pulls IP-reputation
	// feeds (Spamhaus DROP, FireHOL). Set THREATFEED_SYNC=off in air-gapped
	// deployments; manual refresh from the admin UI still works either way.
	ThreatFeedSync bool

	// ClickHouse powers high-volume per-request analytics. Optional: when
	// CLICKHOUSE_URL is empty, the rich analytics endpoints report disabled and
	// the dashboard falls back to the coarse Postgres counters.
	ClickHouseURL      string
	ClickHouseDB       string
	ClickHouseUser     string
	ClickHousePassword string

	// GeoIP enriches analytics events with country + ASN using the free,
	// public-domain (PDDL) iptoasn.com IP-to-ASN database. Set GEOIP_ENABLED=off
	// to skip the download/enrichment.
	GeoIPEnabled bool
	GeoIPV4URL   string
	GeoIPV6URL   string
}

// SMTPConfig holds outbound mail settings used when MAILER=smtp.
type SMTPConfig struct {
	Addr     string // host:port, e.g. smtp.example.com:587
	Username string // empty => no SMTP AUTH (e.g. Mailpit)
	Password string
	From     string // envelope + header From address
	TLS      string // "starttls" (587) | "tls" (465, implicit) | "none"
	Insecure bool   // skip TLS cert verification (self-signed internal relays only)
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
		SMTP: SMTPConfig{
			Addr:     env("SMTP_ADDR", "mailpit:1025"),
			Username: os.Getenv("SMTP_USERNAME"),
			Password: os.Getenv("SMTP_PASSWORD"),
			From:     env("SMTP_FROM", "no-reply@"+env("AEGIS_BRAND", "Aegis")),
			TLS:      strings.ToLower(env("SMTP_TLS", "starttls")),
			Insecure: envBool("SMTP_TLS_INSECURE", false),
		},
		AgentToken:      os.Getenv("AGENT_TOKEN"),
		PDNSAPIURL:      env("PDNS_API_URL", "http://powerdns:8081"),
		PDNSAPIKey:      os.Getenv("PDNS_API_KEY"),
		AssignedNS:      [2]string{env("ASSIGNED_NS1", "ns1.aegis.example"), env("ASSIGNED_NS2", "ns2.aegis.example")},
		EdgePublicIP:    env("EDGE_PUBLIC_IP", "127.0.0.1"),
		EdgeTLSMode:     env("EDGE_TLS_MODE", "internal"),
		ACMEEmail:       env("ACME_EMAIL", "admin@example.com"),
		ChallengeSecret: os.Getenv("CHALLENGE_SECRET"),
		ThreatFeedSync:  envBool("THREATFEED_SYNC", true),

		ClickHouseURL:      os.Getenv("CLICKHOUSE_URL"),
		ClickHouseDB:       env("CLICKHOUSE_DB", "aegis"),
		ClickHouseUser:     env("CLICKHOUSE_USER", "default"),
		ClickHousePassword: os.Getenv("CLICKHOUSE_PASSWORD"),

		GeoIPEnabled: envBool("GEOIP_ENABLED", true),
		GeoIPV4URL:   env("GEOIP_V4_URL", "https://iptoasn.com/data/ip2asn-v4.tsv.gz"),
		GeoIPV6URL:   env("GEOIP_V6_URL", "https://iptoasn.com/data/ip2asn-v6.tsv.gz"),
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
	if c.Mailer == "smtp" {
		switch c.SMTP.TLS {
		case "starttls", "tls", "none":
		default:
			return nil, fmt.Errorf("SMTP_TLS must be 'starttls', 'tls' or 'none', got %q", c.SMTP.TLS)
		}
		if c.SMTP.Addr == "" {
			return nil, fmt.Errorf("SMTP_ADDR is required when MAILER=smtp")
		}
	}
	return c, nil
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// envBool reads a boolean-ish env var. "0", "false", "no", "off" (any case) are
// false; anything else non-empty is true; unset falls back to def.
func envBool(key string, def bool) bool {
	v := strings.TrimSpace(strings.ToLower(os.Getenv(key)))
	if v == "" {
		return def
	}
	switch v {
	case "0", "false", "no", "off":
		return false
	default:
		return true
	}
}
