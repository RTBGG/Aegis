package store

import (
	"time"

	"github.com/google/uuid"
)

type Account struct {
	ID        uuid.UUID `db:"id"`
	Name      string    `db:"name"`
	CreatedAt time.Time `db:"created_at"`
}

type User struct {
	ID            uuid.UUID  `db:"id"`
	AccountID     uuid.UUID  `db:"account_id"`
	Email         string     `db:"email"`
	PasswordHash  string     `db:"password_hash"`
	Role          string     `db:"role"`
	Status        string     `db:"status"`
	EmailVerified bool       `db:"email_verified"`
	TOTPSecret    *string    `db:"totp_secret"`
	TOTPEnabled   bool       `db:"totp_enabled"`
	CreatedAt     time.Time  `db:"created_at"`
	LastLoginAt   *time.Time `db:"last_login_at"`
}

type Domain struct {
	ID                uuid.UUID  `db:"id"`
	AccountID         uuid.UUID  `db:"account_id"`
	Name              string     `db:"name"`
	Status            string     `db:"status"`
	Paused            bool       `db:"paused"`
	VerificationToken string     `db:"verification_token"`
	VerifiedAt        *time.Time `db:"verified_at"`
	CreatedAt         time.Time  `db:"created_at"`
}

type DNSRecord struct {
	ID        uuid.UUID `db:"id"`
	DomainID  uuid.UUID `db:"domain_id"`
	Type      string    `db:"type"`
	Name      string    `db:"name"`
	Content   string    `db:"content"`
	TTL       int32     `db:"ttl"`
	Priority  *int32    `db:"priority"`
	Proxied   bool      `db:"proxied"`
	CreatedAt time.Time `db:"created_at"`
	UpdatedAt time.Time `db:"updated_at"`
}

type SecurityPolicy struct {
	ID               uuid.UUID `db:"id"`
	DomainID         uuid.UUID `db:"domain_id"`
	HTTPSRedirect    bool      `db:"https_redirect"`
	MinTLS           string    `db:"min_tls"`
	WAFEnabled       bool      `db:"waf_enabled"`
	WAFParanoia      int32     `db:"waf_paranoia"`
	WAFMode          string    `db:"waf_mode"`
	WAFCustomRules   string    `db:"waf_custom_rules"`
	RateLimitEnabled bool      `db:"rate_limit_enabled"`
	RateLimitRPM     int32     `db:"rate_limit_rpm"`
	RateLimitBurst   int32     `db:"rate_limit_burst"`
	CacheEnabled     bool      `db:"cache_enabled"`
	CacheTTL         int32     `db:"cache_ttl"`
	BotProtection    string    `db:"bot_protection"`
	BotAllowVerified bool      `db:"bot_allow_verified"`
	ChallengeEnabled bool      `db:"challenge_enabled"`
	ChallengeMode    string    `db:"challenge_mode"`
	CaptchaProvider  string    `db:"captcha_provider"`
	CaptchaSitekey   string    `db:"captcha_sitekey"`
	CaptchaSecret    string    `db:"captcha_secret"`
	UpdatedAt        time.Time `db:"updated_at"`
}

type WAFRouteOverride struct {
	ID            uuid.UUID `db:"id" json:"id"`
	DomainID      uuid.UUID `db:"domain_id" json:"domain_id"`
	Path          string    `db:"path" json:"path"`
	Mode          string    `db:"mode" json:"mode"`
	ExcludedRules string    `db:"excluded_rules" json:"excluded_rules"`
	Paranoia      *int32    `db:"paranoia" json:"paranoia"`
	Enabled       bool      `db:"enabled" json:"enabled"`
	CreatedAt     time.Time `db:"created_at" json:"created_at"`
}

type Edge struct {
	ID             uuid.UUID  `db:"id" json:"id"`
	Name           string     `db:"name" json:"name"`
	PublicIP       string     `db:"public_ip" json:"public_ip"`
	Region         string     `db:"region" json:"region"`
	Status         string     `db:"status" json:"status"`
	Weight         int32      `db:"weight" json:"weight"`
	AgentVersion   *string    `db:"agent_version" json:"agent_version"`
	AgentTokenHash *string    `db:"agent_token_hash" json:"-"`
	EnrolledAt     *time.Time `db:"enrolled_at" json:"enrolled_at"`
	CertSerial     *string    `db:"cert_serial" json:"-"`
	CertExpiresAt  *time.Time `db:"cert_expires_at" json:"cert_expires_at"`
	RevokedAt      *time.Time `db:"revoked_at" json:"revoked_at"`
	LastSeenAt     *time.Time `db:"last_seen_at" json:"last_seen_at"`
	CreatedAt      time.Time  `db:"created_at" json:"created_at"`
}

type EnrollmentToken struct {
	ID        uuid.UUID  `db:"id"`
	TokenHash string     `db:"token_hash"`
	Note      *string    `db:"note"`
	CreatedBy *uuid.UUID `db:"created_by"`
	ExpiresAt time.Time  `db:"expires_at"`
	UsedAt    *time.Time `db:"used_at"`
	EdgeID    *uuid.UUID `db:"edge_id"`
	CreatedAt time.Time  `db:"created_at"`
}

type Blocklist struct {
	ID        uuid.UUID  `db:"id" json:"id"`
	Scope     string     `db:"scope" json:"scope"`
	DomainID  *uuid.UUID `db:"domain_id" json:"domain_id"`
	Kind      string     `db:"kind" json:"kind"`
	Value     string     `db:"value" json:"value"`
	Action    string     `db:"action" json:"action"`
	Note      *string    `db:"note" json:"note"`
	CreatedAt time.Time  `db:"created_at" json:"created_at"`
}

type ThreatFeed struct {
	ID              uuid.UUID  `db:"id"`
	Slug            string     `db:"slug"`
	Name            string     `db:"name"`
	URL             string     `db:"url"`
	Format          string     `db:"format"`
	Action          string     `db:"action"`
	Enabled         bool       `db:"enabled"`
	RefreshInterval int32      `db:"refresh_interval"`
	LastSyncedAt    *time.Time `db:"last_synced_at"`
	LastStatus      *string    `db:"last_status"`
	LastError       *string    `db:"last_error"`
	EntryCount      int32      `db:"entry_count"`
	CreatedAt       time.Time  `db:"created_at"`
	UpdatedAt       time.Time  `db:"updated_at"`
}

type ConfigBundle struct {
	Version   int64     `db:"version"`
	Caddyfile string    `db:"caddyfile"`
	Checksum  string    `db:"checksum"`
	CreatedAt time.Time `db:"created_at"`
}

type EdgeMetric struct {
	EdgeID      *uuid.UUID `db:"edge_id"`
	DomainID    *uuid.UUID `db:"domain_id"`
	TS          time.Time  `db:"ts"`
	Requests    int64      `db:"requests"`
	BlockedWAF  int64      `db:"blocked_waf"`
	BlockedRate int64      `db:"blocked_rate"`
	Challenged  int64      `db:"challenged"`
	CacheHits   int64      `db:"cache_hits"`
	CacheMiss   int64      `db:"cache_miss"`
	Bytes       int64      `db:"bytes"`
}
