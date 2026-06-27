package store

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// GetOrCreatePolicy returns the security policy for a domain, creating a
// default row if none exists.
func (s *Store) GetOrCreatePolicy(ctx context.Context, domainID uuid.UUID) (*SecurityPolicy, error) {
	rows, err := s.Pool.Query(ctx,
		`INSERT INTO security_policies (domain_id) VALUES ($1)
		 ON CONFLICT (domain_id) DO UPDATE SET domain_id = EXCLUDED.domain_id
		 RETURNING *`, domainID)
	if err != nil {
		return nil, err
	}
	p, err := pgx.CollectOneRow(rows, pgx.RowToStructByNameLax[SecurityPolicy])
	if err != nil {
		return nil, err
	}
	return &p, nil
}

func (s *Store) UpdatePolicy(ctx context.Context, p *SecurityPolicy) (*SecurityPolicy, error) {
	rows, err := s.Pool.Query(ctx, `
		UPDATE security_policies SET
			https_redirect=$2, min_tls=$3,
			waf_enabled=$4, waf_paranoia=$5, waf_mode=$6, waf_custom_rules=$14,
			rate_limit_enabled=$7, rate_limit_rpm=$8, rate_limit_burst=$9,
			cache_enabled=$10, cache_ttl=$11,
			bot_protection=$12, challenge_enabled=$13,
			bot_allow_verified=$15, challenge_mode=$16,
			captcha_provider=$17, captcha_sitekey=$18,
			-- write-only secret: a blank value leaves the stored secret untouched
			captcha_secret = CASE WHEN $19 = '' THEN captcha_secret ELSE $19 END,
			updated_at=now()
		WHERE domain_id=$1 RETURNING *`,
		p.DomainID, p.HTTPSRedirect, p.MinTLS,
		p.WAFEnabled, p.WAFParanoia, p.WAFMode,
		p.RateLimitEnabled, p.RateLimitRPM, p.RateLimitBurst,
		p.CacheEnabled, p.CacheTTL,
		p.BotProtection, p.ChallengeEnabled, p.WAFCustomRules,
		p.BotAllowVerified, p.ChallengeMode,
		p.CaptchaProvider, p.CaptchaSitekey, p.CaptchaSecret)
	if err != nil {
		return nil, err
	}
	out, err := pgx.CollectOneRow(rows, pgx.RowToStructByNameLax[SecurityPolicy])
	if err != nil {
		return nil, err
	}
	return &out, nil
}
