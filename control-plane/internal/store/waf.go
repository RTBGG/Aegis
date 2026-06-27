package store

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ListWAFOverrides returns all per-route WAF overrides for a domain (for the UI).
func (s *Store) ListWAFOverrides(ctx context.Context, domainID uuid.UUID) ([]WAFRouteOverride, error) {
	rows, err := s.Pool.Query(ctx,
		`SELECT * FROM waf_route_overrides WHERE domain_id=$1 ORDER BY path, created_at`, domainID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByNameLax[WAFRouteOverride])
}

// ListWAFOverridesForRender returns the enabled overrides for a domain in a
// stable order, so the rendered Caddyfile (and its checksum) are deterministic.
func (s *Store) ListWAFOverridesForRender(ctx context.Context, domainID uuid.UUID) ([]WAFRouteOverride, error) {
	rows, err := s.Pool.Query(ctx,
		`SELECT * FROM waf_route_overrides WHERE domain_id=$1 AND enabled=true ORDER BY path, id`, domainID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByNameLax[WAFRouteOverride])
}

func (s *Store) CreateWAFOverride(ctx context.Context, o *WAFRouteOverride) (*WAFRouteOverride, error) {
	rows, err := s.Pool.Query(ctx,
		`INSERT INTO waf_route_overrides (domain_id, path, mode, excluded_rules, paranoia, enabled)
		 VALUES ($1,$2,$3,$4,$5,$6) RETURNING *`,
		o.DomainID, o.Path, o.Mode, o.ExcludedRules, o.Paranoia, o.Enabled)
	if err != nil {
		return nil, err
	}
	out, err := pgx.CollectOneRow(rows, pgx.RowToStructByNameLax[WAFRouteOverride])
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// DeleteWAFOverride removes an override, scoped by domain for ownership safety.
func (s *Store) DeleteWAFOverride(ctx context.Context, id, domainID uuid.UUID) error {
	_, err := s.Pool.Exec(ctx,
		`DELETE FROM waf_route_overrides WHERE id=$1 AND domain_id=$2`, id, domainID)
	return err
}
