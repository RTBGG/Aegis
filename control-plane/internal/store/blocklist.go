package store

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func (s *Store) CreateBlocklist(ctx context.Context, b *Blocklist) (*Blocklist, error) {
	rows, err := s.Pool.Query(ctx,
		`INSERT INTO blocklists (scope, domain_id, kind, value, action, note)
		 VALUES ($1,$2,$3,$4,$5,$6) RETURNING *`,
		b.Scope, b.DomainID, b.Kind, b.Value, b.Action, b.Note)
	if err != nil {
		return nil, err
	}
	out, err := pgx.CollectOneRow(rows, pgx.RowToStructByNameLax[Blocklist])
	if err != nil {
		return nil, err
	}
	return &out, nil
}

func (s *Store) ListBlocklists(ctx context.Context) ([]Blocklist, error) {
	rows, err := s.Pool.Query(ctx, `SELECT * FROM blocklists ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByNameLax[Blocklist])
}

func (s *Store) ListBlocklistsForDomain(ctx context.Context, domainID uuid.UUID) ([]Blocklist, error) {
	rows, err := s.Pool.Query(ctx,
		`SELECT * FROM blocklists WHERE scope='global' OR (scope='domain' AND domain_id=$1) ORDER BY created_at`,
		domainID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByNameLax[Blocklist])
}

func (s *Store) DeleteBlocklist(ctx context.Context, id uuid.UUID) error {
	_, err := s.Pool.Exec(ctx, `DELETE FROM blocklists WHERE id=$1`, id)
	return err
}
