package store

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func (s *Store) CreateDomain(ctx context.Context, accountID uuid.UUID, name, verificationToken string) (*Domain, error) {
	rows, err := s.Pool.Query(ctx,
		`INSERT INTO domains (account_id, name, verification_token) VALUES ($1,$2,$3) RETURNING *`,
		accountID, name, verificationToken)
	if err != nil {
		return nil, err
	}
	d, err := pgx.CollectOneRow(rows, pgx.RowToStructByNameLax[Domain])
	if err != nil {
		return nil, err
	}
	return &d, nil
}

func (s *Store) GetDomain(ctx context.Context, id uuid.UUID) (*Domain, error) {
	rows, err := s.Pool.Query(ctx, `SELECT * FROM domains WHERE id=$1`, id)
	if err != nil {
		return nil, err
	}
	d, err := pgx.CollectOneRow(rows, pgx.RowToStructByNameLax[Domain])
	if err != nil {
		return nil, err
	}
	return &d, nil
}

// GetDomainOwned fetches a domain only if it belongs to the given account.
func (s *Store) GetDomainOwned(ctx context.Context, id, accountID uuid.UUID) (*Domain, error) {
	rows, err := s.Pool.Query(ctx, `SELECT * FROM domains WHERE id=$1 AND account_id=$2`, id, accountID)
	if err != nil {
		return nil, err
	}
	d, err := pgx.CollectOneRow(rows, pgx.RowToStructByNameLax[Domain])
	if err != nil {
		return nil, err
	}
	return &d, nil
}

func (s *Store) GetDomainByName(ctx context.Context, name string) (*Domain, error) {
	rows, err := s.Pool.Query(ctx, `SELECT * FROM domains WHERE name=$1`, name)
	if err != nil {
		return nil, err
	}
	d, err := pgx.CollectOneRow(rows, pgx.RowToStructByNameLax[Domain])
	if err != nil {
		return nil, err
	}
	return &d, nil
}

func (s *Store) ListDomainsByAccount(ctx context.Context, accountID uuid.UUID) ([]Domain, error) {
	rows, err := s.Pool.Query(ctx, `SELECT * FROM domains WHERE account_id=$1 ORDER BY created_at DESC`, accountID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByNameLax[Domain])
}

// ListActiveDomainsForRender returns domains the edge should serve.
func (s *Store) ListActiveDomainsForRender(ctx context.Context) ([]Domain, error) {
	rows, err := s.Pool.Query(ctx,
		`SELECT * FROM domains WHERE status='active' AND paused=false ORDER BY name`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByNameLax[Domain])
}

func (s *Store) MarkDomainVerified(ctx context.Context, id uuid.UUID) error {
	_, err := s.Pool.Exec(ctx,
		`UPDATE domains SET status='active', verified_at=now() WHERE id=$1`, id)
	return err
}

func (s *Store) SetDomainPaused(ctx context.Context, id uuid.UUID, paused bool) error {
	_, err := s.Pool.Exec(ctx, `UPDATE domains SET paused=$2 WHERE id=$1`, id, paused)
	return err
}

func (s *Store) DeleteDomain(ctx context.Context, id uuid.UUID) error {
	_, err := s.Pool.Exec(ctx, `DELETE FROM domains WHERE id=$1`, id)
	return err
}
