package store

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
)

// InsertConfigBundle stores a newly rendered edge config and returns its version.
func (s *Store) InsertConfigBundle(ctx context.Context, caddyfile, checksum string) (int64, error) {
	var version int64
	err := s.Pool.QueryRow(ctx,
		`INSERT INTO config_bundles (caddyfile, checksum) VALUES ($1,$2) RETURNING version`,
		caddyfile, checksum).Scan(&version)
	return version, err
}

func (s *Store) GetLatestBundle(ctx context.Context) (*ConfigBundle, error) {
	rows, err := s.Pool.Query(ctx, `SELECT * FROM config_bundles ORDER BY version DESC LIMIT 1`)
	if err != nil {
		return nil, err
	}
	b, err := pgx.CollectOneRow(rows, pgx.RowToStructByNameLax[ConfigBundle])
	if err != nil {
		return nil, err
	}
	return &b, nil
}

// LatestChecksum returns the checksum of the newest bundle, or "" if none.
func (s *Store) LatestChecksum(ctx context.Context) (string, error) {
	var sum string
	err := s.Pool.QueryRow(ctx, `SELECT checksum FROM config_bundles ORDER BY version DESC LIMIT 1`).Scan(&sum)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	return sum, err
}
