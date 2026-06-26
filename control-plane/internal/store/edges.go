package store

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func (s *Store) ListEdges(ctx context.Context) ([]Edge, error) {
	rows, err := s.Pool.Query(ctx, `SELECT * FROM edges ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByNameLax[Edge])
}

// ListHealthyEdgeIPs returns the public IPs of edges eligible to serve traffic.
func (s *Store) ListHealthyEdgeIPs(ctx context.Context) ([]string, error) {
	rows, err := s.Pool.Query(ctx,
		`SELECT public_ip FROM edges WHERE status IN ('healthy','pending') ORDER BY public_ip`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ips []string
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			return nil, err
		}
		ips = append(ips, ip)
	}
	return ips, rows.Err()
}

func (s *Store) GetEdge(ctx context.Context, id uuid.UUID) (*Edge, error) {
	rows, err := s.Pool.Query(ctx, `SELECT * FROM edges WHERE id=$1`, id)
	if err != nil {
		return nil, err
	}
	e, err := pgx.CollectOneRow(rows, pgx.RowToStructByNameLax[Edge])
	if err != nil {
		return nil, err
	}
	return &e, nil
}

func (s *Store) GetEdgeByName(ctx context.Context, name string) (*Edge, error) {
	rows, err := s.Pool.Query(ctx, `SELECT * FROM edges WHERE name=$1`, name)
	if err != nil {
		return nil, err
	}
	e, err := pgx.CollectOneRow(rows, pgx.RowToStructByNameLax[Edge])
	if err != nil {
		return nil, err
	}
	return &e, nil
}

// UpsertEdge inserts or refreshes an edge by name (used to seed the local edge).
func (s *Store) UpsertEdge(ctx context.Context, name, publicIP, region string) (*Edge, error) {
	rows, err := s.Pool.Query(ctx,
		`INSERT INTO edges (name, public_ip, region) VALUES ($1,$2,$3)
		 ON CONFLICT (name) DO UPDATE SET public_ip=EXCLUDED.public_ip, region=EXCLUDED.region
		 RETURNING *`, name, publicIP, region)
	if err != nil {
		return nil, err
	}
	e, err := pgx.CollectOneRow(rows, pgx.RowToStructByNameLax[Edge])
	if err != nil {
		return nil, err
	}
	return &e, nil
}

func (s *Store) EdgeHeartbeat(ctx context.Context, id uuid.UUID, agentVersion, status string) error {
	_, err := s.Pool.Exec(ctx,
		`UPDATE edges SET last_seen_at=now(), agent_version=$2, status=$3 WHERE id=$1`,
		id, agentVersion, status)
	return err
}

// --- enrollment tokens (Phase 3 multi-node; CRUD available now) ---

func (s *Store) CreateEnrollmentToken(ctx context.Context, tokenHash, note string, createdBy *uuid.UUID, expires time.Time) (*EnrollmentToken, error) {
	rows, err := s.Pool.Query(ctx,
		`INSERT INTO enrollment_tokens (token_hash, note, created_by, expires_at)
		 VALUES ($1,$2,$3,$4) RETURNING *`, tokenHash, note, createdBy, expires)
	if err != nil {
		return nil, err
	}
	t, err := pgx.CollectOneRow(rows, pgx.RowToStructByNameLax[EnrollmentToken])
	if err != nil {
		return nil, err
	}
	return &t, nil
}

func (s *Store) ListEnrollmentTokens(ctx context.Context) ([]EnrollmentToken, error) {
	rows, err := s.Pool.Query(ctx, `SELECT * FROM enrollment_tokens ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByNameLax[EnrollmentToken])
}

// ConsumeEnrollmentToken validates and single-uses a token, returning its id.
func (s *Store) ConsumeEnrollmentToken(ctx context.Context, tokenHash string) (uuid.UUID, error) {
	var id uuid.UUID
	err := s.Pool.QueryRow(ctx,
		`UPDATE enrollment_tokens SET used_at=now()
		 WHERE token_hash=$1 AND used_at IS NULL AND expires_at>now()
		 RETURNING id`, tokenHash).Scan(&id)
	return id, err
}
