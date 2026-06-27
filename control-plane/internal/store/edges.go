package store

import (
	"context"
	"errors"
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

// GetEdgeByTokenHash resolves an edge from its per-node agent token hash.
func (s *Store) GetEdgeByTokenHash(ctx context.Context, tokenHash string) (*Edge, error) {
	rows, err := s.Pool.Query(ctx, `SELECT * FROM edges WHERE agent_token_hash=$1`, tokenHash)
	if err != nil {
		return nil, err
	}
	e, err := pgx.CollectOneRow(rows, pgx.RowToStructByNameLax[Edge])
	if err != nil {
		return nil, err
	}
	return &e, nil
}

// EnrollEdge atomically consumes a single-use enrollment token and registers (or
// re-registers) an edge by name with a fresh per-node agent token. ErrNotFound
// is returned when the enrollment token is missing, expired or already used.
func (s *Store) EnrollEdge(ctx context.Context, enrollTokenHash, name, publicIP, region, agentTokenHash string) (*Edge, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	var tokenID uuid.UUID
	err = tx.QueryRow(ctx,
		`UPDATE enrollment_tokens SET used_at=now()
		 WHERE token_hash=$1 AND used_at IS NULL AND expires_at>now()
		 RETURNING id`, enrollTokenHash).Scan(&tokenID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	} else if err != nil {
		return nil, err
	}

	rows, err := tx.Query(ctx,
		`INSERT INTO edges (name, public_ip, region, status, agent_token_hash, enrolled_at)
		 VALUES ($1,$2,$3,'pending',$4, now())
		 ON CONFLICT (name) DO UPDATE SET
		     public_ip=EXCLUDED.public_ip, region=EXCLUDED.region,
		     status='pending', agent_token_hash=EXCLUDED.agent_token_hash, enrolled_at=now()
		 RETURNING *`, name, publicIP, region, agentTokenHash)
	if err != nil {
		return nil, err
	}
	edge, err := pgx.CollectOneRow(rows, pgx.RowToStructByNameLax[Edge])
	if err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `UPDATE enrollment_tokens SET edge_id=$1 WHERE id=$2`, edge.ID, tokenID); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &edge, nil
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
