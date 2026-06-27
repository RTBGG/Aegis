package store

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ErrNotFound is returned when a lookup matches no rows.
var ErrNotFound = pgx.ErrNoRows

// CreateAccountWithUser creates an account and its first (owner) user atomically.
func (s *Store) CreateAccountWithUser(ctx context.Context, accountName, email, passwordHash, role string) (*User, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	var accID uuid.UUID
	if err := tx.QueryRow(ctx, `INSERT INTO accounts (name) VALUES ($1) RETURNING id`, accountName).Scan(&accID); err != nil {
		return nil, err
	}
	rows, err := tx.Query(ctx,
		`INSERT INTO users (account_id, email, password_hash, role) VALUES ($1,$2,$3,$4) RETURNING *`,
		accID, email, passwordHash, role)
	if err != nil {
		return nil, err
	}
	u, err := pgx.CollectOneRow(rows, pgx.RowToStructByNameLax[User])
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &u, nil
}

func (s *Store) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	rows, err := s.Pool.Query(ctx, `SELECT * FROM users WHERE lower(email)=lower($1)`, email)
	if err != nil {
		return nil, err
	}
	u, err := pgx.CollectOneRow(rows, pgx.RowToStructByNameLax[User])
	if err != nil {
		return nil, err
	}
	return &u, nil
}

func (s *Store) GetUserByID(ctx context.Context, id uuid.UUID) (*User, error) {
	rows, err := s.Pool.Query(ctx, `SELECT * FROM users WHERE id=$1`, id)
	if err != nil {
		return nil, err
	}
	u, err := pgx.CollectOneRow(rows, pgx.RowToStructByNameLax[User])
	if err != nil {
		return nil, err
	}
	return &u, nil
}

func (s *Store) CountUsers(ctx context.Context) (int64, error) {
	var n int64
	err := s.Pool.QueryRow(ctx, `SELECT count(*) FROM users`).Scan(&n)
	return n, err
}

func (s *Store) TouchLastLogin(ctx context.Context, id uuid.UUID) error {
	_, err := s.Pool.Exec(ctx, `UPDATE users SET last_login_at=now() WHERE id=$1`, id)
	return err
}

func (s *Store) SetTOTPSecret(ctx context.Context, id uuid.UUID, secret string) error {
	_, err := s.Pool.Exec(ctx, `UPDATE users SET totp_secret=$2 WHERE id=$1`, id, secret)
	return err
}

func (s *Store) SetTOTPEnabled(ctx context.Context, id uuid.UUID, enabled bool) error {
	_, err := s.Pool.Exec(ctx, `UPDATE users SET totp_enabled=$2 WHERE id=$1`, id, enabled)
	return err
}

func (s *Store) MarkEmailVerified(ctx context.Context, id uuid.UUID) error {
	_, err := s.Pool.Exec(ctx, `UPDATE users SET email_verified=true WHERE id=$1`, id)
	return err
}

func (s *Store) SetUserStatus(ctx context.Context, id uuid.UUID, status string) error {
	_, err := s.Pool.Exec(ctx, `UPDATE users SET status=$2 WHERE id=$1`, id, status)
	return err
}

// --- email verification / reset tokens ---

func (s *Store) CreateEmailToken(ctx context.Context, userID uuid.UUID, tokenHash, purpose string, expires time.Time) error {
	_, err := s.Pool.Exec(ctx,
		`INSERT INTO email_tokens (user_id, token_hash, purpose, expires_at) VALUES ($1,$2,$3,$4)`,
		userID, tokenHash, purpose, expires)
	return err
}

// ConsumeEmailToken validates and single-uses a token, returning the user id.
func (s *Store) ConsumeEmailToken(ctx context.Context, tokenHash, purpose string) (uuid.UUID, error) {
	var userID uuid.UUID
	err := s.Pool.QueryRow(ctx,
		`UPDATE email_tokens SET used_at=now()
		 WHERE token_hash=$1 AND purpose=$2 AND used_at IS NULL AND expires_at>now()
		 RETURNING user_id`, tokenHash, purpose).Scan(&userID)
	return userID, err
}

// --- admin listing ---

// AdminUserRow is the admin view of a user joined with account + domain count.
// json tags must stay snake_case to match the dashboard's AdminUser type.
type AdminUserRow struct {
	ID            uuid.UUID  `db:"id" json:"id"`
	Email         string     `db:"email" json:"email"`
	Role          string     `db:"role" json:"role"`
	Status        string     `db:"status" json:"status"`
	EmailVerified bool       `db:"email_verified" json:"email_verified"`
	TOTPEnabled   bool       `db:"totp_enabled" json:"totp_enabled"`
	CreatedAt     time.Time  `db:"created_at" json:"created_at"`
	LastLoginAt   *time.Time `db:"last_login_at" json:"last_login_at"`
	AccountID     uuid.UUID  `db:"account_id" json:"account_id"`
	AccountName   string     `db:"account_name" json:"account_name"`
	DomainCount   int64      `db:"domain_count" json:"domain_count"`
}

func (s *Store) ListUsersWithStats(ctx context.Context) ([]AdminUserRow, error) {
	rows, err := s.Pool.Query(ctx, `
		SELECT u.id, u.email, u.role, u.status, u.email_verified, u.totp_enabled,
		       u.created_at, u.last_login_at, u.account_id,
		       a.name AS account_name,
		       count(DISTINCT d.id) AS domain_count
		FROM users u
		JOIN accounts a ON a.id = u.account_id
		LEFT JOIN domains d ON d.account_id = u.account_id
		GROUP BY u.id, a.name
		ORDER BY u.created_at DESC`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByNameLax[AdminUserRow])
}
