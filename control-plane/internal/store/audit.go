package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Audit appends an entry to the audit log. metadata may be nil.
func (s *Store) Audit(ctx context.Context, accountID, actorID *uuid.UUID, action, target, ip string, metadata map[string]any) error {
	var raw []byte
	if metadata != nil {
		b, err := json.Marshal(metadata)
		if err != nil {
			return err
		}
		raw = b
	}
	_, err := s.Pool.Exec(ctx,
		`INSERT INTO audit_log (account_id, actor_user_id, action, target, metadata, ip)
		 VALUES ($1,$2,$3,$4,$5,$6)`,
		accountID, actorID, action, target, raw, ip)
	return err
}

// AuditEntry is a joined audit row (actor email resolved) for admin views.
type AuditEntry struct {
	ID         int64     `db:"id"`
	Action     string    `db:"action"`
	ActorEmail *string   `db:"actor_email"`
	Target     *string   `db:"target"`
	IP         *string   `db:"ip"`
	CreatedAt  time.Time `db:"created_at"`
}

// ListImpersonationAudit returns the most recent impersonation start/stop events.
func (s *Store) ListImpersonationAudit(ctx context.Context, limit int) ([]AuditEntry, error) {
	rows, err := s.Pool.Query(ctx, `
		SELECT al.id, al.action, u.email AS actor_email, al.target, al.ip, al.created_at
		FROM audit_log al
		LEFT JOIN users u ON u.id = al.actor_user_id
		WHERE al.action IN ('admin.impersonate_start','admin.impersonate_stop')
		ORDER BY al.created_at DESC
		LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByNameLax[AuditEntry])
}
