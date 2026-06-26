package store

import (
	"context"
	"encoding/json"

	"github.com/google/uuid"
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
