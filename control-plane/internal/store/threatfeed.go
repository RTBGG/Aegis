package store

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func (s *Store) ListThreatFeeds(ctx context.Context) ([]ThreatFeed, error) {
	rows, err := s.Pool.Query(ctx, `SELECT * FROM threat_feeds ORDER BY name`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByNameLax[ThreatFeed])
}

func (s *Store) GetThreatFeed(ctx context.Context, id uuid.UUID) (*ThreatFeed, error) {
	rows, err := s.Pool.Query(ctx, `SELECT * FROM threat_feeds WHERE id=$1`, id)
	if err != nil {
		return nil, err
	}
	f, err := pgx.CollectOneRow(rows, pgx.RowToStructByNameLax[ThreatFeed])
	if err != nil {
		return nil, err
	}
	return &f, nil
}

// DueThreatFeeds returns enabled feeds that have never synced or whose last
// successful sync is older than their refresh interval.
func (s *Store) DueThreatFeeds(ctx context.Context) ([]ThreatFeed, error) {
	rows, err := s.Pool.Query(ctx,
		`SELECT * FROM threat_feeds
		 WHERE enabled = true
		   AND (last_synced_at IS NULL
		        OR last_synced_at < now() - make_interval(secs => refresh_interval))
		 ORDER BY name`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByNameLax[ThreatFeed])
}

// SetThreatFeedEnabled toggles a feed on/off.
func (s *Store) SetThreatFeedEnabled(ctx context.Context, id uuid.UUID, enabled bool) error {
	_, err := s.Pool.Exec(ctx,
		`UPDATE threat_feeds SET enabled=$2, updated_at=now() WHERE id=$1`, id, enabled)
	return err
}

// ReplaceThreatFeedEntries atomically swaps a feed's CIDR set for a fresh one
// and marks the sync successful. cidrs must already be de-duplicated.
func (s *Store) ReplaceThreatFeedEntries(ctx context.Context, feedID uuid.UUID, cidrs []string) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx, `DELETE FROM threat_feed_entries WHERE feed_id=$1`, feedID); err != nil {
		return err
	}
	if len(cidrs) > 0 {
		src := pgx.CopyFromSlice(len(cidrs), func(i int) ([]any, error) {
			return []any{feedID, cidrs[i]}, nil
		})
		if _, err := tx.CopyFrom(ctx, pgx.Identifier{"threat_feed_entries"}, []string{"feed_id", "cidr"}, src); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(ctx,
		`UPDATE threat_feeds
		 SET entry_count=$2, last_synced_at=now(), last_status='ok', last_error=NULL, updated_at=now()
		 WHERE id=$1`, feedID, len(cidrs)); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// SetThreatFeedError records a failed sync without disturbing the existing
// (last-known-good) entries.
func (s *Store) SetThreatFeedError(ctx context.Context, feedID uuid.UUID, msg string) error {
	_, err := s.Pool.Exec(ctx,
		`UPDATE threat_feeds
		 SET last_synced_at=now(), last_status='error', last_error=$2, updated_at=now()
		 WHERE id=$1`, feedID, msg)
	return err
}

// ListEnabledThreatFeedCIDRs returns the de-duplicated, sorted union of all CIDRs
// across enabled feeds. This is the set the edge enforces as a global blocklist.
func (s *Store) ListEnabledThreatFeedCIDRs(ctx context.Context) ([]string, error) {
	rows, err := s.Pool.Query(ctx,
		`SELECT DISTINCT e.cidr
		 FROM threat_feed_entries e
		 JOIN threat_feeds f ON f.id = e.feed_id
		 WHERE f.enabled = true
		 ORDER BY e.cidr`)
	if err != nil {
		return nil, err
	}
	var out []string
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}
