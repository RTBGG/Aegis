package store

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// MetricsSummary aggregates edge telemetry over a window.
type MetricsSummary struct {
	Requests    int64 `json:"requests"`
	BlockedWAF  int64 `json:"blocked_waf"`
	BlockedRate int64 `json:"blocked_rate"`
	Challenged  int64 `json:"challenged"`
	CacheHits   int64 `json:"cache_hits"`
	CacheMiss   int64 `json:"cache_miss"`
	Bytes       int64 `json:"bytes"`
}

func (s *Store) InsertMetric(ctx context.Context, m *EdgeMetric) error {
	_, err := s.Pool.Exec(ctx,
		`INSERT INTO edge_metrics
		   (edge_id, domain_id, requests, blocked_waf, blocked_rate, challenged, cache_hits, cache_miss, bytes)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		m.EdgeID, m.DomainID, m.Requests, m.BlockedWAF, m.BlockedRate, m.Challenged, m.CacheHits, m.CacheMiss, m.Bytes)
	return err
}

func (s *Store) MetricsSummarySince(ctx context.Context, since time.Time) (*MetricsSummary, error) {
	var out MetricsSummary
	err := s.Pool.QueryRow(ctx, `
		SELECT coalesce(sum(requests),0), coalesce(sum(blocked_waf),0), coalesce(sum(blocked_rate),0),
		       coalesce(sum(challenged),0), coalesce(sum(cache_hits),0), coalesce(sum(cache_miss),0),
		       coalesce(sum(bytes),0)
		FROM edge_metrics WHERE ts > $1`, since).
		Scan(&out.Requests, &out.BlockedWAF, &out.BlockedRate, &out.Challenged, &out.CacheHits, &out.CacheMiss, &out.Bytes)
	return &out, err
}

func (s *Store) MetricsSummaryForAccount(ctx context.Context, accountID uuid.UUID, since time.Time) (*MetricsSummary, error) {
	var out MetricsSummary
	err := s.Pool.QueryRow(ctx, `
		SELECT coalesce(sum(m.requests),0), coalesce(sum(m.blocked_waf),0), coalesce(sum(m.blocked_rate),0),
		       coalesce(sum(m.challenged),0), coalesce(sum(m.cache_hits),0), coalesce(sum(m.cache_miss),0),
		       coalesce(sum(m.bytes),0)
		FROM edge_metrics m JOIN domains d ON d.id = m.domain_id
		WHERE d.account_id=$1 AND m.ts > $2`, accountID, since).
		Scan(&out.Requests, &out.BlockedWAF, &out.BlockedRate, &out.Challenged, &out.CacheHits, &out.CacheMiss, &out.Bytes)
	return &out, err
}

func (s *Store) MetricsSummaryForDomain(ctx context.Context, domainID uuid.UUID, since time.Time) (*MetricsSummary, error) {
	var out MetricsSummary
	err := s.Pool.QueryRow(ctx, `
		SELECT coalesce(sum(requests),0), coalesce(sum(blocked_waf),0), coalesce(sum(blocked_rate),0),
		       coalesce(sum(challenged),0), coalesce(sum(cache_hits),0), coalesce(sum(cache_miss),0),
		       coalesce(sum(bytes),0)
		FROM edge_metrics WHERE domain_id=$1 AND ts > $2`, domainID, since).
		Scan(&out.Requests, &out.BlockedWAF, &out.BlockedRate, &out.Challenged, &out.CacheHits, &out.CacheMiss, &out.Bytes)
	return &out, err
}
