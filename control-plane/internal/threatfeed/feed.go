package threatfeed

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/aegis/control-plane/internal/config"
	"github.com/aegis/control-plane/internal/store"
)

const (
	maxDownloadBytes = 32 << 20         // 32 MiB cap on a feed body
	fetchTimeout     = 30 * time.Second // per-feed HTTP timeout
	scanInterval     = 60 * time.Second // how often we look for due feeds
	startupDelay     = 10 * time.Second // let the stack settle before first egress
)

// Syncer fetches enabled threat feeds on a schedule and rebuilds edge config
// whenever their contents change.
type Syncer struct {
	store  *store.Store
	render *config.Renderer
	http   *http.Client
	log    *slog.Logger
}

func New(st *store.Store, render *config.Renderer) *Syncer {
	return &Syncer{
		store:  st,
		render: render,
		http:   &http.Client{Timeout: fetchTimeout},
		log:    slog.Default(),
	}
}

// Run polls for due feeds until ctx is cancelled. Intended to run in a goroutine.
func (s *Syncer) Run(ctx context.Context) {
	select {
	case <-ctx.Done():
		return
	case <-time.After(startupDelay):
	}
	t := time.NewTicker(scanInterval)
	defer t.Stop()
	for {
		s.syncDue(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// syncDue syncs every feed whose schedule is due, then rebuilds config once if
// anything changed.
func (s *Syncer) syncDue(ctx context.Context) {
	feeds, err := s.store.DueThreatFeeds(ctx)
	if err != nil {
		s.log.Warn("threatfeed: list due failed", "err", err)
		return
	}
	changed := false
	for _, f := range feeds {
		if ctx.Err() != nil {
			return
		}
		if s.syncFeed(ctx, f) {
			changed = true
		}
	}
	if changed {
		if _, _, err := s.render.Rebuild(ctx); err != nil {
			s.log.Warn("threatfeed: rebuild after sync failed", "err", err)
		}
	}
}

// RefreshNow syncs a single feed immediately (admin-triggered), rebuilds config
// if it changed, and returns the refreshed feed record.
func (s *Syncer) RefreshNow(ctx context.Context, id uuid.UUID) (*store.ThreatFeed, error) {
	f, err := s.store.GetThreatFeed(ctx, id)
	if err != nil {
		return nil, err
	}
	if s.syncFeed(ctx, *f) {
		if _, _, err := s.render.Rebuild(ctx); err != nil {
			s.log.Warn("threatfeed: rebuild after manual refresh failed", "err", err)
		}
	}
	return s.store.GetThreatFeed(ctx, id)
}

// syncFeed fetches and stores one feed. It returns true if the entry set was
// successfully replaced (so config should be rebuilt). Failures are recorded on
// the feed row and never abort the caller, leaving the last-known-good entries
// in place.
func (s *Syncer) syncFeed(ctx context.Context, f store.ThreatFeed) bool {
	body, err := s.fetch(ctx, f.URL)
	if err != nil {
		s.log.Warn("threatfeed: fetch failed", "feed", f.Slug, "err", err)
		_ = s.store.SetThreatFeedError(ctx, f.ID, truncate(err.Error(), 500))
		return false
	}
	cidrs, skipped := ParseCIDRs(body)
	if len(cidrs) == 0 {
		s.log.Warn("threatfeed: no usable entries", "feed", f.Slug, "skipped", skipped)
		_ = s.store.SetThreatFeedError(ctx, f.ID, "feed returned no usable CIDR entries")
		return false
	}
	if err := s.store.ReplaceThreatFeedEntries(ctx, f.ID, cidrs); err != nil {
		s.log.Warn("threatfeed: store entries failed", "feed", f.Slug, "err", err)
		_ = s.store.SetThreatFeedError(ctx, f.ID, truncate(err.Error(), 500))
		return false
	}
	s.log.Info("threatfeed: synced", "feed", f.Slug, "entries", len(cidrs), "skipped", skipped)
	return true
}

func (s *Syncer) fetch(ctx context.Context, url string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "Aegis-ThreatFeed/1.0 (+https://github.com/RTBGG/Aegis)")
	resp, err := s.http.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxDownloadBytes))
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
