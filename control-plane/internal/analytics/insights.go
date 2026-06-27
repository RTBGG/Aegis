package analytics

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/aegis/control-plane/internal/auth"
	"github.com/aegis/control-plane/internal/web"
)

// insightsWindow maps a window name to its lookback and time-bucket (seconds).
func insightsWindow(name string) (since time.Time, bucket int, label string) {
	switch name {
	case "7d":
		return time.Now().Add(-7 * 24 * time.Hour), 6 * 3600, "7d"
	default:
		return time.Now().Add(-24 * time.Hour), 3600, "24h"
	}
}

type insSummary struct {
	Requests   int64 `json:"requests"`
	Visitors   int64 `json:"visitors"`
	Bytes      int64 `json:"bytes"`
	Blocked    int64 `json:"blocked"`
	Challenged int64 `json:"challenged"`
	Cached     int64 `json:"cached"`
}

type insPoint struct {
	T          int64 `json:"t"`
	Requests   int64 `json:"requests"`
	Visitors   int64 `json:"visitors"`
	Blocked    int64 `json:"blocked"`
	Challenged int64 `json:"challenged"`
}

type insPath struct {
	Path  string `json:"path"`
	Count int64  `json:"count"`
}

type insStatus struct {
	Status int   `json:"status"`
	Count  int64 `json:"count"`
}

// Insights returns ClickHouse-backed per-domain analytics (time-series, unique
// visitors, top paths, status breakdown). Falls back to enabled:false when
// ClickHouse is not configured.
func (s *Service) Insights(w http.ResponseWriter, r *http.Request) {
	u := auth.MustUser(r.Context())
	id, err := uuid.Parse(chi.URLParam(r, "domainID"))
	if err != nil {
		web.Error(w, http.StatusBadRequest, "bad_id", "invalid domain id")
		return
	}
	d, err := s.Store.GetDomainOwned(r.Context(), id, u.AccountID)
	if err != nil {
		web.Error(w, http.StatusNotFound, "not_found", "domain not found")
		return
	}
	since, bucket, label := insightsWindow(r.URL.Query().Get("window"))
	if !s.CH.Enabled() {
		web.JSON(w, http.StatusOK, map[string]any{"enabled": false, "window": label})
		return
	}

	// host matches the apex and any subdomain of the zone.
	params := map[string]string{
		"since": since.UTC().Format("2006-01-02 15:04:05"),
		"d":     d.Name,
		"dot":   "." + d.Name,
	}
	where := "WHERE ts >= {since:DateTime} AND (host = {d:String} OR endsWith(host, {dot:String}))"

	summary, err := chQueryOne[insSummary](r.Context(), s, fmt.Sprintf(`
		SELECT count() AS requests, uniq(ip) AS visitors, sum(bytes) AS bytes,
		       countIf(action='blocked') AS blocked, countIf(action='challenged') AS challenged,
		       countIf(action='cached') AS cached
		FROM aegis_requests %s`, where), params)
	if err != nil {
		web.Error(w, http.StatusBadGateway, "analytics_error", "could not query analytics: "+err.Error())
		return
	}
	series, err := chQuery[insPoint](r.Context(), s, fmt.Sprintf(`
		SELECT toUnixTimestamp(toStartOfInterval(ts, INTERVAL %d SECOND)) AS t,
		       count() AS requests, uniq(ip) AS visitors,
		       countIf(action='blocked') AS blocked, countIf(action='challenged') AS challenged
		FROM aegis_requests %s GROUP BY t ORDER BY t`, bucket, where), params)
	if err != nil {
		web.Error(w, http.StatusBadGateway, "analytics_error", "could not query analytics: "+err.Error())
		return
	}
	topPaths, err := chQuery[insPath](r.Context(), s, fmt.Sprintf(`
		SELECT path, count() AS count FROM aegis_requests %s
		GROUP BY path ORDER BY count DESC LIMIT 10`, where), params)
	if err != nil {
		web.Error(w, http.StatusBadGateway, "analytics_error", "could not query analytics: "+err.Error())
		return
	}
	statuses, err := chQuery[insStatus](r.Context(), s, fmt.Sprintf(`
		SELECT status, count() AS count FROM aegis_requests %s
		GROUP BY status ORDER BY count DESC LIMIT 12`, where), params)
	if err != nil {
		web.Error(w, http.StatusBadGateway, "analytics_error", "could not query analytics: "+err.Error())
		return
	}

	web.JSON(w, http.StatusOK, map[string]any{
		"enabled":   true,
		"window":    label,
		"summary":   summary,
		"series":    series,
		"top_paths": topPaths,
		"statuses":  statuses,
	})
}

func chQuery[T any](ctx context.Context, s *Service, sql string, params map[string]string) ([]T, error) {
	body, err := s.CH.QueryJSON(ctx, sql, params)
	if err != nil {
		return nil, err
	}
	var resp struct {
		Data []T `json:"data"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, err
	}
	return resp.Data, nil
}

func chQueryOne[T any](ctx context.Context, s *Service, sql string, params map[string]string) (T, error) {
	var zero T
	rows, err := chQuery[T](ctx, s, sql, params)
	if err != nil {
		return zero, err
	}
	if len(rows) == 0 {
		return zero, nil
	}
	return rows[0], nil
}
