package analytics

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/aegis/control-plane/internal/auth"
	"github.com/aegis/control-plane/internal/web"
)

// liveWindow is how many seconds of per-second data the live graph shows.
const liveWindow = 120

type liveRow struct {
	T       int64 `json:"t"`
	Total   int64 `json:"total"`
	Blocked int64 `json:"blocked"`
}

type livePoint struct {
	T       int64 `json:"t"`
	Total   int64 `json:"total"`
	Blocked int64 `json:"blocked"`
	Passed  int64 `json:"passed"`
}

// Live returns per-second request counts (total/blocked/passed) for the last two
// minutes — the data behind the dashboard's live "dstat"-style graph. The series
// is zero-filled so the chart always spans the full window even with no traffic.
func (s *Service) Live(w http.ResponseWriter, r *http.Request) {
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
	if !s.CH.Enabled() {
		web.JSON(w, http.StatusOK, map[string]any{"enabled": false})
		return
	}

	end := time.Now().Unix()
	start := end - int64(liveWindow) + 1
	params := map[string]string{
		"since": time.Unix(start, 0).UTC().Format("2006-01-02 15:04:05"),
		"d":     d.Name,
		"dot":   "." + d.Name,
	}
	rows, err := chQuery[liveRow](r.Context(), s, `
		SELECT toUnixTimestamp(ts) AS t, count() AS total,
		       countIf(action='blocked') AS blocked
		FROM aegis_requests
		WHERE ts >= {since:DateTime} AND (host = {d:String} OR endsWith(host, {dot:String}))
		GROUP BY t ORDER BY t`, params)
	if err != nil {
		web.Error(w, http.StatusBadGateway, "analytics_error", "could not query analytics: "+err.Error())
		return
	}

	byT := make(map[int64]liveRow, len(rows))
	for _, row := range rows {
		byT[row.T] = row
	}
	points := make([]livePoint, 0, liveWindow)
	for t := start; t <= end; t++ {
		row := byT[t]
		points = append(points, livePoint{
			T: t, Total: row.Total, Blocked: row.Blocked, Passed: row.Total - row.Blocked,
		})
	}
	web.JSON(w, http.StatusOK, map[string]any{
		"enabled": true,
		"window":  "2m",
		"points":  points,
	})
}
