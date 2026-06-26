// Package edgeapi serves the node-agent: long-polled config delivery and
// telemetry ingest. Authenticated with the shared agent token (Phase 1; Phase 3
// replaces this with per-node mTLS).
package edgeapi

import (
	"crypto/subtle"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/aegis/control-plane/internal/appcfg"
	"github.com/aegis/control-plane/internal/config"
	"github.com/aegis/control-plane/internal/store"
	"github.com/aegis/control-plane/internal/web"
)

type API struct {
	Store *store.Store
	Cfg   *appcfg.Config
}

func New(st *store.Store, cfg *appcfg.Config) *API {
	return &API{Store: st, Cfg: cfg}
}

// Authn is middleware enforcing the shared agent bearer token.
func (a *API) Authn(next http.Handler) http.Handler {
	want := "Bearer " + a.Cfg.AgentToken
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := r.Header.Get("Authorization")
		if subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
			web.Error(w, http.StatusUnauthorized, "unauthorized", "invalid agent token")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (a *API) latest(r *http.Request) (*store.ConfigBundle, error) {
	b, err := a.Store.GetLatestBundle(r.Context())
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil
	}
	return b, err
}

// Config delivers the newest config bundle, long-polling (≤25s) when the agent
// is already up to date so changes propagate quickly without busy polling.
func (a *API) Config(w http.ResponseWriter, r *http.Request) {
	since, _ := strconv.ParseInt(r.URL.Query().Get("since"), 10, 64)

	b, err := a.latest(r)
	if err != nil {
		web.Error(w, http.StatusInternalServerError, "internal", "could not load config")
		return
	}
	if b != nil && b.Version > since {
		writeBundle(w, b)
		return
	}

	// Wait for a change poke or timeout, then re-check.
	sub := a.Store.Redis.Subscribe(r.Context(), config.RedisChannel)
	defer sub.Close()
	select {
	case <-sub.Channel():
	case <-time.After(25 * time.Second):
	case <-r.Context().Done():
		return
	}

	b, err = a.latest(r)
	if err != nil {
		web.Error(w, http.StatusInternalServerError, "internal", "could not load config")
		return
	}
	if b != nil && b.Version > since {
		writeBundle(w, b)
		return
	}
	w.WriteHeader(http.StatusNoContent) // unchanged
}

func writeBundle(w http.ResponseWriter, b *store.ConfigBundle) {
	web.JSON(w, http.StatusOK, map[string]any{
		"version":   b.Version,
		"checksum":  b.Checksum,
		"caddyfile": b.Caddyfile,
	})
}

type metricIn struct {
	Domain      string `json:"domain"`
	Requests    int64  `json:"requests"`
	BlockedWAF  int64  `json:"blocked_waf"`
	BlockedRate int64  `json:"blocked_rate"`
	Challenged  int64  `json:"challenged"`
	CacheHits   int64  `json:"cache_hits"`
	CacheMiss   int64  `json:"cache_miss"`
	Bytes       int64  `json:"bytes"`
}

type telemetryIn struct {
	EdgeName      string     `json:"edge_name"`
	PublicIP      string     `json:"public_ip"`
	AgentVersion  string     `json:"agent_version"`
	Status        string     `json:"status"`
	ConfigVersion int64      `json:"config_version"`
	Metrics       []metricIn `json:"metrics"`
}

// Telemetry records an edge heartbeat and its per-domain metrics.
func (a *API) Telemetry(w http.ResponseWriter, r *http.Request) {
	var in telemetryIn
	if err := web.Decode(w, r, &in); err != nil {
		web.Error(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	if in.EdgeName == "" {
		web.Error(w, http.StatusBadRequest, "validation", "edge_name required")
		return
	}
	edge, err := a.Store.GetEdgeByName(r.Context(), in.EdgeName)
	if errors.Is(err, store.ErrNotFound) {
		edge, err = a.Store.UpsertEdge(r.Context(), in.EdgeName, in.PublicIP, "default")
	}
	if err != nil {
		web.Error(w, http.StatusInternalServerError, "internal", "could not resolve edge")
		return
	}
	status := in.Status
	if status == "" {
		status = "healthy"
	}
	_ = a.Store.EdgeHeartbeat(r.Context(), edge.ID, in.AgentVersion, status)

	for _, m := range in.Metrics {
		em := &store.EdgeMetric{
			EdgeID:      &edge.ID,
			Requests:    m.Requests,
			BlockedWAF:  m.BlockedWAF,
			BlockedRate: m.BlockedRate,
			Challenged:  m.Challenged,
			CacheHits:   m.CacheHits,
			CacheMiss:   m.CacheMiss,
			Bytes:       m.Bytes,
		}
		if m.Domain != "" {
			if d, err := a.Store.GetDomainByName(r.Context(), m.Domain); err == nil {
				em.DomainID = &d.ID
			}
		}
		_ = a.Store.InsertMetric(r.Context(), em)
	}
	web.JSON(w, http.StatusOK, map[string]any{"ok": true})
}
