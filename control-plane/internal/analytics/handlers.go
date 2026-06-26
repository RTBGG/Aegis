// Package analytics serves traffic/security metric summaries to the dashboard.
package analytics

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/aegis/control-plane/internal/auth"
	"github.com/aegis/control-plane/internal/store"
	"github.com/aegis/control-plane/internal/web"
)

type Service struct {
	Store *store.Store
}

func New(st *store.Store) *Service { return &Service{Store: st} }

func windowFrom(r *http.Request) time.Time {
	switch r.URL.Query().Get("window") {
	case "1h":
		return time.Now().Add(-time.Hour)
	case "7d":
		return time.Now().Add(-7 * 24 * time.Hour)
	default:
		return time.Now().Add(-24 * time.Hour)
	}
}

// Overview returns the account-wide summary for the selected window.
func (s *Service) Overview(w http.ResponseWriter, r *http.Request) {
	u := auth.MustUser(r.Context())
	sum, err := s.Store.MetricsSummaryForAccount(r.Context(), u.AccountID, windowFrom(r))
	if err != nil {
		web.Error(w, http.StatusInternalServerError, "internal", "could not load metrics")
		return
	}
	web.JSON(w, http.StatusOK, map[string]any{"summary": sum})
}

// Domain returns the per-domain summary (ownership enforced).
func (s *Service) Domain(w http.ResponseWriter, r *http.Request) {
	u := auth.MustUser(r.Context())
	id, err := uuid.Parse(chi.URLParam(r, "domainID"))
	if err != nil {
		web.Error(w, http.StatusBadRequest, "bad_id", "invalid domain id")
		return
	}
	if _, err := s.Store.GetDomainOwned(r.Context(), id, u.AccountID); err != nil {
		web.Error(w, http.StatusNotFound, "not_found", "domain not found")
		return
	}
	sum, err := s.Store.MetricsSummaryForDomain(r.Context(), id, windowFrom(r))
	if err != nil {
		web.Error(w, http.StatusInternalServerError, "internal", "could not load metrics")
		return
	}
	web.JSON(w, http.StatusOK, map[string]any{"summary": sum})
}
