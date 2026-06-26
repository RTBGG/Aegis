// Package security exposes per-domain security policy (WAF, rate-limit, cache,
// bot/DDoS) read/update endpoints.
package security

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/aegis/control-plane/internal/auth"
	"github.com/aegis/control-plane/internal/config"
	"github.com/aegis/control-plane/internal/store"
	"github.com/aegis/control-plane/internal/web"
)

type Service struct {
	Store  *store.Store
	Render *config.Renderer
}

func New(st *store.Store, r *config.Renderer) *Service {
	return &Service{Store: st, Render: r}
}

func (s *Service) ownDomain(w http.ResponseWriter, r *http.Request) (*store.Domain, bool) {
	u := auth.MustUser(r.Context())
	id, err := uuid.Parse(chi.URLParam(r, "domainID"))
	if err != nil {
		web.Error(w, http.StatusBadRequest, "bad_id", "invalid domain id")
		return nil, false
	}
	d, err := s.Store.GetDomainOwned(r.Context(), id, u.AccountID)
	if err != nil {
		web.Error(w, http.StatusNotFound, "not_found", "domain not found")
		return nil, false
	}
	return d, true
}

type policyDTO struct {
	HTTPSRedirect    bool   `json:"https_redirect"`
	MinTLS           string `json:"min_tls"`
	WAFEnabled       bool   `json:"waf_enabled"`
	WAFParanoia      int32  `json:"waf_paranoia"`
	WAFMode          string `json:"waf_mode"`
	RateLimitEnabled bool   `json:"rate_limit_enabled"`
	RateLimitRPM     int32  `json:"rate_limit_rpm"`
	RateLimitBurst   int32  `json:"rate_limit_burst"`
	CacheEnabled     bool   `json:"cache_enabled"`
	CacheTTL         int32  `json:"cache_ttl"`
	BotProtection    string `json:"bot_protection"`
	ChallengeEnabled bool   `json:"challenge_enabled"`
}

func toPolicyDTO(p *store.SecurityPolicy) policyDTO {
	return policyDTO{
		HTTPSRedirect: p.HTTPSRedirect, MinTLS: p.MinTLS,
		WAFEnabled: p.WAFEnabled, WAFParanoia: p.WAFParanoia, WAFMode: p.WAFMode,
		RateLimitEnabled: p.RateLimitEnabled, RateLimitRPM: p.RateLimitRPM, RateLimitBurst: p.RateLimitBurst,
		CacheEnabled: p.CacheEnabled, CacheTTL: p.CacheTTL,
		BotProtection: p.BotProtection, ChallengeEnabled: p.ChallengeEnabled,
	}
}

func (s *Service) Get(w http.ResponseWriter, r *http.Request) {
	d, ok := s.ownDomain(w, r)
	if !ok {
		return
	}
	p, err := s.Store.GetOrCreatePolicy(r.Context(), d.ID)
	if err != nil {
		web.Error(w, http.StatusInternalServerError, "internal", "could not load policy")
		return
	}
	web.JSON(w, http.StatusOK, map[string]any{"security": toPolicyDTO(p)})
}

func (s *Service) Update(w http.ResponseWriter, r *http.Request) {
	d, ok := s.ownDomain(w, r)
	if !ok {
		return
	}
	var in policyDTO
	if err := web.Decode(w, r, &in); err != nil {
		web.Error(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	if msg, ok := validatePolicy(&in); !ok {
		web.Error(w, http.StatusBadRequest, "validation", msg)
		return
	}
	p := &store.SecurityPolicy{
		DomainID:      d.ID,
		HTTPSRedirect: in.HTTPSRedirect, MinTLS: in.MinTLS,
		WAFEnabled: in.WAFEnabled, WAFParanoia: in.WAFParanoia, WAFMode: in.WAFMode,
		RateLimitEnabled: in.RateLimitEnabled, RateLimitRPM: in.RateLimitRPM, RateLimitBurst: in.RateLimitBurst,
		CacheEnabled: in.CacheEnabled, CacheTTL: in.CacheTTL,
		BotProtection: in.BotProtection, ChallengeEnabled: in.ChallengeEnabled,
	}
	out, err := s.Store.UpdatePolicy(r.Context(), p)
	if err != nil {
		web.Error(w, http.StatusInternalServerError, "internal", "could not update policy")
		return
	}
	_, _, _ = s.Render.Rebuild(r.Context())
	web.JSON(w, http.StatusOK, map[string]any{"security": toPolicyDTO(out)})
}

func validatePolicy(p *policyDTO) (string, bool) {
	if p.WAFParanoia < 1 || p.WAFParanoia > 4 {
		return "waf_paranoia must be 1-4", false
	}
	if p.WAFMode != "block" && p.WAFMode != "detect" {
		return "waf_mode must be block or detect", false
	}
	switch p.BotProtection {
	case "off", "low", "medium", "high":
	default:
		return "bot_protection must be off/low/medium/high", false
	}
	switch p.MinTLS {
	case "1.2", "1.3":
	default:
		return "min_tls must be 1.2 or 1.3", false
	}
	if p.RateLimitRPM < 1 {
		return "rate_limit_rpm must be >= 1", false
	}
	if p.CacheTTL < 0 {
		return "cache_ttl must be >= 0", false
	}
	return "", true
}
