// Package security exposes per-domain security policy (WAF, rate-limit, cache,
// bot/DDoS) read/update endpoints.
package security

import (
	"net/http"
	"strings"

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
	WAFCustomRules   string `json:"waf_custom_rules"`
	RateLimitEnabled bool   `json:"rate_limit_enabled"`
	RateLimitRPM     int32  `json:"rate_limit_rpm"`
	RateLimitBurst   int32  `json:"rate_limit_burst"`
	CacheEnabled     bool   `json:"cache_enabled"`
	CacheTTL         int32  `json:"cache_ttl"`
	BotProtection    string `json:"bot_protection"`
	BotAllowVerified bool   `json:"bot_allow_verified"`
	ChallengeEnabled bool   `json:"challenge_enabled"`
	ChallengeMode    string `json:"challenge_mode"`
	CaptchaProvider  string `json:"captcha_provider"`
	CaptchaSitekey   string `json:"captcha_sitekey"`
	CaptchaSecret    string `json:"captcha_secret"`     // write-only; never returned
	CaptchaSecretSet bool   `json:"captcha_secret_set"` // read-only
}

func toPolicyDTO(p *store.SecurityPolicy) policyDTO {
	return policyDTO{
		HTTPSRedirect: p.HTTPSRedirect, MinTLS: p.MinTLS,
		WAFEnabled: p.WAFEnabled, WAFParanoia: p.WAFParanoia, WAFMode: p.WAFMode, WAFCustomRules: p.WAFCustomRules,
		RateLimitEnabled: p.RateLimitEnabled, RateLimitRPM: p.RateLimitRPM, RateLimitBurst: p.RateLimitBurst,
		CacheEnabled: p.CacheEnabled, CacheTTL: p.CacheTTL,
		BotProtection: p.BotProtection, BotAllowVerified: p.BotAllowVerified,
		ChallengeEnabled: p.ChallengeEnabled, ChallengeMode: p.ChallengeMode,
		CaptchaProvider: p.CaptchaProvider, CaptchaSitekey: p.CaptchaSitekey,
		CaptchaSecret: "", CaptchaSecretSet: p.CaptchaSecret != "",
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
	existing, err := s.Store.GetOrCreatePolicy(r.Context(), d.ID)
	if err != nil {
		web.Error(w, http.StatusInternalServerError, "internal", "could not load policy")
		return
	}
	var in policyDTO
	if err := web.Decode(w, r, &in); err != nil {
		web.Error(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	if in.ChallengeMode == "" {
		in.ChallengeMode = "pow"
	}
	if msg, ok := validatePolicy(&in, existing.CaptchaSecret != ""); !ok {
		web.Error(w, http.StatusBadRequest, "validation", msg)
		return
	}
	p := &store.SecurityPolicy{
		DomainID:      d.ID,
		HTTPSRedirect: in.HTTPSRedirect, MinTLS: in.MinTLS,
		WAFEnabled: in.WAFEnabled, WAFParanoia: in.WAFParanoia, WAFMode: in.WAFMode, WAFCustomRules: in.WAFCustomRules,
		RateLimitEnabled: in.RateLimitEnabled, RateLimitRPM: in.RateLimitRPM, RateLimitBurst: in.RateLimitBurst,
		CacheEnabled: in.CacheEnabled, CacheTTL: in.CacheTTL,
		BotProtection: in.BotProtection, BotAllowVerified: in.BotAllowVerified,
		ChallengeEnabled: in.ChallengeEnabled, ChallengeMode: in.ChallengeMode,
		CaptchaProvider: in.CaptchaProvider, CaptchaSitekey: in.CaptchaSitekey, CaptchaSecret: in.CaptchaSecret,
	}
	out, err := s.Store.UpdatePolicy(r.Context(), p)
	if err != nil {
		web.Error(w, http.StatusInternalServerError, "internal", "could not update policy")
		return
	}
	_, _, _ = s.Render.Rebuild(r.Context())
	web.JSON(w, http.StatusOK, map[string]any{"security": toPolicyDTO(out)})
}

func validatePolicy(p *policyDTO, captchaSecretSet bool) (string, bool) {
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
	if err := validateCustomSecRules(p.WAFCustomRules); err != nil {
		return err.Error(), false
	}
	if msg, ok := validateChallenge(p, captchaSecretSet); !ok {
		return msg, false
	}
	return "", true
}

// validateChallenge checks the challenge/CAPTCHA settings. captchaSecretSet
// reports whether a secret is already stored (a blank secret on update keeps it).
func validateChallenge(p *policyDTO, captchaSecretSet bool) (string, bool) {
	switch p.ChallengeMode {
	case "pow", "captcha":
	default:
		return "challenge_mode must be pow or captcha", false
	}
	switch p.CaptchaProvider {
	case "", "turnstile", "hcaptcha", "recaptcha":
	default:
		return "captcha_provider must be turnstile, hcaptcha or recaptcha", false
	}
	if strings.ContainsAny(p.CaptchaSitekey+p.CaptchaSecret, " \t\r\n") {
		return "captcha sitekey/secret must not contain whitespace", false
	}
	if p.ChallengeMode == "captcha" {
		if p.CaptchaProvider == "" {
			return "captcha_provider is required when challenge_mode is captcha", false
		}
		if p.CaptchaSitekey == "" {
			return "captcha_sitekey is required when challenge_mode is captcha", false
		}
		if p.CaptchaSecret == "" && !captchaSecretSet {
			return "captcha_secret is required when challenge_mode is captcha", false
		}
	}
	return "", true
}

// --- per-route WAF overrides ---

type overrideDTO struct {
	ID            string `json:"id"`
	Path          string `json:"path"`
	Mode          string `json:"mode"`
	ExcludedRules string `json:"excluded_rules"`
	Paranoia      *int32 `json:"paranoia"`
	Enabled       bool   `json:"enabled"`
}

func toOverrideDTO(o store.WAFRouteOverride) overrideDTO {
	return overrideDTO{
		ID: o.ID.String(), Path: o.Path, Mode: o.Mode,
		ExcludedRules: o.ExcludedRules, Paranoia: o.Paranoia, Enabled: o.Enabled,
	}
}

func (s *Service) ListOverrides(w http.ResponseWriter, r *http.Request) {
	d, ok := s.ownDomain(w, r)
	if !ok {
		return
	}
	rows, err := s.Store.ListWAFOverrides(r.Context(), d.ID)
	if err != nil {
		web.Error(w, http.StatusInternalServerError, "internal", "could not list overrides")
		return
	}
	out := make([]overrideDTO, len(rows))
	for i, o := range rows {
		out[i] = toOverrideDTO(o)
	}
	web.JSON(w, http.StatusOK, map[string]any{"overrides": out})
}

func (s *Service) CreateOverride(w http.ResponseWriter, r *http.Request) {
	d, ok := s.ownDomain(w, r)
	if !ok {
		return
	}
	var in struct {
		Path          string `json:"path"`
		Mode          string `json:"mode"`
		ExcludedRules string `json:"excluded_rules"`
		Paranoia      *int32 `json:"paranoia"`
	}
	if err := web.Decode(w, r, &in); err != nil {
		web.Error(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	in.Path = strings.TrimSpace(in.Path)
	if in.Mode == "" {
		in.Mode = "inherit"
	}
	if err := validateWAFPath(in.Path); err != nil {
		web.Error(w, http.StatusBadRequest, "validation", err.Error())
		return
	}
	switch in.Mode {
	case "inherit", "off", "detect":
	default:
		web.Error(w, http.StatusBadRequest, "validation", "mode must be inherit, off or detect")
		return
	}
	if in.Paranoia != nil && (*in.Paranoia < 1 || *in.Paranoia > 4) {
		web.Error(w, http.StatusBadRequest, "validation", "paranoia must be 1-4")
		return
	}
	excluded, err := normalizeRuleIDs(in.ExcludedRules)
	if err != nil {
		web.Error(w, http.StatusBadRequest, "validation", err.Error())
		return
	}
	if in.Mode == "inherit" && excluded == "" && in.Paranoia == nil {
		web.Error(w, http.StatusBadRequest, "validation", "override has no effect: set a mode, excluded rules, or paranoia")
		return
	}
	o, err := s.Store.CreateWAFOverride(r.Context(), &store.WAFRouteOverride{
		DomainID: d.ID, Path: in.Path, Mode: in.Mode, ExcludedRules: excluded, Paranoia: in.Paranoia, Enabled: true,
	})
	if err != nil {
		web.Error(w, http.StatusInternalServerError, "internal", "could not create override")
		return
	}
	_, _, _ = s.Render.Rebuild(r.Context())
	web.JSON(w, http.StatusCreated, map[string]any{"override": toOverrideDTO(*o)})
}

func (s *Service) DeleteOverride(w http.ResponseWriter, r *http.Request) {
	d, ok := s.ownDomain(w, r)
	if !ok {
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "overrideID"))
	if err != nil {
		web.Error(w, http.StatusBadRequest, "bad_id", "invalid override id")
		return
	}
	if err := s.Store.DeleteWAFOverride(r.Context(), id, d.ID); err != nil {
		web.Error(w, http.StatusInternalServerError, "internal", "could not delete override")
		return
	}
	_, _, _ = s.Render.Rebuild(r.Context())
	web.JSON(w, http.StatusOK, map[string]any{"ok": true})
}
