// Package botscore is a Caddy HTTP handler that assigns a heuristic risk score
// to each request (UA/JA4H signals, missing/inconsistent headers, suspicious
// paths, per-IP request rate) and either blocks it, flags it for the challenge
// handler, or lets it through. Verified search-engine crawlers can be allowed
// past scoring.
package botscore

import (
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"

	"github.com/aegis/edge/internal/metrics"
)

func init() {
	caddy.RegisterModule(Handler{})
	httpcaddyfile.RegisterHandlerDirective("botscore", parseCaddyfile)
}

// Handler scores requests for bot likelihood.
type Handler struct {
	// Sensitivity is one of low|medium|high (default medium).
	Sensitivity string `json:"sensitivity,omitempty"`
	// AllowVerifiedBots lets well-known crawlers (Googlebot, Bingbot, …) skip
	// scoring. The match is UA-based and therefore advisory (UA is spoofable).
	AllowVerifiedBots bool `json:"allow_verified_bots,omitempty"`
}

func (Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.botscore",
		New: func() caddy.Module { return new(Handler) },
	}
}

func (h *Handler) Provision(_ caddy.Context) error {
	if h.Sensitivity == "" {
		h.Sensitivity = "medium"
	}
	return nil
}

var suspectAgents = []string{
	"curl/", "wget/", "python", "go-http", "scrapy", "httpclient",
	"libwww", "java/", "headless", "phantomjs", "bot", "spider", "crawler",
}

// verifiedBots are UA fragments of crawlers operators usually want to allow.
var verifiedBots = []string{
	"googlebot", "bingbot", "slurp", "duckduckbot", "baiduspider", "yandexbot",
	"applebot", "facebookexternalhit", "twitterbot", "linkedinbot",
	"uptimerobot", "pingdom",
}

// suspectPaths are scanner/probe targets that strongly indicate automation.
var suspectPaths = []string{
	"/wp-login", "/wp-admin", "/xmlrpc.php", "/.env", "/.git", "/phpmyadmin",
	"/.aws", "/actuator", "/solr/", "/vendor/phpunit", "/.ssh", "/config.json",
}

// signals are the boolean/numeric features the score is computed from. Kept
// separate from the request so scoring is a pure, testable function.
type signals struct {
	uaEmpty           bool
	uaSuspect         bool
	missingAccept     bool
	missingAcceptLang bool
	missingAcceptEnc  bool
	missingCookies    bool
	missingSecFetch   bool // UA claims Chromium but sent no Sec-Fetch-* headers
	suspectPath       bool
	rate              int
}

// scoreSignals turns request features into a 0..N risk score.
func scoreSignals(s signals) int {
	score := 0
	switch {
	case s.uaEmpty:
		score += 40
	case s.uaSuspect:
		score += 35
	}
	if s.missingAccept {
		score += 15
	}
	if s.missingAcceptLang {
		score += 10
	}
	if s.missingAcceptEnc {
		score += 10
	}
	if s.missingCookies {
		score += 10
	}
	if s.missingSecFetch {
		score += 20
	}
	if s.suspectPath {
		score += 30
	}
	switch {
	case s.rate > 300:
		score += 50
	case s.rate > 120:
		score += 25
	case s.rate > 60:
		score += 10
	}
	return score
}

func isVerifiedBot(ua string) bool {
	for _, b := range verifiedBots {
		if strings.Contains(ua, b) {
			return true
		}
	}
	return false
}

func extractSignals(r *http.Request, ua string) signals {
	claimsChromium := strings.Contains(ua, "chrome") || strings.Contains(ua, "chromium") || strings.Contains(ua, "edg")
	var sig signals
	sig.uaEmpty = ua == ""
	if !sig.uaEmpty {
		for _, s := range suspectAgents {
			if strings.Contains(ua, s) {
				sig.uaSuspect = true
				break
			}
		}
	}
	sig.missingAccept = r.Header.Get("Accept") == ""
	sig.missingAcceptLang = r.Header.Get("Accept-Language") == ""
	sig.missingAcceptEnc = r.Header.Get("Accept-Encoding") == ""
	sig.missingCookies = len(r.Cookies()) == 0
	sig.missingSecFetch = claimsChromium && r.Header.Get("Sec-Fetch-Mode") == "" && r.Header.Get("Sec-Ch-Ua") == ""
	sig.suspectPath = matchesSuspectPath(r.URL.Path)
	sig.rate = metrics.RequestRate(clientIP(r))
	return sig
}

func matchesSuspectPath(p string) bool {
	p = strings.ToLower(p)
	for _, sp := range suspectPaths {
		if strings.Contains(p, sp) {
			return true
		}
	}
	return false
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	ua := strings.ToLower(r.UserAgent())

	if h.AllowVerifiedBots && isVerifiedBot(ua) {
		caddyhttp.SetVar(r.Context(), "bot_verified", true)
		return next.ServeHTTP(w, r)
	}

	score := scoreSignals(extractSignals(r, ua))
	caddyhttp.SetVar(r.Context(), "bot_score", score)
	r.Header.Set("X-Aegis-Bot-Score", strconv.Itoa(score))

	challengeT, blockT := thresholds(h.Sensitivity)
	switch {
	case score >= blockT:
		metrics.Incr("blocked_bot")
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("Forbidden: request blocked by Aegis bot protection.\n"))
		return nil
	case score >= challengeT:
		metrics.Incr("challenged")
		caddyhttp.SetVar(r.Context(), "aegis_challenge", true)
	}
	return next.ServeHTTP(w, r)
}

func thresholds(sensitivity string) (challenge, block int) {
	switch sensitivity {
	case "low":
		return 80, 130
	case "high":
		return 35, 75
	default: // medium
		return 55, 100
	}
}

func clientIP(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

func (h *Handler) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		for d.NextBlock(0) {
			switch d.Val() {
			case "sensitivity":
				if !d.NextArg() {
					return d.ArgErr()
				}
				h.Sensitivity = d.Val()
			case "allow_verified_bots":
				h.AllowVerifiedBots = true
			default:
				return d.Errf("unknown botscore option %q", d.Val())
			}
		}
	}
	return nil
}

func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var m Handler
	err := m.UnmarshalCaddyfile(h.Dispenser)
	return &m, err
}

var (
	_ caddyhttp.MiddlewareHandler = (*Handler)(nil)
	_ caddy.Provisioner           = (*Handler)(nil)
	_ caddyfile.Unmarshaler       = (*Handler)(nil)
)
