// Package botscore is a Caddy HTTP handler that assigns a heuristic risk score
// to each request (UA/JA4H signals, missing headers, per-IP request rate) and
// either blocks it or flags it for the challenge handler.
package botscore

import (
	"net"
	"net/http"
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

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	score := 0
	ua := strings.ToLower(r.UserAgent())
	if ua == "" {
		score += 40
	} else {
		for _, s := range suspectAgents {
			if strings.Contains(ua, s) {
				score += 35
				break
			}
		}
	}
	if r.Header.Get("Accept") == "" {
		score += 15
	}
	if r.Header.Get("Accept-Language") == "" {
		score += 10
	}
	if len(r.Cookies()) == 0 {
		score += 10
	}

	ip := clientIP(r)
	switch rate := metrics.RequestRate(ip); {
	case rate > 300:
		score += 50
	case rate > 120:
		score += 25
	case rate > 60:
		score += 10
	}

	caddyhttp.SetVar(r.Context(), "bot_score", score)

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
