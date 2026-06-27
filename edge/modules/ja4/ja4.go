// Package ja4 is a Caddy HTTP handler that computes a JA4H (HTTP-layer)
// fingerprint for each request and exposes it as the `{http.vars.ja4h}`
// placeholder + an `X-Aegis-JA4H` header for downstream handlers and logging.
//
// True TLS-level JA4 needs the raw ClientHello (a listener wrapper); that lands
// in Phase 2. JA4H is fully derivable from the HTTP request and is a strong
// signal for the bot-scoring stage.
package ja4

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"

	"github.com/aegis/edge/internal/metrics"
)

func init() {
	caddy.RegisterModule(Handler{})
	httpcaddyfile.RegisterHandlerDirective("ja4", parseCaddyfile)
}

// Handler computes JA4H fingerprints.
type Handler struct{}

func (Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.ja4",
		New: func() caddy.Module { return new(Handler) },
	}
}

func (h Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	fp := computeJA4H(r)
	caddyhttp.SetVar(r.Context(), "ja4h", fp)
	r.Header.Set("X-Aegis-JA4H", fp)
	metrics.Incr("requests")

	// Record status/size without buffering the body, then emit a per-request
	// analytics event for the ClickHouse pipeline.
	rec := caddyhttp.NewResponseRecorder(w, nil, func(int, http.Header) bool { return false })
	err := next.ServeHTTP(rec, r)
	// Handlers like the WAF return a Caddy error instead of writing the response
	// themselves (Caddy writes the error page to the original writer, bypassing
	// the recorder), so recover the status from the error in that case.
	status := rec.Status()
	if status == 0 && err != nil {
		var he caddyhttp.HandlerError
		if errors.As(err, &he) {
			status = he.StatusCode
		}
	}
	emitEvent(r, fp, status, rec.Size(), rec.Header())
	return err
}

// event mirrors the ClickHouse `aegis_requests` columns (JSONEachRow keys).
type event struct {
	TS     int64  `json:"ts"`
	Host   string `json:"host"`
	IP     string `json:"ip"`
	Method string `json:"method"`
	Path   string `json:"path"`
	Status int    `json:"status"`
	Bytes  int    `json:"bytes"`
	UA     string `json:"ua"`
	JA4H   string `json:"ja4h"`
	Action string `json:"action"`
}

func emitEvent(r *http.Request, ja4h string, status, size int, respHeader http.Header) {
	if status == 0 {
		status = http.StatusOK
	}
	ev := event{
		TS:     time.Now().Unix(),
		Host:   r.Host,
		IP:     clientIP(r),
		Method: r.Method,
		Path:   truncate(r.URL.Path, 256),
		Status: status,
		Bytes:  size,
		UA:     truncate(r.UserAgent(), 256),
		JA4H:   ja4h,
		Action: classify(r, status, respHeader),
	}
	if b, err := json.Marshal(ev); err == nil {
		metrics.PushEvent(string(b))
	}
}

// classify buckets a request outcome for analytics.
func classify(r *http.Request, status int, respHeader http.Header) string {
	if flagged, _ := caddyhttp.GetVar(r.Context(), "aegis_challenge").(bool); flagged && status == http.StatusServiceUnavailable {
		return "challenged"
	}
	if status == http.StatusForbidden || status == http.StatusTooManyRequests {
		return "blocked"
	}
	if cs := strings.ToLower(respHeader.Get("Cache-Status")); strings.Contains(cs, "hit") {
		return "cached"
	}
	return "allowed"
}

func clientIP(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// computeJA4H builds a JA4H-style fingerprint: a_b_c_d where
//
//	a = method(2) + httpver(2) + cookie? + referer? + header_count(2) + lang(2)
//	b = sha256(sorted header names)[:12]
//	c = sha256(sorted cookie names)[:12]
//	d = sha256(sorted cookie name=value)[:12]
func computeJA4H(r *http.Request) string {
	method := strings.ToLower(r.Method)
	if len(method) >= 2 {
		method = method[:2]
	}
	ver := "11"
	if r.ProtoMajor == 2 {
		ver = "20"
	} else if r.ProtoMajor == 3 {
		ver = "30"
	}
	cookieFlag := "n"
	if len(r.Cookies()) > 0 {
		cookieFlag = "c"
	}
	refFlag := "n"
	if r.Referer() != "" {
		refFlag = "r"
	}

	var names []string
	for name := range r.Header {
		ln := strings.ToLower(name)
		if ln == "cookie" || ln == "referer" {
			continue
		}
		names = append(names, ln)
	}
	sort.Strings(names)
	count := len(names)
	if count > 99 {
		count = 99
	}

	lang := "00"
	if al := r.Header.Get("Accept-Language"); al != "" {
		al = strings.ToLower(strings.TrimSpace(al))
		al = strings.SplitN(al, ",", 2)[0]
		al = strings.SplitN(al, "-", 2)[0]
		al = strings.SplitN(al, ";", 2)[0]
		for len(al) < 2 {
			al += "0"
		}
		lang = al[:2]
	}

	a := fmt.Sprintf("%s%s%s%s%02d%s", method, ver, cookieFlag, refFlag, count, lang)

	var cookieNames, cookiePairs []string
	for _, c := range r.Cookies() {
		cookieNames = append(cookieNames, c.Name)
		cookiePairs = append(cookiePairs, c.Name+"="+c.Value)
	}
	sort.Strings(cookieNames)
	sort.Strings(cookiePairs)

	return strings.Join([]string{
		a,
		hash12(strings.Join(names, ",")),
		hash12(strings.Join(cookieNames, ",")),
		hash12(strings.Join(cookiePairs, ",")),
	}, "_")
}

func hash12(s string) string {
	if s == "" {
		return "000000000000"
	}
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:12]
}

func (h *Handler) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
	}
	return nil
}

func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var m Handler
	err := m.UnmarshalCaddyfile(h.Dispenser)
	return m, err
}

var (
	_ caddyhttp.MiddlewareHandler = (*Handler)(nil)
	_ caddyfile.Unmarshaler       = (*Handler)(nil)
)
