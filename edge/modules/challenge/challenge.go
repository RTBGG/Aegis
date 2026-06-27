// Package challenge is a Caddy HTTP handler that gates flagged requests behind a
// lightweight proof-of-work interstitial. When the bot-scoring stage sets the
// `aegis_challenge` var, unverified clients receive a PoW page; solving it mints
// a signed clearance cookie that lets subsequent requests through.
package challenge

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"math/bits"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

const (
	submitPath    = "/__aegis/challenge"
	clearanceName = "aegis_clearance"
	clearanceTTL  = time.Hour
	challengeTTL  = 5 * time.Minute
	defaultDiff   = 16 // leading zero bits (~65k hashes, sub-second in-browser)
)

func init() {
	caddy.RegisterModule(Handler{})
	httpcaddyfile.RegisterHandlerDirective("challenge", parseCaddyfile)
}

// Handler serves and verifies an anti-bot challenge. The default "pow" mode is a
// transparent proof-of-work interstitial; "captcha" mode renders a pluggable
// CAPTCHA widget (Turnstile/hCaptcha/reCAPTCHA) and verifies it server-side.
// Either way, success mints a signed clearance cookie.
type Handler struct {
	Secret     string `json:"secret,omitempty"`
	Difficulty int    `json:"difficulty,omitempty"`

	// Mode is "pow" (default) or "captcha".
	Mode          string `json:"mode,omitempty"`
	Provider      string `json:"provider,omitempty"` // turnstile|hcaptcha|recaptcha
	SiteKey       string `json:"sitekey,omitempty"`
	CaptchaSecret string `json:"captcha_secret,omitempty"`
	VerifyURL     string `json:"verify_url,omitempty"` // override provider default (testing)

	prov   captchaProvider
	client *http.Client
}

func (Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.challenge",
		New: func() caddy.Module { return new(Handler) },
	}
}

func (h *Handler) Provision(_ caddy.Context) error {
	if h.Secret == "" {
		h.Secret = os.Getenv("CHALLENGE_SECRET")
	}
	if h.Secret == "" {
		h.Secret = "insecure-default-change-me"
	}
	if h.Difficulty <= 0 {
		h.Difficulty = defaultDiff
	}
	if h.Mode == "" {
		h.Mode = "pow"
	}
	if h.Mode == "captcha" {
		h.prov = providers[h.Provider]
		if h.VerifyURL != "" {
			h.prov.verifyURL = h.VerifyURL
		}
		h.client = &http.Client{Timeout: captchaVerifyTimeout}
	}
	return nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	if r.URL.Path == submitPath {
		if h.Mode == "captcha" {
			return h.verifyCaptchaSubmit(w, r)
		}
		return h.verify(w, r)
	}
	if h.hasClearance(r) {
		return next.ServeHTTP(w, r)
	}
	if flagged, _ := caddyhttp.GetVar(r.Context(), "aegis_challenge").(bool); flagged {
		h.serveInterstitial(w, r, r.URL.RequestURI())
		return nil
	}
	return next.ServeHTTP(w, r)
}

// verifyCaptchaSubmit validates a posted CAPTCHA response and, on success, mints
// the clearance cookie and redirects back to the original target.
func (h *Handler) verifyCaptchaSubmit(w http.ResponseWriter, r *http.Request) error {
	if err := r.ParseForm(); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return nil
	}
	token := r.Form.Get(h.prov.fieldName)
	to := sanitizeTarget(r.FormValue("to"))
	if token == "" {
		http.Redirect(w, r, to, http.StatusFound)
		return nil
	}
	ctx, cancel := context.WithTimeout(r.Context(), captchaVerifyTimeout)
	defer cancel()
	ok, err := verifyCaptcha(ctx, h.client, h.prov.verifyURL, h.CaptchaSecret, token, clientIP(r))
	if err != nil || !ok {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("captcha verification failed"))
		return nil
	}
	h.setClearance(w, r)
	http.Redirect(w, r, to, http.StatusFound)
	return nil
}

// --- clearance cookie ---

func (h *Handler) hasClearance(r *http.Request) bool {
	c, err := r.Cookie(clearanceName)
	if err != nil {
		return false
	}
	parts := strings.SplitN(c.Value, ".", 2)
	if len(parts) != 2 {
		return false
	}
	exp, err := strconv.ParseInt(parts[0], 16, 64)
	if err != nil || time.Now().Unix() > exp {
		return false
	}
	return hmac.Equal([]byte(parts[1]), []byte(h.mac(clearanceData(r, parts[0]))))
}

func (h *Handler) setClearance(w http.ResponseWriter, r *http.Request) {
	exp := strconv.FormatInt(time.Now().Add(clearanceTTL).Unix(), 16)
	val := exp + "." + h.mac(clearanceData(r, exp))
	http.SetCookie(w, &http.Cookie{
		Name: clearanceName, Value: val, Path: "/", HttpOnly: true,
		Secure: r.TLS != nil, SameSite: http.SameSiteLaxMode, MaxAge: int(clearanceTTL.Seconds()),
	})
}

func clearanceData(r *http.Request, exp string) string {
	return clientIP(r) + "|" + r.UserAgent() + "|" + exp
}

// --- challenge token ---

func (h *Handler) issueToken() string {
	exp := strconv.FormatInt(time.Now().Add(challengeTTL).Unix(), 16)
	rnd := make([]byte, 12)
	_, _ = rand.Read(rnd)
	body := exp + "." + hex.EncodeToString(rnd)
	return body + "." + h.mac(body)
}

func (h *Handler) validToken(tok string) bool {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return false
	}
	exp, err := strconv.ParseInt(parts[0], 16, 64)
	if err != nil || time.Now().Unix() > exp {
		return false
	}
	return hmac.Equal([]byte(parts[2]), []byte(h.mac(parts[0]+"."+parts[1])))
}

func (h *Handler) verify(w http.ResponseWriter, r *http.Request) error {
	tok := r.URL.Query().Get("c")
	nonce := r.URL.Query().Get("nonce")
	to := sanitizeTarget(r.URL.Query().Get("to"))

	if !h.validToken(tok) || !solved(tok, nonce, h.Difficulty) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("challenge failed"))
		return nil
	}
	h.setClearance(w, r)
	http.Redirect(w, r, to, http.StatusFound)
	return nil
}

// solved reports whether sha256(token||nonce) has >= difficulty leading zero bits.
func solved(token, nonce string, difficulty int) bool {
	sum := sha256.Sum256([]byte(token + nonce))
	return leadingZeroBits(sum[:]) >= difficulty
}

func leadingZeroBits(b []byte) int {
	n := 0
	for _, x := range b {
		if x == 0 {
			n += 8
			continue
		}
		n += bits.LeadingZeros8(x)
		break
	}
	return n
}

func (h *Handler) mac(data string) string {
	m := hmac.New(sha256.New, []byte(h.Secret))
	m.Write([]byte(data))
	return hex.EncodeToString(m.Sum(nil))
}

func sanitizeTarget(to string) string {
	if to == "" || !strings.HasPrefix(to, "/") || strings.HasPrefix(to, "//") {
		return "/"
	}
	return to
}

func clientIP(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

func (h *Handler) serveInterstitial(w http.ResponseWriter, _ *http.Request, to string) {
	var page string
	if h.Mode == "captcha" {
		page = strings.NewReplacer(
			"__SCRIPT__", h.prov.scriptURL,
			"__WIDGET__", h.prov.widgetClass,
			"__SITEKEY__", htmlEscape(h.SiteKey),
			"__TO__", htmlEscape(to),
			"__SUBMIT__", submitPath,
		).Replace(captchaHTML)
	} else {
		page = strings.NewReplacer(
			"__C__", h.issueToken(),
			"__DIFF__", strconv.Itoa(h.Difficulty),
			"__TO__", htmlEscape(to),
			"__SUBMIT__", submitPath,
		).Replace(interstitialHTML)
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusServiceUnavailable) // 503 while verifying
	_, _ = w.Write([]byte(page))
}

func htmlEscape(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&#39;")
	return r.Replace(s)
}

func (h *Handler) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		for d.NextBlock(0) {
			switch d.Val() {
			case "secret":
				if !d.NextArg() {
					return d.ArgErr()
				}
				h.Secret = d.Val()
			case "difficulty":
				if !d.NextArg() {
					return d.ArgErr()
				}
				n, err := strconv.Atoi(d.Val())
				if err != nil {
					return d.Errf("invalid difficulty: %v", err)
				}
				h.Difficulty = n
			case "mode":
				if !d.NextArg() {
					return d.ArgErr()
				}
				h.Mode = d.Val()
			case "provider":
				if !d.NextArg() {
					return d.ArgErr()
				}
				h.Provider = d.Val()
			case "sitekey":
				if !d.NextArg() {
					return d.ArgErr()
				}
				h.SiteKey = d.Val()
			case "captcha_secret":
				if !d.NextArg() {
					return d.ArgErr()
				}
				h.CaptchaSecret = d.Val()
			case "verify_url":
				if !d.NextArg() {
					return d.ArgErr()
				}
				h.VerifyURL = d.Val()
			default:
				return d.Errf("unknown challenge option %q", d.Val())
			}
		}
	}
	return nil
}

func parseCaddyfile(hc httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var m Handler
	err := m.UnmarshalCaddyfile(hc.Dispenser)
	return &m, err
}

var (
	_ caddyhttp.MiddlewareHandler = (*Handler)(nil)
	_ caddy.Provisioner           = (*Handler)(nil)
	_ caddyfile.Unmarshaler       = (*Handler)(nil)
)
