package challenge

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// captchaProvider describes a pluggable CAPTCHA vendor. Cloudflare Turnstile,
// hCaptcha and reCAPTCHA all share the same siteverify contract
// (POST form {secret,response,remoteip} -> JSON {"success":bool}) and only
// differ in widget script URL, widget element class, and response field name.
type captchaProvider struct {
	scriptURL   string
	widgetClass string
	fieldName   string
	verifyURL   string
}

var providers = map[string]captchaProvider{
	"turnstile": {
		scriptURL:   "https://challenges.cloudflare.com/turnstile/v0/api.js",
		widgetClass: "cf-turnstile",
		fieldName:   "cf-turnstile-response",
		verifyURL:   "https://challenges.cloudflare.com/turnstile/v0/siteverify",
	},
	"hcaptcha": {
		scriptURL:   "https://js.hcaptcha.com/1/api.js",
		widgetClass: "h-captcha",
		fieldName:   "h-captcha-response",
		verifyURL:   "https://hcaptcha.com/siteverify",
	},
	"recaptcha": {
		scriptURL:   "https://www.google.com/recaptcha/api.js",
		widgetClass: "g-recaptcha",
		fieldName:   "g-recaptcha-response",
		verifyURL:   "https://www.google.com/recaptcha/api/siteverify",
	},
}

// verifyCaptcha posts the client's CAPTCHA response to the provider's siteverify
// endpoint and reports whether it was accepted.
func verifyCaptcha(ctx context.Context, client *http.Client, verifyURL, secret, response, remoteIP string) (bool, error) {
	form := url.Values{"secret": {secret}, "response": {response}}
	if remoteIP != "" {
		form.Set("remoteip", remoteIP)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, verifyURL, strings.NewReader(form.Encode()))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	var out struct {
		Success bool `json:"success"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&out); err != nil {
		return false, err
	}
	return out.Success, nil
}

const captchaVerifyTimeout = 8 * time.Second
