package auth

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5/middleware"

	"github.com/aegis/control-plane/internal/web"
)

// Login/MFA brute-force throttle: cap failed unauthenticated auth attempts per
// client IP so the dashboard's login and MFA endpoints can't be hammered. Only
// failed attempts (401/403) count against the window; a successful auth clears
// it. Keyed per-IP (not per-account) to avoid letting an attacker lock a victim
// out. This is application-layer defence in depth on top of the edge's per-IP
// rate limit (which uses the spoof-resistant connection IP).
var (
	authRateWindow = 15 * time.Minute
	authRateMax    = 10
)

func authRateKey(ip string) string { return "auth:rl:" + ip }

// RateLimitAuth throttles the auth endpoints it wraps (login, MFA) by client IP
// using Redis. Fails open if Redis is unavailable so an outage can't lock
// everyone out.
func (a *Auth) RateLimitAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := authRateKey(clientIP(r))
		ctx := r.Context()

		if n, err := a.Store.Redis.Get(ctx, key).Int(); err == nil && n >= authRateMax {
			ttl, err := a.Store.Redis.TTL(ctx, key).Result()
			if err != nil || ttl <= 0 {
				ttl = authRateWindow
			}
			w.Header().Set("Retry-After", strconv.Itoa(int(ttl.Seconds())))
			web.Error(w, http.StatusTooManyRequests, "rate_limited", "too many attempts; try again later")
			return
		}

		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
		next.ServeHTTP(ww, r)

		switch {
		case ww.Status() == http.StatusUnauthorized || ww.Status() == http.StatusForbidden:
			a.recordAuthFailure(ctx, key)
		case ww.Status() >= 200 && ww.Status() < 400:
			_ = a.Store.Redis.Del(ctx, key).Err()
		}
	})
}

// recordAuthFailure increments the per-IP failure counter, setting the window
// TTL on the first failure.
func (a *Auth) recordAuthFailure(ctx context.Context, key string) {
	n, err := a.Store.Redis.Incr(ctx, key).Result()
	if err != nil {
		return
	}
	if n == 1 {
		_ = a.Store.Redis.Expire(ctx, key, authRateWindow).Err()
	}
}
