package auth

import (
	"context"
	"crypto/subtle"
	"net/http"

	"github.com/aegis/control-plane/internal/store"
	"github.com/aegis/control-plane/internal/web"
)

type ctxKey int

const (
	userKey ctxKey = iota
	sessionIDKey
)

// UserFrom returns the authenticated user from the request context.
func UserFrom(ctx context.Context) (*store.User, bool) {
	u, ok := ctx.Value(userKey).(*store.User)
	return u, ok
}

// MustUser returns the authenticated user or panics (only use behind RequireAuth).
func MustUser(ctx context.Context) *store.User {
	u, _ := UserFrom(ctx)
	return u
}

func sessionIDFrom(ctx context.Context) string {
	s, _ := ctx.Value(sessionIDKey).(string)
	return s
}

// RequireAuth ensures a valid, MFA-complete session and loads the user.
func (a *Auth) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, sess, err := a.loadSession(r.Context(), r)
		if err != nil {
			web.Error(w, http.StatusUnauthorized, "unauthorized", "authentication required")
			return
		}
		if sess.MFARequired {
			web.Error(w, http.StatusUnauthorized, "mfa_required", "multi-factor authentication required")
			return
		}
		u, err := a.Store.GetUserByID(r.Context(), sess.UserID)
		if err != nil {
			web.Error(w, http.StatusUnauthorized, "unauthorized", "session user not found")
			return
		}
		if u.Status != "active" {
			web.Error(w, http.StatusForbidden, "suspended", "account suspended")
			return
		}
		ctx := context.WithValue(r.Context(), userKey, u)
		ctx = context.WithValue(ctx, sessionIDKey, id)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequireRole ensures the authenticated user has one of the allowed roles.
func RequireRole(roles ...string) func(http.Handler) http.Handler {
	allowed := make(map[string]bool, len(roles))
	for _, r := range roles {
		allowed[r] = true
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			u, ok := UserFrom(r.Context())
			if !ok || !allowed[u.Role] {
				web.Error(w, http.StatusForbidden, "forbidden", "insufficient privileges")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// CSRF enforces double-submit token checks on state-changing requests.
func (a *Auth) CSRF(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			next.ServeHTTP(w, r)
			return
		}
		cookie, err := r.Cookie(csrfCookie)
		header := r.Header.Get("X-CSRF-Token")
		if err != nil || header == "" || subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(header)) != 1 {
			web.Error(w, http.StatusForbidden, "csrf", "invalid or missing CSRF token")
			return
		}
		next.ServeHTTP(w, r)
	})
}
