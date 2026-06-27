package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

const (
	sessionCookie = "aegis_session"
	csrfCookie    = "aegis_csrf"
	sessionTTL    = 7 * 24 * time.Hour
)

// Session is the server-side session record stored in Redis.
type Session struct {
	UserID      uuid.UUID `json:"uid"`
	CreatedAt   time.Time `json:"ct"`
	MFARequired bool      `json:"mfa"` // true while TOTP step is still pending

	// Impersonation: when an admin assumes another user's identity, UserID is the
	// target and these record the real admin so the session can be restored.
	ImpersonatorID    *uuid.UUID `json:"imp,omitempty"`
	ImpersonatorEmail string     `json:"impe,omitempty"`
}

func sessKey(id string) string { return "sess:" + id }

// createSession persists a new session and sets the session + CSRF cookies.
func (a *Auth) createSession(ctx context.Context, w http.ResponseWriter, sess Session) error {
	id := randToken(32)
	data, err := json.Marshal(sess)
	if err != nil {
		return err
	}
	if err := a.Store.Redis.Set(ctx, sessKey(id), data, sessionTTL).Err(); err != nil {
		return err
	}
	a.setCookie(w, sessionCookie, id, sessionTTL, true)
	a.setCookie(w, csrfCookie, randToken(24), sessionTTL, false) // readable by JS for double-submit
	return nil
}

// loadSession reads and decodes the session referenced by the request cookie.
func (a *Auth) loadSession(ctx context.Context, r *http.Request) (string, *Session, error) {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return "", nil, errors.New("no session")
	}
	raw, err := a.Store.Redis.Get(ctx, sessKey(c.Value)).Bytes()
	if errors.Is(err, redis.Nil) {
		return "", nil, errors.New("session expired")
	} else if err != nil {
		return "", nil, err
	}
	var sess Session
	if err := json.Unmarshal(raw, &sess); err != nil {
		return "", nil, err
	}
	return c.Value, &sess, nil
}

func (a *Auth) saveSession(ctx context.Context, id string, sess Session) error {
	data, err := json.Marshal(sess)
	if err != nil {
		return err
	}
	return a.Store.Redis.Set(ctx, sessKey(id), data, sessionTTL).Err()
}

func (a *Auth) destroySession(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		_ = a.Store.Redis.Del(ctx, sessKey(c.Value)).Err()
	}
	a.clearCookie(w, sessionCookie)
	a.clearCookie(w, csrfCookie)
}

func (a *Auth) setCookie(w http.ResponseWriter, name, value string, ttl time.Duration, httpOnly bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		MaxAge:   int(ttl.Seconds()),
		HttpOnly: httpOnly,
		Secure:   a.secure,
		SameSite: http.SameSiteLaxMode,
	})
}

func (a *Auth) clearCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{
		Name: name, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: name == sessionCookie, Secure: a.secure, SameSite: http.SameSiteLaxMode,
	})
}
