// Package auth implements password auth, Redis-backed sessions, TOTP MFA,
// CSRF protection, and RBAC middleware for the control plane.
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"

	"github.com/aegis/control-plane/internal/appcfg"
	"github.com/aegis/control-plane/internal/mailer"
	"github.com/aegis/control-plane/internal/store"
)

// Auth bundles dependencies for authentication handlers and middleware.
type Auth struct {
	Store  *store.Store
	Cfg    *appcfg.Config
	Mailer mailer.Mailer
	secure bool // emit Secure cookies (https control-plane)
}

func New(st *store.Store, cfg *appcfg.Config, ml mailer.Mailer) *Auth {
	return &Auth{
		Store:  st,
		Cfg:    cfg,
		Mailer: ml,
		secure: strings.HasPrefix(cfg.ControlPlaneURL, "https"),
	}
}

// randToken returns a URL-safe random token with n bytes of entropy.
func randToken(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// hashToken returns the hex SHA-256 of a token, for at-rest storage.
func hashToken(tok string) string {
	sum := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(sum[:])
}
