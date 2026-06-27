package auth

import (
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/aegis/control-plane/internal/store"
	"github.com/aegis/control-plane/internal/web"
)

var emailRe = regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`)

// dummyHash equalises login timing for unknown emails (anti-enumeration).
var dummyHash, _ = HashPassword("aegis-dummy-password-for-timing")

// UserDTO is the safe, public representation of a user.
type UserDTO struct {
	ID            string    `json:"id"`
	Email         string    `json:"email"`
	Role          string    `json:"role"`
	Status        string    `json:"status"`
	EmailVerified bool      `json:"email_verified"`
	TOTPEnabled   bool      `json:"totp_enabled"`
	CreatedAt     time.Time `json:"created_at"`
}

func toUserDTO(u *store.User) UserDTO {
	return UserDTO{
		ID: u.ID.String(), Email: u.Email, Role: u.Role, Status: u.Status,
		EmailVerified: u.EmailVerified, TOTPEnabled: u.TOTPEnabled, CreatedAt: u.CreatedAt,
	}
}

func validateCredentials(email, password string) error {
	email = strings.TrimSpace(email)
	if !emailRe.MatchString(email) {
		return errors.New("invalid email address")
	}
	if len(password) < 10 {
		return errors.New("password must be at least 10 characters")
	}
	return nil
}

// Signup creates a new account + owner user and logs them in.
func (a *Auth) Signup(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := web.Decode(w, r, &in); err != nil {
		web.Error(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	in.Email = strings.ToLower(strings.TrimSpace(in.Email))
	if err := validateCredentials(in.Email, in.Password); err != nil {
		web.Error(w, http.StatusBadRequest, "validation", err.Error())
		return
	}
	if _, err := a.Store.GetUserByEmail(r.Context(), in.Email); err == nil {
		web.Error(w, http.StatusConflict, "email_taken", "an account with this email already exists")
		return
	}
	hash, err := HashPassword(in.Password)
	if err != nil {
		web.Error(w, http.StatusInternalServerError, "internal", "could not hash password")
		return
	}
	u, err := a.Store.CreateAccountWithUser(r.Context(), in.Email, in.Email, hash, "user")
	if err != nil {
		web.Error(w, http.StatusInternalServerError, "internal", "could not create account")
		return
	}
	a.sendVerificationEmail(r, u)
	if err := a.createSession(r.Context(), w, Session{UserID: u.ID, CreatedAt: time.Now()}); err != nil {
		web.Error(w, http.StatusInternalServerError, "internal", "could not start session")
		return
	}
	_ = a.Store.Audit(r.Context(), &u.AccountID, &u.ID, "user.signup", u.Email, clientIP(r), nil)
	web.JSON(w, http.StatusCreated, map[string]any{"user": toUserDTO(u)})
}

// Login authenticates a user; may require an MFA second step.
func (a *Auth) Login(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := web.Decode(w, r, &in); err != nil {
		web.Error(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	in.Email = strings.ToLower(strings.TrimSpace(in.Email))
	u, err := a.Store.GetUserByEmail(r.Context(), in.Email)
	if err != nil {
		_, _ = VerifyPassword(in.Password, dummyHash) // equalise timing
		web.Error(w, http.StatusUnauthorized, "invalid_credentials", "invalid email or password")
		return
	}
	ok, _ := VerifyPassword(in.Password, u.PasswordHash)
	if !ok {
		web.Error(w, http.StatusUnauthorized, "invalid_credentials", "invalid email or password")
		return
	}
	if u.Status != "active" {
		web.Error(w, http.StatusForbidden, "suspended", "account suspended")
		return
	}
	sess := Session{UserID: u.ID, CreatedAt: time.Now(), MFARequired: u.TOTPEnabled}
	if err := a.createSession(r.Context(), w, sess); err != nil {
		web.Error(w, http.StatusInternalServerError, "internal", "could not start session")
		return
	}
	if u.TOTPEnabled {
		web.JSON(w, http.StatusOK, map[string]any{"mfa_required": true})
		return
	}
	_ = a.Store.TouchLastLogin(r.Context(), u.ID)
	_ = a.Store.Audit(r.Context(), &u.AccountID, &u.ID, "user.login", u.Email, clientIP(r), nil)
	web.JSON(w, http.StatusOK, map[string]any{"user": toUserDTO(u)})
}

// MFAVerifyLogin completes the second factor for a pending login session.
func (a *Auth) MFAVerifyLogin(w http.ResponseWriter, r *http.Request) {
	id, sess, err := a.loadSession(r.Context(), r)
	if err != nil {
		web.Error(w, http.StatusUnauthorized, "unauthorized", "no pending login")
		return
	}
	var in struct {
		Code string `json:"code"`
	}
	if err := web.Decode(w, r, &in); err != nil {
		web.Error(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	u, err := a.Store.GetUserByID(r.Context(), sess.UserID)
	if err != nil || u.TOTPSecret == nil {
		web.Error(w, http.StatusUnauthorized, "unauthorized", "invalid state")
		return
	}
	if !validateTOTP(*u.TOTPSecret, strings.TrimSpace(in.Code)) {
		web.Error(w, http.StatusUnauthorized, "invalid_code", "invalid authentication code")
		return
	}
	sess.MFARequired = false
	if err := a.saveSession(r.Context(), id, *sess); err != nil {
		web.Error(w, http.StatusInternalServerError, "internal", "could not update session")
		return
	}
	_ = a.Store.TouchLastLogin(r.Context(), u.ID)
	web.JSON(w, http.StatusOK, map[string]any{"user": toUserDTO(u)})
}

// Logout destroys the current session.
func (a *Auth) Logout(w http.ResponseWriter, r *http.Request) {
	a.destroySession(r.Context(), w, r)
	web.JSON(w, http.StatusOK, map[string]any{"ok": true})
}

// Me returns the currently authenticated user, plus the impersonating admin
// when the session is in an impersonation.
func (a *Auth) Me(w http.ResponseWriter, r *http.Request) {
	u := MustUser(r.Context())
	resp := map[string]any{"user": toUserDTO(u)}
	if sess, ok := SessionFrom(r.Context()); ok && sess.ImpersonatorID != nil {
		resp["impersonator"] = map[string]any{
			"id":    sess.ImpersonatorID.String(),
			"email": sess.ImpersonatorEmail,
		}
	}
	web.JSON(w, http.StatusOK, resp)
}

// VerifyEmail consumes an email verification token.
func (a *Auth) VerifyEmail(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Token string `json:"token"`
	}
	if err := web.Decode(w, r, &in); err != nil {
		web.Error(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	uid, err := a.Store.ConsumeEmailToken(r.Context(), hashToken(in.Token), "verify_email")
	if err != nil {
		web.Error(w, http.StatusBadRequest, "invalid_token", "invalid or expired token")
		return
	}
	_ = a.Store.MarkEmailVerified(r.Context(), uid)
	web.JSON(w, http.StatusOK, map[string]any{"ok": true})
}

// --- MFA setup (authenticated) ---

func (a *Auth) MFASetup(w http.ResponseWriter, r *http.Request) {
	u := MustUser(r.Context())
	key, err := generateTOTP(a.Cfg.Brand, u.Email)
	if err != nil {
		web.Error(w, http.StatusInternalServerError, "internal", "could not generate secret")
		return
	}
	if err := a.Store.SetTOTPSecret(r.Context(), u.ID, key.Secret()); err != nil {
		web.Error(w, http.StatusInternalServerError, "internal", "could not store secret")
		return
	}
	web.JSON(w, http.StatusOK, map[string]any{
		"secret":      key.Secret(),
		"otpauth_url": key.URL(),
	})
}

func (a *Auth) MFAEnable(w http.ResponseWriter, r *http.Request) {
	u := MustUser(r.Context())
	var in struct {
		Code string `json:"code"`
	}
	if err := web.Decode(w, r, &in); err != nil {
		web.Error(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	if u.TOTPSecret == nil {
		web.Error(w, http.StatusBadRequest, "no_secret", "run MFA setup first")
		return
	}
	if !validateTOTP(*u.TOTPSecret, strings.TrimSpace(in.Code)) {
		web.Error(w, http.StatusBadRequest, "invalid_code", "code did not match")
		return
	}
	if err := a.Store.SetTOTPEnabled(r.Context(), u.ID, true); err != nil {
		web.Error(w, http.StatusInternalServerError, "internal", "could not enable MFA")
		return
	}
	web.JSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (a *Auth) MFADisable(w http.ResponseWriter, r *http.Request) {
	u := MustUser(r.Context())
	var in struct {
		Password string `json:"password"`
	}
	if err := web.Decode(w, r, &in); err != nil {
		web.Error(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	if ok, _ := VerifyPassword(in.Password, u.PasswordHash); !ok {
		web.Error(w, http.StatusUnauthorized, "invalid_credentials", "password incorrect")
		return
	}
	_ = a.Store.SetTOTPEnabled(r.Context(), u.ID, false)
	_ = a.Store.SetTOTPSecret(r.Context(), u.ID, "")
	web.JSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (a *Auth) sendVerificationEmail(r *http.Request, u *store.User) {
	tok := randToken(32)
	if err := a.Store.CreateEmailToken(r.Context(), u.ID, hashToken(tok), "verify_email", time.Now().Add(24*time.Hour)); err != nil {
		return
	}
	link := fmt.Sprintf("%s/verify?token=%s", strings.TrimRight(a.Cfg.DashboardURL, "/"), tok)
	body := fmt.Sprintf("Welcome to %s!\n\nConfirm your email:\n%s\n\nThis link expires in 24 hours.", a.Cfg.Brand, link)
	_ = a.Mailer.Send(r.Context(), u.Email, "Verify your email", body)
}

func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return strings.TrimSpace(strings.Split(xff, ",")[0])
	}
	if xr := r.Header.Get("X-Real-IP"); xr != "" {
		return xr
	}
	host, _, _ := strings.Cut(r.RemoteAddr, ":")
	return host
}
