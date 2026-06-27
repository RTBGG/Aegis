// Package admin implements the admin-only surface: user oversight, edge fleet,
// global blocklists, edge-enrollment tokens, and global analytics.
package admin

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/aegis/control-plane/internal/appcfg"
	"github.com/aegis/control-plane/internal/auth"
	"github.com/aegis/control-plane/internal/config"
	"github.com/aegis/control-plane/internal/mailer"
	"github.com/aegis/control-plane/internal/store"
	"github.com/aegis/control-plane/internal/threatfeed"
	"github.com/aegis/control-plane/internal/web"
)

type Service struct {
	Store  *store.Store
	Cfg    *appcfg.Config
	Render *config.Renderer
	Feeds  *threatfeed.Syncer
	Mailer mailer.Mailer
}

func New(st *store.Store, cfg *appcfg.Config, r *config.Renderer, feeds *threatfeed.Syncer, ml mailer.Mailer) *Service {
	return &Service{Store: st, Cfg: cfg, Render: r, Feeds: feeds, Mailer: ml}
}

// --- users ---

func (s *Service) Users(w http.ResponseWriter, r *http.Request) {
	rows, err := s.Store.ListUsersWithStats(r.Context())
	if err != nil {
		web.Error(w, http.StatusInternalServerError, "internal", "could not list users")
		return
	}
	web.JSON(w, http.StatusOK, map[string]any{"users": rows})
}

func (s *Service) SetUserStatus(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "userID"))
	if err != nil {
		web.Error(w, http.StatusBadRequest, "bad_id", "invalid user id")
		return
	}
	var in struct {
		Status string `json:"status"`
	}
	if err := web.Decode(w, r, &in); err != nil {
		web.Error(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	if in.Status != "active" && in.Status != "suspended" {
		web.Error(w, http.StatusBadRequest, "validation", "status must be active or suspended")
		return
	}
	actor := auth.MustUser(r.Context())
	if actor.ID == id {
		web.Error(w, http.StatusBadRequest, "self", "cannot change your own status")
		return
	}
	if err := s.Store.SetUserStatus(r.Context(), id, in.Status); err != nil {
		web.Error(w, http.StatusInternalServerError, "internal", "could not update user")
		return
	}
	_ = s.Store.Audit(r.Context(), nil, &actor.ID, "admin.user_status", id.String(), "", map[string]any{"status": in.Status})
	web.JSON(w, http.StatusOK, map[string]any{"ok": true})
}

// --- email / SMTP ---

// EmailConfig returns the non-secret outbound-mail settings for the admin UI.
func (s *Service) EmailConfig(w http.ResponseWriter, r *http.Request) {
	web.JSON(w, http.StatusOK, map[string]any{
		"mailer": s.Cfg.Mailer,
		"addr":   s.Cfg.SMTP.Addr,
		"from":   s.Cfg.SMTP.From,
		"tls":    s.Cfg.SMTP.TLS,
		"auth":   s.Cfg.SMTP.Username != "",
	})
}

// TestEmail sends a test message to the requesting admin to verify mail delivery.
func (s *Service) TestEmail(w http.ResponseWriter, r *http.Request) {
	actor := auth.MustUser(r.Context())
	subject := s.Cfg.Brand + " — SMTP test email"
	body := fmt.Sprintf("This is a test email from %s confirming your outbound mail (MAILER=%s) is working.\n\nDelivered to: %s\n",
		s.Cfg.Brand, s.Cfg.Mailer, actor.Email)
	if err := s.Mailer.Send(r.Context(), actor.Email, subject, body); err != nil {
		web.Error(w, http.StatusBadGateway, "mail_error", "send failed: "+err.Error())
		return
	}
	_ = s.Store.Audit(r.Context(), nil, &actor.ID, "admin.test_email", actor.Email, r.RemoteAddr, nil)
	web.JSON(w, http.StatusOK, map[string]any{"ok": true, "sent_to": actor.Email})
}

// --- impersonation audit ---

func (s *Service) ImpersonationLog(w http.ResponseWriter, r *http.Request) {
	rows, err := s.Store.ListImpersonationAudit(r.Context(), 50)
	if err != nil {
		web.Error(w, http.StatusInternalServerError, "internal", "could not load audit log")
		return
	}
	type entryView struct {
		ID         int64     `json:"id"`
		Action     string    `json:"action"`
		ActorEmail *string   `json:"actor_email"`
		Target     *string   `json:"target"`
		IP         *string   `json:"ip"`
		CreatedAt  time.Time `json:"created_at"`
	}
	out := make([]entryView, len(rows))
	for i, e := range rows {
		out[i] = entryView{ID: e.ID, Action: e.Action, ActorEmail: e.ActorEmail, Target: e.Target, IP: e.IP, CreatedAt: e.CreatedAt}
	}
	web.JSON(w, http.StatusOK, map[string]any{"entries": out})
}

// --- edge fleet ---

func (s *Service) Edges(w http.ResponseWriter, r *http.Request) {
	edges, err := s.Store.ListEdges(r.Context())
	if err != nil {
		web.Error(w, http.StatusInternalServerError, "internal", "could not list edges")
		return
	}
	web.JSON(w, http.StatusOK, map[string]any{"edges": edges})
}

// --- global analytics ---

func (s *Service) Analytics(w http.ResponseWriter, r *http.Request) {
	since := time.Now().Add(-24 * time.Hour)
	sum, err := s.Store.MetricsSummarySince(r.Context(), since)
	if err != nil {
		web.Error(w, http.StatusInternalServerError, "internal", "could not load metrics")
		return
	}
	users, _ := s.Store.CountUsers(r.Context())
	web.JSON(w, http.StatusOK, map[string]any{"summary": sum, "users": users})
}

// --- blocklists ---

func (s *Service) ListBlocklists(w http.ResponseWriter, r *http.Request) {
	bls, err := s.Store.ListBlocklists(r.Context())
	if err != nil {
		web.Error(w, http.StatusInternalServerError, "internal", "could not list blocklists")
		return
	}
	web.JSON(w, http.StatusOK, map[string]any{"blocklists": bls})
}

func (s *Service) CreateBlocklist(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Scope  string  `json:"scope"`
		Kind   string  `json:"kind"`
		Value  string  `json:"value"`
		Action string  `json:"action"`
		Note   *string `json:"note"`
	}
	if err := web.Decode(w, r, &in); err != nil {
		web.Error(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	in.Scope, in.Action = strings.ToLower(in.Scope), strings.ToLower(in.Action)
	in.Kind, in.Value = strings.ToLower(strings.TrimSpace(in.Kind)), strings.TrimSpace(in.Value)
	if in.Scope == "" {
		in.Scope = "global"
	}
	if in.Action == "" {
		in.Action = "block"
	}
	if in.Value == "" {
		web.Error(w, http.StatusBadRequest, "validation", "value is required")
		return
	}
	switch in.Kind {
	case "ip", "cidr", "asn", "ja4", "country":
	default:
		web.Error(w, http.StatusBadRequest, "validation", "kind must be ip/cidr/asn/ja4/country")
		return
	}
	bl, err := s.Store.CreateBlocklist(r.Context(), &store.Blocklist{
		Scope: in.Scope, Kind: in.Kind, Value: in.Value, Action: in.Action, Note: in.Note,
	})
	if err != nil {
		web.Error(w, http.StatusInternalServerError, "internal", "could not create blocklist entry")
		return
	}
	_, _, _ = s.Render.Rebuild(r.Context())
	web.JSON(w, http.StatusCreated, map[string]any{"blocklist": bl})
}

func (s *Service) DeleteBlocklist(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		web.Error(w, http.StatusBadRequest, "bad_id", "invalid id")
		return
	}
	if err := s.Store.DeleteBlocklist(r.Context(), id); err != nil {
		web.Error(w, http.StatusInternalServerError, "internal", "could not delete entry")
		return
	}
	_, _, _ = s.Render.Rebuild(r.Context())
	web.JSON(w, http.StatusOK, map[string]any{"ok": true})
}

// --- threat feeds (Phase 2 auto-blocklists) ---

type feedDTO struct {
	ID              uuid.UUID  `json:"id"`
	Slug            string     `json:"slug"`
	Name            string     `json:"name"`
	URL             string     `json:"url"`
	Format          string     `json:"format"`
	Enabled         bool       `json:"enabled"`
	RefreshInterval int32      `json:"refresh_interval"`
	LastSyncedAt    *time.Time `json:"last_synced_at"`
	LastStatus      *string    `json:"last_status"`
	LastError       *string    `json:"last_error"`
	EntryCount      int32      `json:"entry_count"`
}

func toFeedDTO(f store.ThreatFeed) feedDTO {
	return feedDTO{
		ID: f.ID, Slug: f.Slug, Name: f.Name, URL: f.URL, Format: f.Format,
		Enabled: f.Enabled, RefreshInterval: f.RefreshInterval,
		LastSyncedAt: f.LastSyncedAt, LastStatus: f.LastStatus, LastError: f.LastError,
		EntryCount: f.EntryCount,
	}
}

func (s *Service) ListThreatFeeds(w http.ResponseWriter, r *http.Request) {
	feeds, err := s.Store.ListThreatFeeds(r.Context())
	if err != nil {
		web.Error(w, http.StatusInternalServerError, "internal", "could not list threat feeds")
		return
	}
	out := make([]feedDTO, len(feeds))
	for i, f := range feeds {
		out[i] = toFeedDTO(f)
	}
	web.JSON(w, http.StatusOK, map[string]any{"feeds": out})
}

func (s *Service) UpdateThreatFeed(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		web.Error(w, http.StatusBadRequest, "bad_id", "invalid id")
		return
	}
	var in struct {
		Enabled bool `json:"enabled"`
	}
	if err := web.Decode(w, r, &in); err != nil {
		web.Error(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	if err := s.Store.SetThreatFeedEnabled(r.Context(), id, in.Enabled); err != nil {
		web.Error(w, http.StatusInternalServerError, "internal", "could not update feed")
		return
	}
	actor := auth.MustUser(r.Context())
	_ = s.Store.Audit(r.Context(), nil, &actor.ID, "admin.threat_feed", id.String(), "", map[string]any{"enabled": in.Enabled})
	// Toggling a feed changes the effective edge blocklist.
	_, _, _ = s.Render.Rebuild(r.Context())
	f, err := s.Store.GetThreatFeed(r.Context(), id)
	if err != nil {
		web.Error(w, http.StatusNotFound, "not_found", "feed not found")
		return
	}
	web.JSON(w, http.StatusOK, map[string]any{"feed": toFeedDTO(*f)})
}

func (s *Service) RefreshThreatFeed(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		web.Error(w, http.StatusBadRequest, "bad_id", "invalid id")
		return
	}
	f, err := s.Feeds.RefreshNow(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		web.Error(w, http.StatusNotFound, "not_found", "feed not found")
		return
	}
	if err != nil {
		web.Error(w, http.StatusInternalServerError, "internal", "could not refresh feed")
		return
	}
	actor := auth.MustUser(r.Context())
	_ = s.Store.Audit(r.Context(), nil, &actor.ID, "admin.threat_feed_refresh", id.String(), "", nil)
	web.JSON(w, http.StatusOK, map[string]any{"feed": toFeedDTO(*f)})
}

// --- edge enrollment tokens (Phase 3 provisioning; mint/list available now) ---

func (s *Service) ListEnrollmentTokens(w http.ResponseWriter, r *http.Request) {
	toks, err := s.Store.ListEnrollmentTokens(r.Context())
	if err != nil {
		web.Error(w, http.StatusInternalServerError, "internal", "could not list tokens")
		return
	}
	// Never expose token_hash to the client.
	type tokView struct {
		ID        uuid.UUID  `json:"id"`
		Note      *string    `json:"note"`
		ExpiresAt time.Time  `json:"expires_at"`
		UsedAt    *time.Time `json:"used_at"`
		CreatedAt time.Time  `json:"created_at"`
	}
	out := make([]tokView, len(toks))
	for i, t := range toks {
		out[i] = tokView{ID: t.ID, Note: t.Note, ExpiresAt: t.ExpiresAt, UsedAt: t.UsedAt, CreatedAt: t.CreatedAt}
	}
	web.JSON(w, http.StatusOK, map[string]any{"tokens": out})
}

func (s *Service) CreateEnrollmentToken(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Note     string `json:"note"`
		TTLHours int    `json:"ttl_hours"`
	}
	_ = web.Decode(w, r, &in)
	if in.TTLHours <= 0 || in.TTLHours > 168 {
		in.TTLHours = 24
	}
	raw := randToken(32)
	actor := auth.MustUser(r.Context())
	expires := time.Now().Add(time.Duration(in.TTLHours) * time.Hour)
	if _, err := s.Store.CreateEnrollmentToken(r.Context(), hashToken(raw), in.Note, &actor.ID, expires); err != nil {
		web.Error(w, http.StatusInternalServerError, "internal", "could not create token")
		return
	}
	installCmd := fmt.Sprintf("curl -fsSL %s/install/edge.sh | sudo ENROLL_TOKEN=%s bash",
		strings.TrimRight(s.Cfg.ControlPlaneURL, "/"), raw)
	_ = s.Store.Audit(r.Context(), nil, &actor.ID, "admin.enroll_token", "", "", nil)
	// The raw token is shown exactly once.
	web.JSON(w, http.StatusCreated, map[string]any{
		"token":       raw,
		"expires_at":  expires,
		"install_cmd": installCmd,
	})
}

func randToken(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func hashToken(tok string) string {
	sum := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(sum[:])
}
