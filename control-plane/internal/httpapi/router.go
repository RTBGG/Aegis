// Package httpapi assembles the control-plane HTTP router.
package httpapi

import (
	_ "embed"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/aegis/control-plane/internal/admin"
	"github.com/aegis/control-plane/internal/analytics"
	"github.com/aegis/control-plane/internal/appcfg"
	"github.com/aegis/control-plane/internal/auth"
	"github.com/aegis/control-plane/internal/domains"
	"github.com/aegis/control-plane/internal/edgeapi"
	"github.com/aegis/control-plane/internal/security"
)

//go:embed edge.sh
var edgeScript string

// Deps carries the handler services the router wires together.
type Deps struct {
	Cfg       *appcfg.Config
	Auth      *auth.Auth
	Domains   *domains.Service
	Security  *security.Service
	Analytics *analytics.Service
	Admin     *admin.Service
	Edge      *edgeapi.API
}

func NewRouter(d Deps) http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.StripSlashes)
	r.Use(middleware.Timeout(60 * time.Second))
	r.Use(corsMiddleware(d.Cfg))

	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})

	// Served enrollment script (rendered with this control plane's URL).
	r.Get("/install/edge.sh", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/x-shellscript")
		_, _ = w.Write([]byte(strings.ReplaceAll(edgeScript, "__CONTROL_PLANE_URL__", strings.TrimRight(d.Cfg.ControlPlaneURL, "/"))))
	})

	// Edge enrollment: unauthenticated except by the single-use enrollment token
	// carried in the body. Exchanges it for a durable per-node agent token.
	r.Post("/edge/v1/enroll", d.Edge.Enroll)

	// Edge-facing API (agent bearer token, no CSRF).
	r.Route("/edge/v1", func(r chi.Router) {
		r.Use(d.Edge.Authn)
		r.Get("/config", d.Edge.Config)
		r.Post("/telemetry", d.Edge.Telemetry)
		r.Post("/events", d.Edge.Events)
	})

	r.Route("/api/v1", func(r chi.Router) {
		// Unauthenticated auth endpoints (no session yet => no CSRF).
		r.Post("/auth/signup", d.Auth.Signup)
		r.Post("/auth/login", d.Auth.Login)
		r.Post("/auth/mfa", d.Auth.MFAVerifyLogin)
		r.Post("/auth/verify-email", d.Auth.VerifyEmail)

		// Authenticated, CSRF-protected.
		r.Group(func(r chi.Router) {
			r.Use(d.Auth.RequireAuth)
			r.Use(d.Auth.CSRF)

			r.Get("/auth/me", d.Auth.Me)
			r.Post("/auth/logout", d.Auth.Logout)
			r.Post("/auth/impersonate/stop", d.Auth.ImpersonateStop)
			r.Post("/auth/mfa/setup", d.Auth.MFASetup)
			r.Post("/auth/mfa/enable", d.Auth.MFAEnable)
			r.Post("/auth/mfa/disable", d.Auth.MFADisable)

			r.Get("/domains", d.Domains.List)
			r.Post("/domains", d.Domains.Create)
			r.Get("/domains/{domainID}", d.Domains.Get)
			r.Delete("/domains/{domainID}", d.Domains.Delete)
			r.Post("/domains/{domainID}/verify", d.Domains.Verify)
			r.Post("/domains/{domainID}/pause", d.Domains.SetPaused)
			r.Get("/domains/{domainID}/records", d.Domains.ListRecords)
			r.Post("/domains/{domainID}/records", d.Domains.CreateRecord)
			r.Get("/domains/{domainID}/dnssec", d.Domains.GetDNSSEC)
			r.Post("/domains/{domainID}/dnssec", d.Domains.EnableDNSSEC)
			r.Delete("/domains/{domainID}/dnssec", d.Domains.DisableDNSSEC)
			r.Get("/domains/{domainID}/security", d.Security.Get)
			r.Put("/domains/{domainID}/security", d.Security.Update)
			r.Get("/domains/{domainID}/waf/overrides", d.Security.ListOverrides)
			r.Post("/domains/{domainID}/waf/overrides", d.Security.CreateOverride)
			r.Delete("/domains/{domainID}/waf/overrides/{overrideID}", d.Security.DeleteOverride)
			r.Get("/domains/{domainID}/analytics", d.Analytics.Domain)
			r.Get("/domains/{domainID}/insights", d.Analytics.Insights)
			r.Put("/records/{recordID}", d.Domains.UpdateRecord)
			r.Delete("/records/{recordID}", d.Domains.DeleteRecord)
			r.Get("/analytics/overview", d.Analytics.Overview)

			// Admin-only.
			r.Group(func(r chi.Router) {
				r.Use(auth.RequireRole("admin", "superadmin"))
				r.Get("/admin/users", d.Admin.Users)
				r.Post("/admin/users/{userID}/status", d.Admin.SetUserStatus)
				r.Post("/admin/users/{userID}/impersonate", d.Auth.ImpersonateStart)
				r.Get("/admin/impersonation-log", d.Admin.ImpersonationLog)
				r.Get("/admin/email-config", d.Admin.EmailConfig)
				r.Post("/admin/test-email", d.Admin.TestEmail)
				r.Get("/admin/edges", d.Admin.Edges)
				r.Post("/admin/edges/{id}/weight", d.Admin.SetEdgeWeight)
				r.Post("/admin/edges/{id}/region", d.Admin.SetEdgeRegion)
				r.Get("/admin/analytics", d.Admin.Analytics)
				r.Get("/admin/blocklists", d.Admin.ListBlocklists)
				r.Post("/admin/blocklists", d.Admin.CreateBlocklist)
				r.Delete("/admin/blocklists/{id}", d.Admin.DeleteBlocklist)
				r.Get("/admin/threat-feeds", d.Admin.ListThreatFeeds)
				r.Put("/admin/threat-feeds/{id}", d.Admin.UpdateThreatFeed)
				r.Post("/admin/threat-feeds/{id}/refresh", d.Admin.RefreshThreatFeed)
				r.Get("/admin/enrollment-tokens", d.Admin.ListEnrollmentTokens)
				r.Post("/admin/enrollment-tokens", d.Admin.CreateEnrollmentToken)
			})
		})
	})

	return r
}

// NewEdgeMTLSRouter builds the handler for the dedicated mTLS listener: the edge
// API authenticated by per-node client certificate (no bearer token).
func NewEdgeMTLSRouter(edge *edgeapi.API) http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(60 * time.Second))
	r.Route("/edge/v1", func(r chi.Router) {
		r.Use(edge.AuthnMTLS)
		r.Get("/config", edge.Config)
		r.Post("/telemetry", edge.Telemetry)
		r.Post("/events", edge.Events)
	})
	return r
}

// corsMiddleware permits the dashboard origin to call the API with credentials.
func corsMiddleware(cfg *appcfg.Config) func(http.Handler) http.Handler {
	allowed := map[string]bool{
		strings.TrimRight(cfg.DashboardURL, "/"):    true,
		strings.TrimRight(cfg.ControlPlaneURL, "/"): true,
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			if origin != "" && allowed[origin] {
				h := w.Header()
				h.Set("Access-Control-Allow-Origin", origin)
				h.Set("Access-Control-Allow-Credentials", "true")
				h.Set("Vary", "Origin")
				h.Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
				h.Set("Access-Control-Allow-Headers", "Content-Type, X-CSRF-Token")
			}
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
