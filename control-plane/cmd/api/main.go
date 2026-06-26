// Command api is the Aegis control-plane HTTP server.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/aegis/control-plane/internal/admin"
	"github.com/aegis/control-plane/internal/analytics"
	"github.com/aegis/control-plane/internal/appcfg"
	"github.com/aegis/control-plane/internal/auth"
	"github.com/aegis/control-plane/internal/config"
	"github.com/aegis/control-plane/internal/dns"
	"github.com/aegis/control-plane/internal/domains"
	"github.com/aegis/control-plane/internal/edgeapi"
	"github.com/aegis/control-plane/internal/httpapi"
	"github.com/aegis/control-plane/internal/mailer"
	"github.com/aegis/control-plane/internal/security"
	"github.com/aegis/control-plane/internal/store"
)

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})))

	cfg, err := appcfg.Load()
	if err != nil {
		slog.Error("config", "err", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Migrations are idempotent; run on boot so the all-in-one stack self-sets-up.
	if err := waitAndMigrate(cfg.DatabaseURL); err != nil {
		slog.Error("migrate", "err", err)
		os.Exit(1)
	}

	st, err := store.New(ctx, cfg.DatabaseURL, cfg.RedisURL)
	if err != nil {
		slog.Error("store", "err", err)
		os.Exit(1)
	}
	defer st.Close()

	ml := mailer.New(cfg.Mailer, cfg.SMTPAddr, "no-reply@"+cfg.Brand)
	pdns := dns.NewClient(cfg.PDNSAPIURL, cfg.PDNSAPIKey)
	renderer := config.New(st, cfg)

	if err := bootstrap(ctx, st, cfg); err != nil {
		slog.Error("bootstrap", "err", err)
		os.Exit(1)
	}
	if _, changed, err := renderer.Rebuild(ctx); err != nil {
		slog.Warn("initial config render failed", "err", err)
	} else {
		slog.Info("initial config rendered", "changed", changed)
	}

	deps := httpapi.Deps{
		Cfg:       cfg,
		Auth:      auth.New(st, cfg, ml),
		Domains:   domains.New(st, pdns, cfg, renderer),
		Security:  security.New(st, renderer),
		Analytics: analytics.New(st),
		Admin:     admin.New(st, cfg, renderer),
		Edge:      edgeapi.New(st, cfg),
	}
	srv := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           httpapi.NewRouter(deps),
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		slog.Info("control-plane listening", "addr", srv.Addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("server", "err", err)
			os.Exit(1)
		}
	}()

	<-ctx.Done()
	slog.Info("shutting down")
	shutCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutCtx)
}

// waitAndMigrate retries migrations briefly so the API can start before
// Postgres is fully ready (compose ordering).
func waitAndMigrate(dbURL string) error {
	var lastErr error
	for i := 0; i < 30; i++ {
		if err := store.Migrate(dbURL); err != nil {
			lastErr = err
			slog.Info("waiting for postgres…", "attempt", i+1)
			time.Sleep(2 * time.Second)
			continue
		}
		return nil
	}
	return lastErr
}

// bootstrap seeds the superadmin and the local edge on first boot.
func bootstrap(ctx context.Context, st *store.Store, cfg *appcfg.Config) error {
	if _, err := st.UpsertEdge(ctx, "local-edge", cfg.EdgePublicIP, "default"); err != nil {
		return err
	}
	n, err := st.CountUsers(ctx)
	if err != nil {
		return err
	}
	if n > 0 || cfg.BootstrapAdminPassword == "" {
		return nil
	}
	hash, err := auth.HashPassword(cfg.BootstrapAdminPassword)
	if err != nil {
		return err
	}
	u, err := st.CreateAccountWithUser(ctx, cfg.BootstrapAdminEmail, cfg.BootstrapAdminEmail, hash, "superadmin")
	if err != nil {
		return err
	}
	if err := st.MarkEmailVerified(ctx, u.ID); err != nil {
		return err
	}
	slog.Info("seeded bootstrap superadmin", "email", cfg.BootstrapAdminEmail)
	return nil
}
