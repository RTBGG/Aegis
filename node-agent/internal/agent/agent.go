package agent

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/redis/go-redis/v9"
)

const eventsKey = "aegis:events"

// Run starts Caddy and the config/telemetry loops, blocking until ctx is
// cancelled or Caddy exits.
func Run(ctx context.Context) error {
	cfg := LoadConfig()
	if cfg.AgentToken == "" {
		return errors.New("AGENT_TOKEN is required")
	}
	log := slog.Default()

	var version atomic.Int64

	// Seed initial config so Caddy boots with the full customer set.
	if b, ok := fetchInitial(ctx, cfg, log); ok {
		_ = cfg.writeDynamic(b.Caddyfile)
		version.Store(b.Version)
	} else {
		_ = cfg.writeDynamic("")
	}

	cmd, err := cfg.startCaddy(ctx)
	if err != nil {
		return err
	}
	log.Info("caddy started", "config", cfg.Caddyfile)
	caddyDone := make(chan error, 1)
	go func() { caddyDone <- cmd.Wait() }()

	go cfg.configLoop(ctx, &version, log)
	go cfg.telemetryLoop(ctx, &version, log)
	go cfg.rotateLoop(ctx, log)

	select {
	case <-ctx.Done():
		log.Info("shutting down agent")
		return nil
	case err := <-caddyDone:
		return errors.New("caddy exited: " + errString(err))
	}
}

func fetchInitial(ctx context.Context, cfg Config, log *slog.Logger) (*bundle, bool) {
	for i := 0; i < 10; i++ {
		ctxTry, cancel := context.WithTimeout(ctx, 5*time.Second)
		b, ok, err := cfg.fetchConfig(ctxTry, 0)
		cancel()
		if err == nil && ok {
			return b, true
		}
		if err == nil && !ok {
			return nil, false // up to date / empty
		}
		log.Info("waiting for control plane…", "attempt", i+1, "err", errString(err))
		select {
		case <-ctx.Done():
			return nil, false
		case <-time.After(3 * time.Second):
		}
	}
	return nil, false
}

func (c Config) configLoop(ctx context.Context, version *atomic.Int64, log *slog.Logger) {
	for ctx.Err() == nil {
		b, changed, err := c.fetchConfig(ctx, version.Load())
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Warn("config fetch failed", "err", errString(err))
			time.Sleep(3 * time.Second)
			continue
		}
		if !changed {
			continue // long-poll returned no change; re-poll
		}
		if err := c.writeDynamic(b.Caddyfile); err != nil {
			log.Error("write config failed", "err", errString(err))
			continue
		}
		if err := c.reloadCaddy(); err != nil {
			log.Error("reload failed", "err", errString(err))
			continue
		}
		version.Store(b.Version)
		log.Info("applied config", "version", b.Version)
	}
}

var counterKeys = []string{"requests", "challenged", "blocked_bot", "blocked_rate", "cache_hits", "cache_miss", "bytes"}

func (c Config) telemetryLoop(ctx context.Context, version *atomic.Int64, log *slog.Logger) {
	rdb := redis.NewClient(&redis.Options{Addr: c.RedisAddr})
	defer rdb.Close()

	ticker := time.NewTicker(c.TelemetryInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		counts := drainCounters(ctx, rdb)
		payload := telemetryPayload{
			EdgeName:      c.EdgeName,
			PublicIP:      c.PublicIP,
			AgentVersion:  Version,
			Status:        "healthy",
			ConfigVersion: version.Load(),
			Metrics: []metricLine{{
				Requests:    counts["requests"],
				Challenged:  counts["challenged"],
				BlockedRate: counts["blocked_bot"] + counts["blocked_rate"],
				CacheHits:   counts["cache_hits"],
				CacheMiss:   counts["cache_miss"],
				Bytes:       counts["bytes"],
			}},
		}
		if err := c.sendTelemetry(ctx, payload); err != nil && ctx.Err() == nil {
			log.Warn("telemetry failed", "err", errString(err))
		}
		if evs := drainEvents(ctx, rdb); len(evs) > 0 {
			if err := c.sendEvents(ctx, evs); err != nil && ctx.Err() == nil {
				log.Warn("events ship failed", "err", errString(err), "count", len(evs))
			}
		}
	}
}

// drainEvents atomically pops a batch of analytics events from Redis.
func drainEvents(ctx context.Context, rdb *redis.Client) []json.RawMessage {
	const max = 5000
	res, err := rdb.LPopCount(ctx, eventsKey, max).Result()
	if err != nil || len(res) == 0 {
		return nil
	}
	out := make([]json.RawMessage, 0, len(res))
	for _, s := range res {
		out = append(out, json.RawMessage(s))
	}
	return out
}

// drainCounters reads and resets the edge counters set by the Caddy modules.
func drainCounters(ctx context.Context, rdb *redis.Client) map[string]int64 {
	out := make(map[string]int64, len(counterKeys))
	for _, k := range counterKeys {
		v, err := rdb.GetDel(ctx, "aegis:m:"+k).Result()
		if err != nil {
			continue
		}
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			out[k] = n
		}
	}
	return out
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
