// Package metrics provides best-effort, fire-and-forget edge counters in Redis.
// The node-agent drains these (GETDEL) each interval and reports them as
// telemetry to the control plane.
package metrics

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

const Prefix = "aegis:m:"

// EventsKey is the Redis list the edge appends per-request analytics events to;
// the node-agent drains it and ships the batch to the control plane.
const EventsKey = "aegis:events"

// eventsCap bounds the events list so a stalled agent can't exhaust Redis.
const eventsCap = 100_000

var (
	once   sync.Once
	client *redis.Client
)

func get() *redis.Client {
	once.Do(func() {
		addr := os.Getenv("AEGIS_REDIS")
		if addr == "" {
			addr = "redis:6379"
		}
		client = redis.NewClient(&redis.Options{
			Addr:         addr,
			DialTimeout:  500 * time.Millisecond,
			ReadTimeout:  500 * time.Millisecond,
			WriteTimeout: 500 * time.Millisecond,
		})
	})
	return client
}

// RequestRate increments and returns the per-minute request count for an IP.
// Best-effort: returns 0 if Redis is unavailable (rate signal simply skipped).
func RequestRate(ip string) int {
	c := get()
	if c == nil {
		return 0
	}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	key := fmt.Sprintf("aegis:rate:%s:%d", ip, time.Now().Unix()/60)
	n, err := c.Incr(ctx, key).Result()
	if err != nil {
		return 0
	}
	c.Expire(ctx, key, 70*time.Second)
	return int(n)
}

// UnderAttackKey is the Redis flag the control plane sets to switch the edge's
// dashboard "under attack" challenge on/off live (no reload needed).
const UnderAttackKey = "aegis:under_attack"

// uaCacheTTL bounds how often the flag is actually read from Redis, so the
// per-request check costs at most one GET every couple of seconds.
const uaCacheTTL = 2 * time.Second

var (
	uaMu        sync.Mutex
	uaCached    bool
	uaCheckedAt time.Time
)

// UnderAttackActive reports whether dashboard "under attack" mode is enabled,
// caching the Redis flag briefly. On any Redis error it keeps the last known
// value, so a transient blip never silently drops protection mid-attack.
func UnderAttackActive() bool {
	uaMu.Lock()
	if time.Since(uaCheckedAt) < uaCacheTTL {
		v := uaCached
		uaMu.Unlock()
		return v
	}
	uaCheckedAt = time.Now() // claim the refresh so concurrent callers use cache
	last := uaCached
	uaMu.Unlock()

	v := last
	if c := get(); c != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		n, err := c.Exists(ctx, UnderAttackKey).Result()
		cancel()
		if err == nil {
			v = n > 0
		}
	}
	uaMu.Lock()
	uaCached = v
	uaMu.Unlock()
	return v
}

// BlackholePendingKey is the edge-local set of freshly auto-banned IPs. The
// node-agent drains it and reports the IPs to the control plane, which aggregates
// them into the authoritative blackhole list served to every edge's host-side nft
// sync agent (the edge runs in a container and can't touch the host firewall).
const BlackholePendingKey = "aegis:blackhole:pending"

// Blackhole queues an IP for host-level L3 dropping (fire-and-forget). Only the
// worst offenders (already auto-banned at L7) reach here.
func Blackhole(ip string) {
	c := get()
	if c == nil {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()
		_ = c.SAdd(ctx, BlackholePendingKey, ip).Err()
		// Bound the set so a stalled agent can't grow it unbounded.
		c.Expire(ctx, BlackholePendingKey, 10*time.Minute)
	}()
}

// challengeStrikeWindow is how long per-IP challenge strikes accumulate before
// the counter resets (giving a formerly-abusive IP another chance).
const challengeStrikeWindow = 2 * time.Minute

// ChallengeStrike increments and returns the count of challenges served to an IP
// without it ever solving one (the counter is cleared on success via
// ClearChallengeStrikes). Callers use it to auto-ban clients that repeatedly get
// challenged but never pass. Best-effort: returns 0 if Redis is unavailable.
func ChallengeStrike(ip string) int64 {
	c := get()
	if c == nil {
		return 0
	}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	key := "aegis:chal:" + ip
	n, err := c.Incr(ctx, key).Result()
	if err != nil {
		return 0
	}
	if n == 1 {
		c.Expire(ctx, key, challengeStrikeWindow)
	}
	return n
}

// ClearChallengeStrikes resets an IP's strike counter (called when it solves a
// challenge), so a shared/NAT IP is un-banned as soon as any client behind it passes.
func ClearChallengeStrikes(ip string) {
	c := get()
	if c == nil {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
		defer cancel()
		_ = c.Del(ctx, "aegis:chal:"+ip).Err()
	}()
}

// Incr increments a named counter without blocking the request path.
func Incr(name string) {
	c := get()
	if c == nil {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()
		_ = c.Incr(ctx, Prefix+name).Err()
	}()
}

// PushEvent appends a JSON analytics event to the events list (fire-and-forget),
// trimming the list to a bounded size.
func PushEvent(jsonLine string) {
	c := get()
	if c == nil {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()
		pipe := c.Pipeline()
		pipe.RPush(ctx, EventsKey, jsonLine)
		pipe.LTrim(ctx, EventsKey, -eventsCap, -1)
		_, _ = pipe.Exec(ctx)
	}()
}
