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
