// Package store owns the Postgres pool, the Redis client, and all data access.
package store

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/redis/go-redis/v9"

	"github.com/aegis/control-plane/migrations"
)

// Store bundles the persistent stores used by the control plane.
type Store struct {
	Pool  *pgxpool.Pool
	Redis *redis.Client
}

// New connects to Postgres and Redis and verifies both are reachable.
func New(ctx context.Context, databaseURL, redisURL string) (*Store, error) {
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return nil, fmt.Errorf("postgres connect: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("postgres ping: %w", err)
	}

	ropt, err := redis.ParseURL(redisURL)
	if err != nil {
		pool.Close()
		return nil, fmt.Errorf("redis url: %w", err)
	}
	rdb := redis.NewClient(ropt)
	if err := rdb.Ping(ctx).Err(); err != nil {
		pool.Close()
		_ = rdb.Close()
		return nil, fmt.Errorf("redis ping: %w", err)
	}

	return &Store{Pool: pool, Redis: rdb}, nil
}

// Close releases all connections.
func (s *Store) Close() {
	if s.Pool != nil {
		s.Pool.Close()
	}
	if s.Redis != nil {
		_ = s.Redis.Close()
	}
}

// Migrate runs all pending goose migrations using a temporary database/sql
// connection (goose requires *sql.DB; the app otherwise uses pgxpool).
func Migrate(databaseURL string) error {
	cfg, err := pgx.ParseConfig(databaseURL)
	if err != nil {
		return fmt.Errorf("parse database url: %w", err)
	}
	db := stdlib.OpenDB(*cfg)
	defer db.Close()

	goose.SetBaseFS(migrations.FS)
	if err := goose.SetDialect("postgres"); err != nil {
		return err
	}
	return goose.Up(db, ".")
}
