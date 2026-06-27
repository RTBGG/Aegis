-- +goose Up
-- Phase 3: multi-node edge enrollment. Each enrolled edge gets a durable,
-- per-node bearer token (stored hashed) issued in exchange for a single-use
-- enrollment token. (Per-node mTLS is the later hardening step.)

ALTER TABLE edges
    ADD COLUMN agent_token_hash TEXT,
    ADD COLUMN enrolled_at      TIMESTAMPTZ;

CREATE INDEX edges_agent_token_idx ON edges (agent_token_hash);

-- +goose Down
DROP INDEX IF EXISTS edges_agent_token_idx;
ALTER TABLE edges
    DROP COLUMN IF EXISTS enrolled_at,
    DROP COLUMN IF EXISTS agent_token_hash;
