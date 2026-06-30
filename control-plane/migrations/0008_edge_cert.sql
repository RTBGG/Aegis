-- +goose Up
-- Phase 3: per-node cert rotation + revocation. Track each edge's current client
-- certificate (serial + expiry) so the mTLS listener can (a) reject superseded
-- certs after a rotation and (b) reject explicitly revoked edges.

ALTER TABLE edges
    ADD COLUMN cert_serial     TEXT,
    ADD COLUMN cert_expires_at TIMESTAMPTZ,
    ADD COLUMN revoked_at      TIMESTAMPTZ;

-- +goose Down
ALTER TABLE edges
    DROP COLUMN IF EXISTS revoked_at,
    DROP COLUMN IF EXISTS cert_expires_at,
    DROP COLUMN IF EXISTS cert_serial;
