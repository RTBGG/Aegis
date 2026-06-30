-- +goose Up
-- Phase 3: per-node mTLS. The control plane runs a small CA whose cert+key are
-- persisted here (single row, name='edge-ca') so it survives restarts and is
-- shared by HA replicas. Edge client certs are signed from it at enrollment.

CREATE TABLE pki (
    name       TEXT PRIMARY KEY,
    cert_pem   TEXT NOT NULL,
    key_pem    TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- +goose Down
DROP TABLE IF EXISTS pki;
