-- +goose Up
-- Phase 3: weighted edge distribution. Each edge carries a weight; proxied
-- records are published as PowerDNS Lua `pickwhashed` records so traffic is
-- split across the edge pool proportionally (and stickily per client). Weight 0
-- drains an edge (kept healthy, served no traffic).

ALTER TABLE edges
    ADD COLUMN weight INTEGER NOT NULL DEFAULT 100 CHECK (weight BETWEEN 0 AND 1000);

-- +goose Down
ALTER TABLE edges DROP COLUMN IF EXISTS weight;
