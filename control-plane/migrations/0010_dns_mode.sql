-- +goose Up
-- Domains can be connected to Aegis in two ways:
--   'ns'    – delegate the zone's nameservers to Aegis (PowerDNS is authoritative)
--   'cname' – keep DNS at the customer's provider and point CNAME/ALIAS/ANAME
--             records at an Aegis target hostname
-- Existing rows default to 'ns', preserving current behaviour.
ALTER TABLE domains ADD COLUMN dns_mode TEXT NOT NULL DEFAULT 'ns'
    CHECK (dns_mode IN ('ns','cname'));

-- +goose Down
ALTER TABLE domains DROP COLUMN IF EXISTS dns_mode;
