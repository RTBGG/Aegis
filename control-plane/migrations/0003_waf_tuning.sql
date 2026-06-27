-- +goose Up
-- Phase 2: per-route WAF tuning + custom SecRules import.

-- Operator-supplied SecLang rules appended to the domain's Coraza engine.
-- Validated against a directive allowlist before storage.
ALTER TABLE security_policies ADD COLUMN waf_custom_rules TEXT NOT NULL DEFAULT '';

-- Per-path WAF overrides: disable/relax the engine or drop specific CRS rules
-- for requests under a path prefix. Rendered as path-scoped SecRules.
CREATE TABLE waf_route_overrides (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    domain_id      UUID NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    path           TEXT NOT NULL,                                  -- matched with @beginsWith
    mode           TEXT NOT NULL DEFAULT 'inherit' CHECK (mode IN ('inherit','off','detect')),
    excluded_rules TEXT NOT NULL DEFAULT '',                       -- space-separated CRS rule IDs
    paranoia       INTEGER CHECK (paranoia IS NULL OR (paranoia BETWEEN 1 AND 4)),
    enabled        BOOLEAN NOT NULL DEFAULT TRUE,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX waf_route_overrides_domain_idx ON waf_route_overrides (domain_id);

-- +goose Down
DROP TABLE IF EXISTS waf_route_overrides;
ALTER TABLE security_policies DROP COLUMN IF EXISTS waf_custom_rules;
