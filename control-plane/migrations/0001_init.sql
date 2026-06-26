-- +goose Up
-- Aegis control-plane schema. gen_random_uuid() is built into Postgres 13+.

CREATE TABLE accounts (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name       TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE users (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id     UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    email          TEXT NOT NULL,
    password_hash  TEXT NOT NULL,
    role           TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('user','admin','superadmin')),
    status         TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','suspended')),
    email_verified BOOLEAN NOT NULL DEFAULT FALSE,
    totp_secret    TEXT,
    totp_enabled   BOOLEAN NOT NULL DEFAULT FALSE,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_login_at  TIMESTAMPTZ
);
CREATE UNIQUE INDEX users_email_key ON users (lower(email));
CREATE INDEX users_account_idx ON users (account_id);

CREATE TABLE email_tokens (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL,
    purpose    TEXT NOT NULL DEFAULT 'verify_email',
    expires_at TIMESTAMPTZ NOT NULL,
    used_at    TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX email_tokens_user_idx ON email_tokens (user_id);

CREATE TABLE domains (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id         UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    name               TEXT NOT NULL UNIQUE,
    status             TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','active','disabled')),
    paused             BOOLEAN NOT NULL DEFAULT FALSE,
    verification_token TEXT NOT NULL,
    verified_at        TIMESTAMPTZ,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX domains_account_idx ON domains (account_id);

CREATE TABLE dns_records (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    domain_id  UUID NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    type       TEXT NOT NULL CHECK (type IN ('A','AAAA','CNAME','TXT','MX','NS','CAA','SRV')),
    name       TEXT NOT NULL,
    content    TEXT NOT NULL,
    ttl        INTEGER NOT NULL DEFAULT 300,
    priority   INTEGER,
    proxied    BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX dns_records_domain_idx ON dns_records (domain_id);

CREATE TABLE security_policies (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    domain_id          UUID NOT NULL UNIQUE REFERENCES domains(id) ON DELETE CASCADE,
    https_redirect     BOOLEAN NOT NULL DEFAULT TRUE,
    min_tls            TEXT NOT NULL DEFAULT '1.2',
    waf_enabled        BOOLEAN NOT NULL DEFAULT TRUE,
    waf_paranoia       INTEGER NOT NULL DEFAULT 1 CHECK (waf_paranoia BETWEEN 1 AND 4),
    waf_mode           TEXT NOT NULL DEFAULT 'block' CHECK (waf_mode IN ('block','detect')),
    rate_limit_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    rate_limit_rpm     INTEGER NOT NULL DEFAULT 600,
    rate_limit_burst   INTEGER NOT NULL DEFAULT 60,
    cache_enabled      BOOLEAN NOT NULL DEFAULT FALSE,
    cache_ttl          INTEGER NOT NULL DEFAULT 60,
    bot_protection     TEXT NOT NULL DEFAULT 'medium' CHECK (bot_protection IN ('off','low','medium','high')),
    challenge_enabled  BOOLEAN NOT NULL DEFAULT TRUE,
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE edges (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name          TEXT NOT NULL UNIQUE,
    public_ip     TEXT NOT NULL,
    region        TEXT NOT NULL DEFAULT 'default',
    status        TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','healthy','unhealthy','draining')),
    agent_version TEXT,
    last_seen_at  TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE enrollment_tokens (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    token_hash TEXT NOT NULL,
    note       TEXT,
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at    TIMESTAMPTZ,
    edge_id    UUID REFERENCES edges(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE blocklists (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scope      TEXT NOT NULL DEFAULT 'global' CHECK (scope IN ('global','domain')),
    domain_id  UUID REFERENCES domains(id) ON DELETE CASCADE,
    kind       TEXT NOT NULL CHECK (kind IN ('ip','cidr','asn','ja4','country')),
    value      TEXT NOT NULL,
    action     TEXT NOT NULL DEFAULT 'block' CHECK (action IN ('block','challenge')),
    note       TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX blocklists_scope_idx ON blocklists (scope, domain_id);

CREATE TABLE config_bundles (
    version    BIGSERIAL PRIMARY KEY,
    caddyfile  TEXT NOT NULL,
    checksum   TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE edge_metrics (
    id           BIGSERIAL PRIMARY KEY,
    edge_id      UUID REFERENCES edges(id) ON DELETE CASCADE,
    domain_id    UUID REFERENCES domains(id) ON DELETE SET NULL,
    ts           TIMESTAMPTZ NOT NULL DEFAULT now(),
    requests     BIGINT NOT NULL DEFAULT 0,
    blocked_waf  BIGINT NOT NULL DEFAULT 0,
    blocked_rate BIGINT NOT NULL DEFAULT 0,
    challenged   BIGINT NOT NULL DEFAULT 0,
    cache_hits   BIGINT NOT NULL DEFAULT 0,
    cache_miss   BIGINT NOT NULL DEFAULT 0,
    bytes        BIGINT NOT NULL DEFAULT 0
);
CREATE INDEX edge_metrics_ts_idx ON edge_metrics (ts);
CREATE INDEX edge_metrics_domain_idx ON edge_metrics (domain_id);

CREATE TABLE audit_log (
    id            BIGSERIAL PRIMARY KEY,
    account_id    UUID,
    actor_user_id UUID,
    action        TEXT NOT NULL,
    target        TEXT,
    metadata      JSONB,
    ip            TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX audit_log_account_idx ON audit_log (account_id);

-- +goose Down
DROP TABLE IF EXISTS audit_log;
DROP TABLE IF EXISTS edge_metrics;
DROP TABLE IF EXISTS config_bundles;
DROP TABLE IF EXISTS blocklists;
DROP TABLE IF EXISTS enrollment_tokens;
DROP TABLE IF EXISTS edges;
DROP TABLE IF EXISTS security_policies;
DROP TABLE IF EXISTS dns_records;
DROP TABLE IF EXISTS domains;
DROP TABLE IF EXISTS email_tokens;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS accounts;
