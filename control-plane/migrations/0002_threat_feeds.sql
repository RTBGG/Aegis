-- +goose Up
-- Phase 2: threat-feed ingestion. Free IP reputation lists (Spamhaus DROP,
-- FireHOL Level 1) are fetched on a schedule and their CIDRs are enforced as a
-- global edge blocklist (hard 403), separate from operator-managed `blocklists`.

CREATE TABLE threat_feeds (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    slug             TEXT NOT NULL UNIQUE,
    name             TEXT NOT NULL,
    url              TEXT NOT NULL,
    format           TEXT NOT NULL DEFAULT 'netset' CHECK (format IN ('netset','drop')),
    action           TEXT NOT NULL DEFAULT 'block' CHECK (action IN ('block','challenge')),
    enabled          BOOLEAN NOT NULL DEFAULT TRUE,
    refresh_interval INTEGER NOT NULL DEFAULT 21600 CHECK (refresh_interval >= 300),
    last_synced_at   TIMESTAMPTZ,
    last_status      TEXT,
    last_error       TEXT,
    entry_count      INTEGER NOT NULL DEFAULT 0,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- One row per CIDR per feed. Replaced wholesale on each successful sync.
CREATE TABLE threat_feed_entries (
    feed_id UUID NOT NULL REFERENCES threat_feeds(id) ON DELETE CASCADE,
    cidr    TEXT NOT NULL,
    PRIMARY KEY (feed_id, cidr)
);
CREATE INDEX threat_feed_entries_feed_idx ON threat_feed_entries (feed_id);

-- Seed the two free providers from the plan. Enabled by default; gate the
-- background fetcher with THREATFEED_SYNC=off to avoid egress in air-gapped setups.
INSERT INTO threat_feeds (slug, name, url, format) VALUES
    ('spamhaus_drop',  'Spamhaus DROP',   'https://www.spamhaus.org/drop/drop.txt', 'drop'),
    ('firehol_level1', 'FireHOL Level 1', 'https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset', 'netset');

-- +goose Down
DROP TABLE IF EXISTS threat_feed_entries;
DROP TABLE IF EXISTS threat_feeds;
