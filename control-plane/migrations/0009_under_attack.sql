-- +goose Up
-- Per-domain "Under Attack Mode": challenge every visitor that has not already
-- cleared the proof-of-work/CAPTCHA challenge, instead of only the traffic the
-- bot scorer flags. Equivalent to Cloudflare's "I'm under attack" toggle.
ALTER TABLE security_policies ADD COLUMN under_attack BOOLEAN NOT NULL DEFAULT FALSE;

-- +goose Down
ALTER TABLE security_policies DROP COLUMN IF EXISTS under_attack;
