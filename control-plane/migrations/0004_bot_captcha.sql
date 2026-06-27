-- +goose Up
-- Phase 2: richer bot scoring + pluggable CAPTCHA challenge.

ALTER TABLE security_policies
    ADD COLUMN bot_allow_verified BOOLEAN NOT NULL DEFAULT TRUE,
    ADD COLUMN challenge_mode     TEXT NOT NULL DEFAULT 'pow' CHECK (challenge_mode IN ('pow','captcha')),
    ADD COLUMN captcha_provider   TEXT NOT NULL DEFAULT '' CHECK (captcha_provider IN ('','turnstile','hcaptcha','recaptcha')),
    ADD COLUMN captcha_sitekey    TEXT NOT NULL DEFAULT '',
    ADD COLUMN captcha_secret     TEXT NOT NULL DEFAULT '';

-- +goose Down
ALTER TABLE security_policies
    DROP COLUMN IF EXISTS captcha_secret,
    DROP COLUMN IF EXISTS captcha_sitekey,
    DROP COLUMN IF EXISTS captcha_provider,
    DROP COLUMN IF EXISTS challenge_mode,
    DROP COLUMN IF EXISTS bot_allow_verified;
