-- +goose Up
-- Two-step MFA login pending sessions and TOTP anti-replay tracking
-- (docs/plans/1.2-identity.md §7.1, CTO #20).
ALTER TABLE sessions
    ADD COLUMN mfa_pending boolean NOT NULL DEFAULT false,
    ADD COLUMN mfa_failed_attempts smallint NOT NULL DEFAULT 0
        CHECK (mfa_failed_attempts >= 0);

ALTER TABLE users
    ADD COLUMN mfa_last_used_step bigint;

-- +goose Down
ALTER TABLE users
    DROP COLUMN IF EXISTS mfa_last_used_step;

ALTER TABLE sessions
    DROP COLUMN IF EXISTS mfa_failed_attempts,
    DROP COLUMN IF EXISTS mfa_pending;
