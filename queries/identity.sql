-- Identity core queries: users and sessions (ADR-005, TASKS 1.2 D3).
-- Both tables are global (no organization_id).

-- name: CreateUser :one
INSERT INTO users (id, email, name, password_hash)
VALUES ($1, lower(btrim(sqlc.arg(email)::text)), btrim(sqlc.arg(name)::text), $2)
RETURNING id, email, name, password_hash, email_verified_at, mfa_enabled, mfa_secret_encrypted, status, created_at, updated_at;

-- name: GetUserByEmail :one
SELECT id, email, name, password_hash, email_verified_at, mfa_enabled, mfa_secret_encrypted, status, created_at, updated_at
FROM users
WHERE email = lower(btrim(sqlc.arg(email)::text));

-- name: GetUserByID :one
SELECT id, email, name, password_hash, email_verified_at, mfa_enabled, mfa_secret_encrypted, status, created_at, updated_at
FROM users
WHERE id = $1;

-- name: CreateSession :one
INSERT INTO sessions (
    id,
    user_id,
    token_hash,
    csrf_token_hash,
    last_auth_at,
    expires_at,
    absolute_expires_at,
    ip_prefix,
    user_agent
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
RETURNING id, user_id, token_hash, csrf_token_hash, last_auth_at, expires_at, absolute_expires_at, revoked_at, ip_prefix, user_agent, created_at;

-- name: GetActiveSessionByTokenHash :one
SELECT id, user_id, token_hash, csrf_token_hash, last_auth_at, expires_at, absolute_expires_at, revoked_at, ip_prefix, user_agent, created_at
FROM sessions
WHERE token_hash = $1
  AND revoked_at IS NULL
  AND expires_at > sqlc.arg(now)::timestamptz
  AND absolute_expires_at > sqlc.arg(now)::timestamptz;

-- name: RevokeSession :execrows
UPDATE sessions
SET revoked_at = sqlc.arg(revoked_at)::timestamptz
WHERE id = $1
  AND revoked_at IS NULL;

-- name: RevokeAllUserSessions :execrows
UPDATE sessions
SET revoked_at = sqlc.arg(revoked_at)::timestamptz
WHERE user_id = $1
  AND revoked_at IS NULL;
