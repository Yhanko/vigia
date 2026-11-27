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
SELECT
    s.id,
    s.user_id,
    s.token_hash,
    s.csrf_token_hash,
    s.last_auth_at,
    s.expires_at,
    s.absolute_expires_at,
    s.revoked_at,
    s.ip_prefix,
    s.user_agent,
    s.created_at,
    u.email       AS user_email,
    u.name        AS user_name,
    u.mfa_enabled AS user_mfa_enabled,
    u.status      AS user_status
FROM sessions s
JOIN users u ON u.id = s.user_id AND u.status = 'active'
WHERE s.token_hash = $1
  AND s.revoked_at IS NULL
  AND s.expires_at > sqlc.arg(now)::timestamptz
  AND s.absolute_expires_at > sqlc.arg(now)::timestamptz;

-- name: UpdateUserPasswordHash :exec
UPDATE users
SET password_hash = $2,
    updated_at = sqlc.arg(updated_at)::timestamptz
WHERE id = $1;

-- name: UpdateUserStatus :exec
UPDATE users
SET status = $2,
    updated_at = sqlc.arg(updated_at)::timestamptz
WHERE id = $1;

-- name: InsertGlobalAuditLog :exec
INSERT INTO audit_logs (
    id,
    organization_id,
    actor_type,
    actor_id,
    action,
    resource_type,
    resource_id,
    result,
    ip_prefix,
    user_agent,
    request_id,
    changes
)
VALUES (
    $1,
    NULL,
    $2,
    $3,
    $4,
    $5,
    $6,
    $7,
    $8,
    $9,
    $10,
    $11
);

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
