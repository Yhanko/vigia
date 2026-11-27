-- Identity core queries: users and sessions (ADR-005, TASKS 1.2 D3).
-- Both tables are global (no organization_id).

-- name: CreateUser :one
INSERT INTO users (id, email, name, password_hash)
VALUES ($1, lower(btrim(sqlc.arg(email)::text)), btrim(sqlc.arg(name)::text), $2)
RETURNING id, email, name, password_hash, email_verified_at, mfa_enabled, mfa_secret_encrypted, status, created_at, updated_at, mfa_last_used_step;

-- name: GetUserByEmail :one
SELECT id, email, name, password_hash, email_verified_at, mfa_enabled, mfa_secret_encrypted, status, created_at, updated_at, mfa_last_used_step
FROM users
WHERE email = lower(btrim(sqlc.arg(email)::text));

-- name: GetUserByID :one
SELECT id, email, name, password_hash, email_verified_at, mfa_enabled, mfa_secret_encrypted, status, created_at, updated_at, mfa_last_used_step
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
    user_agent,
    mfa_pending
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
RETURNING id, user_id, token_hash, csrf_token_hash, last_auth_at, expires_at, absolute_expires_at, revoked_at, ip_prefix, user_agent, mfa_pending, mfa_failed_attempts, created_at;

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
    u.email                AS user_email,
    u.name                 AS user_name,
    u.mfa_enabled          AS user_mfa_enabled,
    u.mfa_secret_encrypted AS user_mfa_secret_encrypted,
    u.mfa_last_used_step   AS user_mfa_last_used_step,
    u.status               AS user_status
FROM sessions s
JOIN users u ON u.id = s.user_id AND u.status = 'active'
WHERE s.token_hash = $1
  AND s.mfa_pending = false
  AND s.revoked_at IS NULL
  AND s.expires_at > sqlc.arg(now)::timestamptz
  AND s.absolute_expires_at > sqlc.arg(now)::timestamptz;

-- name: GetPendingMFASessionByTokenHash :one
SELECT
    s.id,
    s.user_id,
    s.token_hash,
    s.csrf_token_hash,
    s.last_auth_at,
    s.expires_at,
    s.absolute_expires_at,
    s.mfa_failed_attempts,
    u.email                AS user_email,
    u.name                 AS user_name,
    u.mfa_enabled          AS user_mfa_enabled,
    u.mfa_secret_encrypted AS user_mfa_secret_encrypted,
    u.mfa_last_used_step   AS user_mfa_last_used_step
FROM sessions s
JOIN users u ON u.id = s.user_id AND u.status = 'active'
WHERE s.token_hash = $1
  AND s.mfa_pending = true
  AND s.revoked_at IS NULL
  AND s.expires_at > sqlc.arg(now)::timestamptz
  AND s.absolute_expires_at > sqlc.arg(now)::timestamptz;

-- name: IncrementSessionMFAFailedAttempts :one
UPDATE sessions
SET mfa_failed_attempts = mfa_failed_attempts + 1,
    revoked_at = CASE WHEN mfa_failed_attempts + 1 >= 5 THEN sqlc.arg(now)::timestamptz ELSE revoked_at END
WHERE id = $1
  AND revoked_at IS NULL
RETURNING mfa_failed_attempts, revoked_at;

-- name: SetUserPendingMFASecret :exec
UPDATE users
SET mfa_secret_encrypted = $2,
    updated_at = sqlc.arg(updated_at)::timestamptz
WHERE id = $1
  AND mfa_enabled = false;

-- name: EnableUserMFA :execrows
UPDATE users
SET mfa_enabled = true,
    mfa_last_used_step = $2,
    updated_at = sqlc.arg(updated_at)::timestamptz
WHERE id = $1
  AND mfa_enabled = false
  AND (mfa_last_used_step IS NULL OR mfa_last_used_step < $2);

-- name: UpdateUserMFALastUsedStep :execrows
UPDATE users
SET mfa_last_used_step = $2,
    updated_at = sqlc.arg(updated_at)::timestamptz
WHERE id = $1
  AND (mfa_last_used_step IS NULL OR mfa_last_used_step < $2);

-- name: RevokeOtherUserSessions :execrows
UPDATE sessions
SET revoked_at = sqlc.arg(revoked_at)::timestamptz
WHERE user_id = $1
  AND id <> sqlc.arg(keep_session_id)
  AND revoked_at IS NULL;

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

-- name: MarkUserEmailVerified :exec
UPDATE users
SET email_verified_at = COALESCE(email_verified_at, sqlc.arg(verified_at)::timestamptz),
    updated_at = sqlc.arg(verified_at)::timestamptz
WHERE id = $1;

-- name: CreateUserToken :exec
INSERT INTO user_tokens (id, user_id, kind, token_hash, expires_at)
VALUES ($1, $2, $3, $4, $5);

-- name: InvalidateUserTokensByKind :exec
UPDATE user_tokens
SET used_at = sqlc.arg(used_at)::timestamptz
WHERE user_id = $1
  AND kind = $2
  AND used_at IS NULL;

-- name: ConsumeUserToken :one
UPDATE user_tokens
SET used_at = sqlc.arg(now)::timestamptz
WHERE token_hash = $1
  AND kind = $2
  AND used_at IS NULL
  AND (expires_at IS NULL OR expires_at > sqlc.arg(now)::timestamptz)
RETURNING id, user_id, kind;

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
