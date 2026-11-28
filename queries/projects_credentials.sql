-- Tenant-scoped projects, environments, and API credentials queries (TASKS 1.3, ADR-005, ADR-008).
-- Every query MUST execute inside database.WithTenantTx(ctx, pool, tenantID, ...).

-- name: CreateProject :one
INSERT INTO projects (id, organization_id, public_id, name, slug, platform)
VALUES ($1, $2, $3, btrim($4), lower(btrim($5)), lower(btrim($6)))
RETURNING id, organization_id, public_id, name, slug, platform, status, deleted_at, created_at, updated_at, allow_request_body, allow_user_ip, inbound_filters;

-- name: GetProjectByID :one
SELECT id, organization_id, public_id, name, slug, platform, status, deleted_at, created_at, updated_at, allow_request_body, allow_user_ip, inbound_filters
FROM projects
WHERE organization_id = $1
  AND id = $2
  AND status <> 'deleted';

-- name: ListProjects :many
SELECT id, organization_id, public_id, name, slug, platform, status, deleted_at, created_at, updated_at, allow_request_body, allow_user_ip, inbound_filters
FROM projects
WHERE organization_id = $1
  AND status = 'active'
ORDER BY created_at DESC, id DESC
LIMIT sqlc.arg(page_limit);

-- name: UpdateProject :one
UPDATE projects
SET name = btrim($3),
    platform = lower(btrim($4)),
    updated_at = sqlc.arg(updated_at)::timestamptz
WHERE organization_id = $1
  AND id = $2
  AND status = 'active'
RETURNING id, organization_id, public_id, name, slug, platform, status, deleted_at, created_at, updated_at, allow_request_body, allow_user_ip, inbound_filters;

-- name: SoftDeleteProject :one
UPDATE projects
SET status = 'deleting',
    deleted_at = sqlc.arg(now)::timestamptz,
    updated_at = sqlc.arg(now)::timestamptz
WHERE organization_id = $1
  AND id = $2
  AND status = 'active'
RETURNING id, organization_id, public_id, name, slug, platform, status, deleted_at, created_at, updated_at, allow_request_body, allow_user_ip, inbound_filters;

-- name: CreateEnvironment :one
INSERT INTO environments (id, organization_id, project_id, name, is_protected)
VALUES ($1, $2, $3, lower(btrim($4)), $5)
RETURNING id, organization_id, project_id, name, is_protected, created_at, updated_at;

-- name: ListProjectEnvironments :many
SELECT id, organization_id, project_id, name, is_protected, created_at, updated_at
FROM environments
WHERE organization_id = $1
  AND project_id = $2
ORDER BY name ASC;

-- name: GetEnvironmentByID :one
SELECT id, organization_id, project_id, name, is_protected, created_at, updated_at
FROM environments
WHERE organization_id = $1
  AND id = $2;

-- name: DeleteEnvironment :execrows
DELETE FROM environments
WHERE organization_id = $1
  AND id = $2
  AND is_protected = false;

-- name: CreateAPICredential :one
INSERT INTO api_credentials (
    id, organization_id, project_id, environment_id,
    kind, name, prefix, secret_hash, public_key,
    scopes, allowed_origins, expires_at, created_by
)
VALUES ($1, $2, $3, $4, $5, btrim($6), $7, $8, $9, $10, $11, $12, $13)
RETURNING id, organization_id, project_id, environment_id, kind, name, prefix, public_key, scopes, allowed_origins, expires_at, last_used_at, revoked_at, created_by, created_at;

-- name: ListProjectCredentials :many
SELECT id, organization_id, project_id, environment_id, kind, name, prefix, public_key, scopes, allowed_origins, expires_at, last_used_at, revoked_at, created_by, created_at
FROM api_credentials
WHERE organization_id = $1
  AND project_id = $2
ORDER BY created_at DESC, id DESC;

-- name: RevokeAPICredential :one
UPDATE api_credentials
SET revoked_at = sqlc.arg(revoked_at)::timestamptz
WHERE organization_id = $1
  AND id = $2
  AND revoked_at IS NULL
RETURNING id, kind, prefix, public_key;

-- name: RevokeAllProjectCredentials :many
UPDATE api_credentials
SET revoked_at = sqlc.arg(revoked_at)::timestamptz
WHERE organization_id = $1
  AND project_id = $2
  AND revoked_at IS NULL
RETURNING id, kind, prefix, public_key;

-- name: TouchAPICredentialLastUsed :exec
UPDATE api_credentials
SET last_used_at = sqlc.arg(last_used_at)::timestamptz
WHERE organization_id = $1
  AND id = $2;

-- name: GetActiveAPICredentialByID :one
SELECT project_id, environment_id, kind, name, prefix, public_key, scopes, allowed_origins
FROM api_credentials
WHERE organization_id = $1
  AND id = $2
  AND revoked_at IS NULL;

-- name: SetAPICredentialOverlapExpiry :exec
UPDATE api_credentials
SET expires_at = LEAST(COALESCE(expires_at, sqlc.arg(expires_at)::timestamptz), sqlc.arg(expires_at)::timestamptz)
WHERE organization_id = $1
  AND id = $2
  AND revoked_at IS NULL;

-- name: LookupDSNKey :one
SELECT
    (r).credential_id::uuid         AS credential_id,
    (r).organization_id::uuid       AS organization_id,
    (r).project_id::uuid            AS project_id,
    (r).project_public_id::bigint   AS project_public_id,
    (r).environment_id::uuid        AS environment_id,
    (r).allowed_origins::text[]     AS allowed_origins,
    (r).expires_at::timestamptz     AS expires_at,
    (r).revoked_at::timestamptz     AS revoked_at,
    (r).allow_request_body::boolean AS allow_request_body,
    (r).allow_user_ip::boolean      AS allow_user_ip,
    (r).inbound_filters::jsonb      AS inbound_filters
FROM lookup_dsn_key(sqlc.arg(public_key)::text) AS r;
