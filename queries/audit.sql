-- Tenant-scoped append-only audit log queries (ADR-008, README §7.10, §9.2).
-- Every query MUST run inside database.WithTenantTx(ctx, pool, tenantID, ...).

-- name: InsertTenantAuditLog :exec
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
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12);

-- name: ListTenantAuditLogsFirstPage :many
SELECT id, organization_id, actor_type, actor_id, action, resource_type, resource_id, result, ip_prefix, user_agent, request_id, changes, created_at
FROM audit_logs
WHERE organization_id = $1
ORDER BY created_at DESC, id DESC
LIMIT sqlc.arg(page_limit);

-- name: ListTenantAuditLogsAfterCursor :many
SELECT id, organization_id, actor_type, actor_id, action, resource_type, resource_id, result, ip_prefix, user_agent, request_id, changes, created_at
FROM audit_logs
WHERE organization_id = $1
  AND (created_at, id) < (sqlc.arg(cursor_created_at)::timestamptz, sqlc.arg(cursor_id)::uuid)
ORDER BY created_at DESC, id DESC
LIMIT sqlc.arg(page_limit);
