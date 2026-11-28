-- name: GetOrganizationPlan :one
SELECT p.id, p.name, p.max_events_per_month, p.max_events_per_day,
       p.rate_limit_org_per_min, p.rate_limit_key_per_min,
       p.max_whatsapp_per_month, p.max_projects, p.max_members,
       p.max_alert_rules_per_project, p.max_notification_targets,
       p.max_artifact_bytes, p.event_retention_days
FROM plans p
JOIN organizations o ON o.plan = p.id
WHERE o.id = $1;

-- name: UpsertUsageAggregate :exec
INSERT INTO usage_aggregates (
    organization_id, resource, period_kind, period_start, used, updated_at
) VALUES ($1, $2, $3, $4, $5, $6)
ON CONFLICT (organization_id, resource, period_kind, period_start)
DO UPDATE SET
    used = GREATEST(usage_aggregates.used, EXCLUDED.used),
    updated_at = EXCLUDED.updated_at;

-- name: GetUsageAggregate :one
SELECT used
FROM usage_aggregates
WHERE organization_id = $1
  AND resource = $2
  AND period_kind = $3
  AND period_start = $4;

-- name: RecordQuotaNotification :one
INSERT INTO quota_notifications (
    organization_id, resource, period_start, threshold_pct, notified_at
) VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (organization_id, resource, period_start, threshold_pct) DO NOTHING
RETURNING threshold_pct;

-- name: CountActiveProjectsByOrg :one
SELECT count(*)::int AS active_projects
FROM projects
WHERE organization_id = $1 AND status = 'active';

-- name: CountMembersAndPendingInvitesByOrg :one
SELECT (
    (SELECT count(*) FROM memberships m WHERE m.organization_id = $1 AND m.status = 'active') +
    (SELECT count(*) FROM invitations i WHERE i.organization_id = $1 AND i.accepted_at IS NULL AND i.expires_at > $2)
)::int AS total_members;

-- name: ListOrgOwnerAndAdminEmails :many
SELECT u.email
FROM memberships m
JOIN users u ON u.id = m.user_id
WHERE m.organization_id = $1
  AND m.status = 'active'
  AND m.role IN ('owner', 'admin')
  AND u.status = 'active'
ORDER BY u.email ASC;

-- name: DeleteOldUsageAggregates :execrows
DELETE FROM usage_aggregates
WHERE ctid IN (
    SELECT ua.ctid FROM usage_aggregates ua
    WHERE ua.period_start < $1
    LIMIT $2
);
