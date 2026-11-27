-- Tenant-scoped organization, membership, invitation, and team queries (ADR-008, TASKS 1.2).
-- Every tenant-scoped query MUST run inside database.WithTenantTx(ctx, pool, tenantID, ...).

-- name: CreateOrganization :one
INSERT INTO organizations (id, name, slug)
VALUES ($1, btrim($2), lower(btrim($3)))
RETURNING id, name, slug, status, purge_after, created_at, updated_at;

-- name: GetOrganizationByID :one
SELECT id, name, slug, status, purge_after, created_at, updated_at
FROM organizations
WHERE id = $1;

-- name: UpdateOrganization :one
UPDATE organizations
SET name = btrim($2),
    updated_at = sqlc.arg(updated_at)::timestamptz
WHERE id = $1
  AND status = 'active'
RETURNING id, name, slug, status, purge_after, created_at, updated_at;

-- name: ScheduleOrganizationDeletion :one
UPDATE organizations
SET status = 'pending_deletion',
    purge_after = sqlc.arg(purge_after)::timestamptz,
    updated_at = sqlc.arg(updated_at)::timestamptz
WHERE id = $1
  AND status = 'active'
RETURNING id, name, slug, status, purge_after, created_at, updated_at;

-- name: CancelOrganizationDeletion :one
UPDATE organizations
SET status = 'active',
    purge_after = NULL,
    updated_at = sqlc.arg(updated_at)::timestamptz
WHERE id = $1
  AND status = 'pending_deletion'
RETURNING id, name, slug, status, purge_after, created_at, updated_at;

-- name: CreateMembership :one
INSERT INTO memberships (id, organization_id, user_id, role, status)
VALUES ($1, $2, $3, $4, 'active')
RETURNING id, organization_id, user_id, role, status, created_at, updated_at;

-- name: GetMembershipByUser :one
SELECT id, organization_id, user_id, role, status, created_at, updated_at
FROM memberships
WHERE organization_id = $1
  AND user_id = $2
  AND status = 'active';

-- name: GetMembershipByID :one
SELECT id, organization_id, user_id, role, status, created_at, updated_at
FROM memberships
WHERE organization_id = $1
  AND id = $2;

-- name: ListOrganizationMembers :many
SELECT
    m.id,
    m.organization_id,
    m.user_id,
    m.role,
    m.status,
    m.created_at,
    m.updated_at,
    u.email AS user_email,
    u.name  AS user_name
FROM memberships m
JOIN users u ON u.id = m.user_id
WHERE m.organization_id = $1
  AND m.status = 'active'
ORDER BY m.created_at DESC, m.id DESC
LIMIT sqlc.arg(page_limit);

-- name: UpdateMembershipRole :one
UPDATE memberships
SET role = $3,
    updated_at = sqlc.arg(updated_at)::timestamptz
WHERE organization_id = $1
  AND id = $2
  AND status = 'active'
RETURNING id, organization_id, user_id, role, status, created_at, updated_at;

-- name: DeleteMembership :execrows
DELETE FROM memberships
WHERE organization_id = $1
  AND id = $2;

-- name: CountActiveOwners :one
SELECT count(*)
FROM memberships
WHERE organization_id = $1
  AND role = 'owner'
  AND status = 'active';

-- name: CreateInvitation :one
INSERT INTO invitations (id, organization_id, email, role, token_hash, invited_by, expires_at)
VALUES ($1, $2, lower(btrim($3)), $4, $5, $6, $7)
RETURNING id, organization_id, email, role, invited_by, expires_at, accepted_at, revoked_at, created_at;

-- name: ListOrganizationInvitations :many
SELECT id, organization_id, email, role, invited_by, expires_at, accepted_at, revoked_at, created_at
FROM invitations
WHERE organization_id = $1
  AND accepted_at IS NULL
  AND revoked_at IS NULL
ORDER BY created_at DESC, id DESC
LIMIT sqlc.arg(page_limit);

-- name: RevokeInvitation :execrows
UPDATE invitations
SET revoked_at = sqlc.arg(revoked_at)::timestamptz
WHERE organization_id = $1
  AND id = $2
  AND accepted_at IS NULL
  AND revoked_at IS NULL;

-- name: RevokeAllPendingOrgInvitations :exec
UPDATE invitations
SET revoked_at = sqlc.arg(revoked_at)::timestamptz
WHERE organization_id = $1
  AND accepted_at IS NULL
  AND revoked_at IS NULL;

-- name: GetUserSecurityStatus :one
SELECT id, email, status, email_verified_at, mfa_enabled
FROM users
WHERE id = $1;

-- name: AcceptInvitation :one
UPDATE invitations i
SET accepted_at = sqlc.arg(now)::timestamptz
FROM users u
WHERE i.organization_id = $1
  AND i.id = $2
  AND u.id = sqlc.arg(user_id)::uuid
  AND u.status = 'active'
  AND u.email_verified_at IS NOT NULL
  AND lower(i.email) = lower(u.email)
  AND i.accepted_at IS NULL
  AND i.revoked_at IS NULL
  AND i.expires_at > sqlc.arg(now)::timestamptz
RETURNING i.id, i.organization_id, i.email, i.role, i.invited_by, i.expires_at, i.accepted_at, i.revoked_at, i.created_at;

-- name: CreateTeam :one
INSERT INTO teams (id, organization_id, name, slug)
VALUES ($1, $2, btrim($3), lower(btrim($4)))
RETURNING id, organization_id, name, slug, created_at, updated_at;

-- name: ListOrganizationTeams :many
SELECT id, organization_id, name, slug, created_at, updated_at
FROM teams
WHERE organization_id = $1
ORDER BY created_at DESC, id DESC
LIMIT sqlc.arg(page_limit);

-- name: GetTeamByID :one
SELECT id, organization_id, name, slug, created_at, updated_at
FROM teams
WHERE organization_id = $1
  AND id = $2;

-- name: UpdateTeam :one
UPDATE teams
SET name = btrim($3),
    updated_at = sqlc.arg(updated_at)::timestamptz
WHERE organization_id = $1
  AND id = $2
RETURNING id, organization_id, name, slug, created_at, updated_at;

-- name: DeleteTeam :execrows
DELETE FROM teams
WHERE organization_id = $1
  AND id = $2;

-- name: AddTeamMember :exec
INSERT INTO team_members (organization_id, team_id, user_id)
VALUES ($1, $2, $3)
ON CONFLICT (team_id, user_id) DO NOTHING;

-- name: RemoveTeamMember :execrows
DELETE FROM team_members
WHERE organization_id = $1
  AND team_id = $2
  AND user_id = $3;
