-- +goose Up
-- Minimal-scope SECURITY DEFINER functions for legitimate cross-tenant lookups
-- (ADR-008 §3.3). Owned exclusively by vigia_definer (NOLOGIN NOSUPERUSER BYPASSRLS),
-- with fixed search_path (pg_temp last) and EXECUTE revoked from PUBLIC.

-- Minimal column-level SELECT grants for vigia_definer.
GRANT SELECT (id, name, slug, status) ON TABLE organizations TO vigia_definer;
GRANT SELECT (organization_id, user_id, role, status) ON TABLE memberships TO vigia_definer;
GRANT SELECT (id, organization_id, token_hash) ON TABLE invitations TO vigia_definer;

-- +goose StatementBegin
CREATE FUNCTION list_user_organizations(p_user_id uuid)
RETURNS TABLE (
    organization_id   uuid,
    name              text,
    slug              text,
    org_status        text,
    role              text,
    membership_status text
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $$
    SELECT o.id, o.name, o.slug, o.status, m.role, m.status
    FROM public.memberships m
    JOIN public.organizations o ON o.id = m.organization_id
    WHERE m.user_id = p_user_id
      AND m.status = 'active'
      AND o.status <> 'deleted'
    ORDER BY o.name ASC, o.id ASC;
$$;
-- +goose StatementEnd

ALTER FUNCTION list_user_organizations(uuid) OWNER TO vigia_definer;
REVOKE EXECUTE ON FUNCTION list_user_organizations(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION list_user_organizations(uuid) TO vigia_app;

-- +goose StatementBegin
-- Returns ONLY (invitation_id, organization_id); callers must immediately enter
-- WithTenantTx(organization_id) to read and validate the full invitation row.
CREATE FUNCTION lookup_invitation_by_token_hash(p_token_hash bytea)
RETURNS TABLE (
    invitation_id   uuid,
    organization_id uuid
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $$
    SELECT i.id, i.organization_id
    FROM public.invitations i
    WHERE i.token_hash = p_token_hash
    LIMIT 1;
$$;
-- +goose StatementEnd

ALTER FUNCTION lookup_invitation_by_token_hash(bytea) OWNER TO vigia_definer;
REVOKE EXECUTE ON FUNCTION lookup_invitation_by_token_hash(bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION lookup_invitation_by_token_hash(bytea) TO vigia_app;

-- +goose Down
DROP FUNCTION IF EXISTS lookup_invitation_by_token_hash(bytea);
DROP FUNCTION IF EXISTS list_user_organizations(uuid);

REVOKE SELECT ON TABLE invitations FROM vigia_definer;
REVOKE SELECT ON TABLE memberships FROM vigia_definer;
REVOKE SELECT ON TABLE organizations FROM vigia_definer;
