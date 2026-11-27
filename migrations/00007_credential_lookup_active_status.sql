-- +goose Up
-- Defense in depth (CTO #28): lookup_api_credential_by_prefix must reject
-- credentials belonging to non-active projects or organizations.

GRANT SELECT (id, organization_id, status) ON projects TO vigia_definer;
GRANT SELECT (id, status) ON organizations TO vigia_definer;

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION lookup_api_credential_by_prefix(p_kind text, p_prefix text)
RETURNS TABLE (
    credential_id   uuid,
    organization_id uuid,
    project_id      uuid,
    environment_id  uuid,
    kind            text,
    secret_hash     bytea,
    scopes          text[],
    expires_at      timestamptz,
    revoked_at      timestamptz
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $$
    SELECT c.id, c.organization_id, c.project_id, c.environment_id,
           c.kind, c.secret_hash, c.scopes, c.expires_at, c.revoked_at
    FROM public.api_credentials c
    JOIN public.projects p
      ON p.organization_id = c.organization_id
     AND p.id = c.project_id
     AND p.status = 'active'
    JOIN public.organizations o
      ON o.id = c.organization_id
     AND o.status = 'active'
    WHERE c.kind = p_kind
      AND c.prefix = p_prefix
      AND c.kind IN ('ingest', 'client');
$$;
-- +goose StatementEnd

ALTER FUNCTION lookup_api_credential_by_prefix(text, text) OWNER TO vigia_definer;
REVOKE EXECUTE ON FUNCTION lookup_api_credential_by_prefix(text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION lookup_api_credential_by_prefix(text, text) TO vigia_app;

-- +goose Down
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION lookup_api_credential_by_prefix(p_kind text, p_prefix text)
RETURNS TABLE (
    credential_id   uuid,
    organization_id uuid,
    project_id      uuid,
    environment_id  uuid,
    kind            text,
    secret_hash     bytea,
    scopes          text[],
    expires_at      timestamptz,
    revoked_at      timestamptz
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $$
    SELECT c.id, c.organization_id, c.project_id, c.environment_id,
           c.kind, c.secret_hash, c.scopes, c.expires_at, c.revoked_at
    FROM public.api_credentials c
    WHERE c.kind = p_kind
      AND c.prefix = p_prefix
      AND c.kind IN ('ingest', 'client');
$$;
-- +goose StatementEnd

ALTER FUNCTION lookup_api_credential_by_prefix(text, text) OWNER TO vigia_definer;
REVOKE EXECUTE ON FUNCTION lookup_api_credential_by_prefix(text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION lookup_api_credential_by_prefix(text, text) TO vigia_app;
REVOKE SELECT ON projects FROM vigia_definer;
REVOKE SELECT ON organizations FROM vigia_definer;
