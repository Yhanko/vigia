-- +goose Up
-- Project privacy opt-ins, inbound filters, and SECURITY DEFINER DSN lookup
-- for Sentry-compatible ingestion (TASKS 2.1, ADR-005, ADR-017 §3.2).

ALTER TABLE projects
    ADD COLUMN allow_request_body BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN allow_user_ip BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN inbound_filters JSONB NOT NULL DEFAULT '{"browser_extensions":true,"localhost":false,"crawlers":true}'::jsonb;

GRANT SELECT (id, organization_id, public_id, status, allow_request_body, allow_user_ip, inbound_filters)
    ON projects TO vigia_definer;
GRANT SELECT (id, organization_id, project_id, environment_id, kind, public_key, allowed_origins, expires_at, revoked_at)
    ON api_credentials TO vigia_definer;

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION lookup_dsn_key(p_public_key text)
RETURNS TABLE (
    credential_id      uuid,
    organization_id    uuid,
    project_id         uuid,
    project_public_id  bigint,
    environment_id     uuid,
    allowed_origins    text[],
    expires_at         timestamptz,
    revoked_at         timestamptz,
    allow_request_body boolean,
    allow_user_ip      boolean,
    inbound_filters    jsonb
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $$
    SELECT c.id,
           c.organization_id,
           c.project_id,
           p.public_id,
           c.environment_id,
           c.allowed_origins,
           c.expires_at,
           c.revoked_at,
           p.allow_request_body,
           p.allow_user_ip,
           p.inbound_filters
    FROM public.api_credentials c
    JOIN public.projects p
      ON p.organization_id = c.organization_id
     AND p.id = c.project_id
     AND p.status = 'active'
    JOIN public.organizations o
      ON o.id = c.organization_id
     AND o.status = 'active'
    WHERE c.kind = 'dsn'
      AND c.public_key = p_public_key;
$$;
-- +goose StatementEnd

ALTER FUNCTION lookup_dsn_key(text) OWNER TO vigia_definer;
REVOKE EXECUTE ON FUNCTION lookup_dsn_key(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION lookup_dsn_key(text) TO vigia_app;

-- +goose Down
DROP FUNCTION IF EXISTS lookup_dsn_key(text);
ALTER TABLE projects
    DROP COLUMN IF EXISTS inbound_filters,
    DROP COLUMN IF EXISTS allow_user_ip,
    DROP COLUMN IF EXISTS allow_request_body;
