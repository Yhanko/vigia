-- +goose Up
-- Projects, environments, and API credentials schema with fail-closed RLS
-- (README §8.2, §10.1-10.2; ADR-005 §3.2, ADR-008; TASKS 1.3).

CREATE TABLE projects (
    id              uuid        PRIMARY KEY,
    organization_id uuid        NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
    public_id       bigint      NOT NULL UNIQUE CHECK (public_id > 0),
    name            text        NOT NULL CHECK (btrim(name) <> ''),
    slug            text        NOT NULL
        CHECK (slug ~ '^[a-z0-9](?:[a-z0-9-]{1,61}[a-z0-9])?$'),
    platform        text        NOT NULL DEFAULT 'other',
    status          text        NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'deleting', 'deleted')),
    deleted_at      timestamptz,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (organization_id, slug),
    UNIQUE (organization_id, id)
);

CREATE INDEX projects_org_created_idx
    ON projects (organization_id, created_at DESC, id DESC);

CREATE TABLE environments (
    id              uuid        PRIMARY KEY,
    organization_id uuid        NOT NULL,
    project_id      uuid        NOT NULL,
    name            text        NOT NULL
        CHECK (name ~ '^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$'),
    is_protected    boolean     NOT NULL DEFAULT false,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (project_id, name),
    UNIQUE (organization_id, id),
    FOREIGN KEY (organization_id, project_id)
        REFERENCES projects(organization_id, id) ON DELETE CASCADE
);

CREATE INDEX environments_org_project_idx
    ON environments (organization_id, project_id);

CREATE TABLE api_credentials (
    id              uuid        PRIMARY KEY,
    organization_id uuid        NOT NULL,
    project_id      uuid        NOT NULL,
    environment_id  uuid,
    kind            text        NOT NULL
        CHECK (kind IN ('ingest', 'client', 'dsn')),
    name            text        NOT NULL CHECK (btrim(name) <> ''),
    prefix          text        NOT NULL CHECK (prefix ~ '^[0-9a-f]{8,12}$'),
    secret_hash     bytea,
    public_key      text        UNIQUE CHECK (public_key IS NULL OR public_key ~ '^[0-9a-f]{32}$'),
    scopes          text[]      NOT NULL DEFAULT '{}',
    allowed_origins text[]      NOT NULL DEFAULT '{}',
    expires_at      timestamptz,
    last_used_at    timestamptz,
    revoked_at      timestamptz,
    created_by      uuid        NOT NULL REFERENCES users(id),
    created_at      timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (organization_id, project_id)
        REFERENCES projects(organization_id, id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id, environment_id)
        REFERENCES environments(organization_id, id) ON DELETE SET NULL,
    CHECK (
        (kind IN ('ingest', 'client') AND secret_hash IS NOT NULL AND public_key IS NULL AND length(prefix) = 12)
        OR
        (kind = 'dsn' AND public_key IS NOT NULL AND secret_hash IS NULL AND length(prefix) = 8)
    )
);

CREATE UNIQUE INDEX api_credentials_secret_kind_prefix_uidx
    ON api_credentials (kind, prefix)
    WHERE kind IN ('ingest', 'client');

CREATE INDEX api_credentials_org_project_idx
    ON api_credentials (organization_id, project_id, created_at DESC);

-- Explicit per-table GRANTs (no ALTER DEFAULT PRIVILEGES).
GRANT SELECT, INSERT, UPDATE, DELETE ON
    projects,
    environments,
    api_credentials
TO vigia_app;

-- Fail-closed RLS on all three tenant-scoped tables (ADR-008).
ALTER TABLE projects ENABLE ROW LEVEL SECURITY;
ALTER TABLE projects FORCE ROW LEVEL SECURITY;
CREATE POLICY projects_tenant_isolation ON projects
    USING (organization_id = NULLIF(current_setting('app.organization_id', true), '')::uuid)
    WITH CHECK (organization_id = NULLIF(current_setting('app.organization_id', true), '')::uuid);

ALTER TABLE environments ENABLE ROW LEVEL SECURITY;
ALTER TABLE environments FORCE ROW LEVEL SECURITY;
CREATE POLICY environments_tenant_isolation ON environments
    USING (organization_id = NULLIF(current_setting('app.organization_id', true), '')::uuid)
    WITH CHECK (organization_id = NULLIF(current_setting('app.organization_id', true), '')::uuid);

ALTER TABLE api_credentials ENABLE ROW LEVEL SECURITY;
ALTER TABLE api_credentials FORCE ROW LEVEL SECURITY;
CREATE POLICY api_credentials_tenant_isolation ON api_credentials
    USING (organization_id = NULLIF(current_setting('app.organization_id', true), '')::uuid)
    WITH CHECK (organization_id = NULLIF(current_setting('app.organization_id', true), '')::uuid);

-- Pre-tenant credential lookup owned by vigia_definer (ADR-005 §3.2, ADR-008).
GRANT SELECT (id, organization_id, project_id, environment_id, kind, prefix, secret_hash, scopes, expires_at, revoked_at)
    ON api_credentials TO vigia_definer;

-- +goose StatementBegin
CREATE FUNCTION lookup_api_credential_by_prefix(p_kind text, p_prefix text)
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

-- +goose Down
DROP FUNCTION IF EXISTS lookup_api_credential_by_prefix(text, text);
DROP TABLE IF EXISTS api_credentials;
DROP TABLE IF EXISTS environments;
DROP TABLE IF EXISTS projects;
