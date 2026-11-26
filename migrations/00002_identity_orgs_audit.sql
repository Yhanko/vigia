-- +goose Up
-- Core identity, organizations, RBAC, and append-only audit schema (README §8.2, §8.6; ADR-005, ADR-008).
-- Roles vigia_app and vigia_definer are cluster-global and ensured outside migrations (EnsureRoles).

-- ─── Global identity tables (no organization_id) ─────────────────────────────

CREATE TABLE users (
    id                   uuid        PRIMARY KEY,
    email                text        NOT NULL UNIQUE
        CHECK (email = lower(btrim(email)) AND email <> ''),
    name                 text        NOT NULL CHECK (btrim(name) <> ''),
    password_hash        text        NOT NULL CHECK (password_hash <> ''),
    email_verified_at    timestamptz,
    mfa_enabled          boolean     NOT NULL DEFAULT false,
    mfa_secret_encrypted bytea,
    status               text        NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'disabled', 'deleted')),
    created_at           timestamptz NOT NULL DEFAULT now(),
    updated_at           timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE sessions (
    id                  uuid        PRIMARY KEY,
    user_id             uuid        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash          bytea       NOT NULL UNIQUE,
    csrf_token_hash     bytea       NOT NULL,
    last_auth_at        timestamptz NOT NULL,
    expires_at          timestamptz NOT NULL,
    absolute_expires_at timestamptz NOT NULL,
    revoked_at          timestamptz,
    ip_prefix           text,
    user_agent          text,
    created_at          timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX sessions_user_expires_idx
    ON sessions (user_id, expires_at DESC);

CREATE TABLE user_tokens (
    id         uuid        PRIMARY KEY,
    user_id    uuid        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    kind       text        NOT NULL
        CHECK (kind IN ('email_verify', 'password_reset', 'mfa_recovery')),
    token_hash bytea       NOT NULL UNIQUE,
    expires_at timestamptz,
    used_at    timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX user_tokens_user_kind_created_idx
    ON user_tokens (user_id, kind, created_at DESC);

-- ─── Tenant-scoped tables (fail-closed RLS) ──────────────────────────────────

CREATE TABLE organizations (
    id          uuid        PRIMARY KEY,
    name        text        NOT NULL CHECK (btrim(name) <> ''),
    slug        text        NOT NULL UNIQUE
        CHECK (slug ~ '^[a-z0-9](?:[a-z0-9-]{1,61}[a-z0-9])?$'),
    status      text        NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'pending_deletion', 'deleted')),
    purge_after timestamptz,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE memberships (
    id              uuid        PRIMARY KEY,
    organization_id uuid        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id         uuid        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role            text        NOT NULL
        CHECK (role IN ('owner', 'admin', 'member', 'viewer')),
    status          text        NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'suspended', 'removed')),
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (organization_id, user_id)
);

CREATE INDEX memberships_user_status_idx
    ON memberships (user_id, status);

CREATE TABLE invitations (
    id              uuid        PRIMARY KEY,
    organization_id uuid        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    email           text        NOT NULL
        CHECK (email = lower(btrim(email)) AND email <> ''),
    role            text        NOT NULL
        CHECK (role IN ('admin', 'member', 'viewer')),
    token_hash      bytea       NOT NULL UNIQUE,
    invited_by      uuid        NOT NULL REFERENCES users(id),
    expires_at      timestamptz NOT NULL,
    accepted_at     timestamptz,
    revoked_at      timestamptz,
    created_at      timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX invitations_org_created_idx
    ON invitations (organization_id, created_at DESC);

CREATE UNIQUE INDEX invitations_org_active_email_uidx
    ON invitations (organization_id, email)
    WHERE accepted_at IS NULL AND revoked_at IS NULL;

CREATE TABLE teams (
    id              uuid        PRIMARY KEY,
    organization_id uuid        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name            text        NOT NULL CHECK (btrim(name) <> ''),
    slug            text        NOT NULL
        CHECK (slug ~ '^[a-z0-9](?:[a-z0-9-]{1,61}[a-z0-9])?$'),
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (organization_id, slug),
    UNIQUE (organization_id, id)
);

CREATE TABLE team_members (
    organization_id uuid        NOT NULL,
    team_id         uuid        NOT NULL,
    user_id         uuid        NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (team_id, user_id),
    FOREIGN KEY (organization_id, team_id)
        REFERENCES teams(organization_id, id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id, user_id)
        REFERENCES memberships(organization_id, user_id) ON DELETE CASCADE
);

CREATE INDEX team_members_org_team_user_idx
    ON team_members (organization_id, team_id, user_id);

-- Append-only audit log: organizations are soft-deleted (status = 'deleted'),
-- never physically removed, so ON DELETE RESTRICT preserves forensic integrity.
CREATE TABLE audit_logs (
    id              uuid        PRIMARY KEY,
    organization_id uuid        REFERENCES organizations(id) ON DELETE RESTRICT,
    actor_type      text        NOT NULL
        CHECK (actor_type IN ('user', 'system', 'credential')),
    actor_id        uuid,
    action          text        NOT NULL CHECK (btrim(action) <> ''),
    resource_type   text        NOT NULL CHECK (btrim(resource_type) <> ''),
    resource_id     text,
    result          text        NOT NULL
        CHECK (result IN ('success', 'denied', 'failure')),
    ip_prefix       text,
    user_agent      text,
    request_id      text        NOT NULL CHECK (btrim(request_id) <> ''),
    changes         jsonb       NOT NULL DEFAULT '{}',
    created_at      timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX audit_logs_org_created_id_idx
    ON audit_logs (organization_id, created_at DESC, id DESC);

CREATE INDEX audit_logs_org_action_created_idx
    ON audit_logs (organization_id, action, created_at DESC);

-- ─── Explicit per-table GRANTs (no ALTER DEFAULT PRIVILEGES) ─────────────────

GRANT USAGE ON SCHEMA public TO vigia_app, vigia_definer;

GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE
    users,
    sessions,
    user_tokens,
    organizations,
    memberships,
    invitations,
    teams,
    team_members
TO vigia_app;

-- audit_logs is strictly append-only for vigia_app (no UPDATE, no DELETE).
GRANT SELECT, INSERT ON TABLE audit_logs TO vigia_app;

-- ─── Fail-closed Row-Level Security (ADR-008) ────────────────────────────────

ALTER TABLE organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE organizations FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON organizations
    USING (id = NULLIF(current_setting('app.organization_id', true), '')::uuid)
    WITH CHECK (id = NULLIF(current_setting('app.organization_id', true), '')::uuid);

ALTER TABLE memberships ENABLE ROW LEVEL SECURITY;
ALTER TABLE memberships FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON memberships
    USING (organization_id = NULLIF(current_setting('app.organization_id', true), '')::uuid)
    WITH CHECK (organization_id = NULLIF(current_setting('app.organization_id', true), '')::uuid);

ALTER TABLE invitations ENABLE ROW LEVEL SECURITY;
ALTER TABLE invitations FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON invitations
    USING (organization_id = NULLIF(current_setting('app.organization_id', true), '')::uuid)
    WITH CHECK (organization_id = NULLIF(current_setting('app.organization_id', true), '')::uuid);

ALTER TABLE teams ENABLE ROW LEVEL SECURITY;
ALTER TABLE teams FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON teams
    USING (organization_id = NULLIF(current_setting('app.organization_id', true), '')::uuid)
    WITH CHECK (organization_id = NULLIF(current_setting('app.organization_id', true), '')::uuid);

ALTER TABLE team_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE team_members FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON team_members
    USING (organization_id = NULLIF(current_setting('app.organization_id', true), '')::uuid)
    WITH CHECK (organization_id = NULLIF(current_setting('app.organization_id', true), '')::uuid);

ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_logs FORCE ROW LEVEL SECURITY;
-- Global auth events (organization_id IS NULL) are insertable, never readable
-- through a tenant-scoped query.
CREATE POLICY tenant_isolation_select ON audit_logs
    FOR SELECT
    USING (organization_id = NULLIF(current_setting('app.organization_id', true), '')::uuid);
CREATE POLICY tenant_isolation_insert ON audit_logs
    FOR INSERT
    WITH CHECK (
        organization_id IS NULL
        OR organization_id = NULLIF(current_setting('app.organization_id', true), '')::uuid
    );

-- +goose Down
-- Roles vigia_app and vigia_definer are cluster-global and intentionally preserved.
DROP TABLE IF EXISTS audit_logs;
DROP TABLE IF EXISTS team_members;
DROP TABLE IF EXISTS teams;
DROP TABLE IF EXISTS invitations;
DROP TABLE IF EXISTS memberships;
DROP TABLE IF EXISTS organizations;
DROP TABLE IF EXISTS user_tokens;
DROP TABLE IF EXISTS sessions;
DROP TABLE IF EXISTS users;
