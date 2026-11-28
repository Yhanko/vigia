-- +goose Up
-- +goose StatementBegin

-- Plan definitions (ADR-009 §3.1). Single source of truth for beta and future paid plans.
-- vigia_app has SELECT-only access; plan changes require a reviewed migration.
CREATE TABLE plans (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    max_events_per_month BIGINT NOT NULL CHECK (max_events_per_month > 0),
    max_events_per_day BIGINT NOT NULL CHECK (max_events_per_day > 0),
    rate_limit_org_per_min INT NOT NULL CHECK (rate_limit_org_per_min > 0),
    rate_limit_key_per_min INT NOT NULL CHECK (rate_limit_key_per_min > 0),
    max_whatsapp_per_month INT NOT NULL CHECK (max_whatsapp_per_month >= 0),
    max_projects INT NOT NULL CHECK (max_projects > 0),
    max_members INT NOT NULL CHECK (max_members > 0),
    max_alert_rules_per_project INT NOT NULL CHECK (max_alert_rules_per_project > 0),
    max_notification_targets INT NOT NULL CHECK (max_notification_targets > 0),
    max_artifact_bytes BIGINT NOT NULL CHECK (max_artifact_bytes > 0),
    event_retention_days INT NOT NULL CHECK (event_retention_days > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO plans (
    id,
    name,
    max_events_per_month,
    max_events_per_day,
    rate_limit_org_per_min,
    rate_limit_key_per_min,
    max_whatsapp_per_month,
    max_projects,
    max_members,
    max_alert_rules_per_project,
    max_notification_targets,
    max_artifact_bytes,
    event_retention_days
) VALUES (
    'beta',
    'Beta',
    100000,
    20000,
    1000,
    600,
    200,
    10,
    15,
    50,
    50,
    1073741824,
    30
);

ALTER TABLE organizations
    ADD COLUMN plan TEXT NOT NULL DEFAULT 'beta' REFERENCES plans(id);

-- Periodic persistence of Redis quota counters (ADR-009 §3.3).
CREATE TABLE usage_aggregates (
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    resource TEXT NOT NULL CHECK (resource IN ('events', 'whatsapp')),
    period_kind TEXT NOT NULL CHECK (period_kind IN ('day', 'month')),
    period_start DATE NOT NULL,
    used BIGINT NOT NULL DEFAULT 0 CHECK (used >= 0),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (organization_id, resource, period_kind, period_start)
);

CREATE INDEX idx_usage_aggregates_period_start ON usage_aggregates (period_start);

ALTER TABLE usage_aggregates ENABLE ROW LEVEL SECURITY;
ALTER TABLE usage_aggregates FORCE ROW LEVEL SECURITY;

CREATE POLICY usage_aggregates_tenant_isolation ON usage_aggregates
    USING (organization_id = NULLIF(current_setting('app.organization_id', true), '')::uuid)
    WITH CHECK (organization_id = NULLIF(current_setting('app.organization_id', true), '')::uuid);

-- One-time 80%/100% quota warning ledger per organization, resource, and monthly period (ADR-009 §3.3).
CREATE TABLE quota_notifications (
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    resource TEXT NOT NULL CHECK (resource IN ('events', 'whatsapp')),
    period_start DATE NOT NULL,
    threshold_pct INT NOT NULL CHECK (threshold_pct IN (80, 100)),
    notified_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (organization_id, resource, period_start, threshold_pct)
);

ALTER TABLE quota_notifications ENABLE ROW LEVEL SECURITY;
ALTER TABLE quota_notifications FORCE ROW LEVEL SECURITY;

CREATE POLICY quota_notifications_tenant_isolation ON quota_notifications
    USING (organization_id = NULLIF(current_setting('app.organization_id', true), '')::uuid)
    WITH CHECK (organization_id = NULLIF(current_setting('app.organization_id', true), '')::uuid);

REVOKE ALL ON TABLE plans, usage_aggregates, quota_notifications FROM PUBLIC;
GRANT SELECT ON TABLE plans TO vigia_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE usage_aggregates, quota_notifications TO vigia_app;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP TABLE IF EXISTS quota_notifications;
DROP TABLE IF EXISTS usage_aggregates;
ALTER TABLE organizations DROP COLUMN IF EXISTS plan;
DROP TABLE IF EXISTS plans;

-- +goose StatementEnd
