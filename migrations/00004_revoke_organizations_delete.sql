-- +goose Up
-- Organizations are never physically deleted (status transitions to 'deleted';
-- ADR-008 §4 and audit_logs ON DELETE RESTRICT). Enforce this at the DB privilege layer.
REVOKE DELETE ON organizations FROM vigia_app;

-- +goose Down
GRANT DELETE ON organizations TO vigia_app;
