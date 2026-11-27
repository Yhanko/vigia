-- +goose Up
-- Projects are soft-deleted and API credentials are revoked (never physically deleted).
-- Enforce at PostgreSQL privilege level (CTO #34, ADR-008 §4).
REVOKE DELETE ON projects, api_credentials FROM vigia_app;

-- +goose Down
GRANT DELETE ON projects, api_credentials TO vigia_app;
