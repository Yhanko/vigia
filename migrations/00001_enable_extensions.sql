-- +goose Up
-- Enable core PostgreSQL extensions required by Vigia.
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS timescaledb;

-- +goose Down
-- Extensions are intentionally preserved on down migration to avoid dropping dependent objects.
SELECT 1;
