-- SPDX-License-Identifier: Apache-2.0

-- Append-only audit event table, same pattern as migrations/registry/0004_audit.sql.
-- CREATE SCHEMA IF NOT EXISTS / CREATE OR REPLACE FUNCTION make this file self-contained for
-- sqlc's schema parser (which only reads migrations/identity, not migrations/registry) and for
-- a from-scratch DB where identity's migrations somehow ran before registry's — both are no-ops
-- against a normal DB, where registry's migrations already created both (same
-- reject_mutation() implementation, not a second one).
CREATE SCHEMA IF NOT EXISTS audit AUTHORIZATION kiban;

CREATE OR REPLACE FUNCTION audit.reject_mutation() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'audit tables are append-only: % on % is forbidden', TG_OP, TG_TABLE_NAME;
END;
$$ LANGUAGE plpgsql;

CREATE TABLE audit.identity__events (
    id             bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    occurred_at    timestamptz NOT NULL DEFAULT now(),
    actor          text NOT NULL,
    action         text NOT NULL,
    subject        text NOT NULL,
    payload        jsonb NOT NULL DEFAULT '{}'::jsonb,
    correlation_id text
);

CREATE TRIGGER identity__events_append_only
    BEFORE UPDATE OR DELETE ON audit.identity__events
    FOR EACH ROW EXECUTE FUNCTION audit.reject_mutation();

-- kiban_identity gets INSERT+SELECT only — never UPDATE/DELETE.
GRANT SELECT, INSERT ON audit.identity__events TO kiban_identity;

---- create above / drop below ----

REVOKE ALL ON audit.identity__events FROM kiban_identity;
DROP TRIGGER identity__events_append_only ON audit.identity__events;
DROP TABLE audit.identity__events;
