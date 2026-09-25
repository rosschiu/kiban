-- SPDX-License-Identifier: Apache-2.0

-- Append-only audit event table, same pattern as migrations/{registry,identity,org}/
-- ..._audit.sql. Audit tables are named audit.<moduleKey>__<name>.
-- CREATE SCHEMA IF NOT EXISTS / CREATE OR REPLACE FUNCTION mirror org's own 0003_audit.sql
-- rationale: self-contained for sqlc-style schema parsers and out-of-order bootstraps alike —
-- both are no-ops against the real dev DB, where registry's migrations already created the
-- shared `audit` schema and `reject_mutation()` function.
CREATE SCHEMA IF NOT EXISTS audit AUTHORIZATION kiban;

CREATE OR REPLACE FUNCTION audit.reject_mutation() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'audit tables are append-only: % on % is forbidden', TG_OP, TG_TABLE_NAME;
END;
$$ LANGUAGE plpgsql;

CREATE TABLE audit.notification__events (
    id             bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    occurred_at    timestamptz NOT NULL DEFAULT now(),
    actor          text NOT NULL,
    action         text NOT NULL,
    subject        text NOT NULL,
    payload        jsonb NOT NULL DEFAULT '{}'::jsonb,
    correlation_id text
);

CREATE TRIGGER notification__events_append_only
    BEFORE UPDATE OR DELETE ON audit.notification__events
    FOR EACH ROW EXECUTE FUNCTION audit.reject_mutation();

-- kiban_notification gets INSERT+SELECT only — never UPDATE/DELETE.
GRANT SELECT, INSERT ON audit.notification__events TO kiban_notification;

---- create above / drop below ----

REVOKE ALL ON audit.notification__events FROM kiban_notification;
DROP TRIGGER notification__events_append_only ON audit.notification__events;
DROP TABLE audit.notification__events;
