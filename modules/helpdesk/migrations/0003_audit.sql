-- SPDX-License-Identifier: Apache-2.0

-- Append-only audit event table, same pattern as every other service's own
-- ..._audit.sql. Audit tables are named audit.<moduleKey>__<name>.
CREATE SCHEMA IF NOT EXISTS audit AUTHORIZATION kiban;

CREATE OR REPLACE FUNCTION audit.reject_mutation() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'audit tables are append-only: % on % is forbidden', TG_OP, TG_TABLE_NAME;
END;
$$ LANGUAGE plpgsql;

CREATE TABLE audit.helpdesk__events (
    id             bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    occurred_at    timestamptz NOT NULL DEFAULT now(),
    actor          text NOT NULL,
    action         text NOT NULL,
    subject        text NOT NULL,
    payload        jsonb NOT NULL DEFAULT '{}'::jsonb,
    correlation_id text
);

CREATE TRIGGER helpdesk__events_append_only
    BEFORE UPDATE OR DELETE ON audit.helpdesk__events
    FOR EACH ROW EXECUTE FUNCTION audit.reject_mutation();

-- kiban_helpdesk gets INSERT+SELECT only — never UPDATE/DELETE.
GRANT SELECT, INSERT ON audit.helpdesk__events TO kiban_helpdesk;

---- create above / drop below ----

REVOKE ALL ON audit.helpdesk__events FROM kiban_helpdesk;
DROP TRIGGER helpdesk__events_append_only ON audit.helpdesk__events;
DROP TABLE audit.helpdesk__events;
