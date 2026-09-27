-- SPDX-License-Identifier: Apache-2.0

-- Append-only audit event table, same pattern as
-- modules/notification/migrations/0003_audit.sql.
CREATE SCHEMA IF NOT EXISTS audit AUTHORIZATION kiban;

CREATE OR REPLACE FUNCTION audit.reject_mutation() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'audit tables are append-only: % on % is forbidden', TG_OP, TG_TABLE_NAME;
END;
$$ LANGUAGE plpgsql;

CREATE TABLE audit.timesheet__events (
    id             bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    occurred_at    timestamptz NOT NULL DEFAULT now(),
    actor          text NOT NULL,
    action         text NOT NULL,
    subject        text NOT NULL,
    payload        jsonb NOT NULL DEFAULT '{}'::jsonb,
    correlation_id text
);

CREATE TRIGGER timesheet__events_append_only
    BEFORE UPDATE OR DELETE ON audit.timesheet__events
    FOR EACH ROW EXECUTE FUNCTION audit.reject_mutation();

GRANT SELECT, INSERT ON audit.timesheet__events TO kiban_timesheet;

---- create above / drop below ----

REVOKE ALL ON audit.timesheet__events FROM kiban_timesheet;
DROP TRIGGER timesheet__events_append_only ON audit.timesheet__events;
DROP TABLE audit.timesheet__events;
