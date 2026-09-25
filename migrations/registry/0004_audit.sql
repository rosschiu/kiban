-- SPDX-License-Identifier: Apache-2.0

-- Append-only audit event table. `audit.reject_mutation` is a shared
-- trigger function (schema-qualified, owned by `kiban`) other services' migrations may reuse
-- for their own `audit.<module>__*` tables — one implementation, not one per service.
CREATE OR REPLACE FUNCTION audit.reject_mutation() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'audit tables are append-only: % on % is forbidden', TG_OP, TG_TABLE_NAME;
END;
$$ LANGUAGE plpgsql;

CREATE TABLE audit.registry__events (
    id             bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    occurred_at    timestamptz NOT NULL DEFAULT now(),
    actor          text NOT NULL,
    action         text NOT NULL,
    subject        text NOT NULL,
    payload        jsonb NOT NULL DEFAULT '{}'::jsonb,
    correlation_id text
);

CREATE TRIGGER registry__events_append_only
    BEFORE UPDATE OR DELETE ON audit.registry__events
    FOR EACH ROW EXECUTE FUNCTION audit.reject_mutation();

-- kiban_registry (and every future role) gets INSERT+SELECT only — never UPDATE/DELETE — on its
-- own audit table; the trigger above is the enforced-in-storage backstop even against
-- a role or statement that somehow bypassed the grant (e.g. run as the table owner).
GRANT SELECT, INSERT ON audit.registry__events TO kiban_registry;

---- create above / drop below ----

REVOKE ALL ON audit.registry__events FROM kiban_registry;
DROP TRIGGER registry__events_append_only ON audit.registry__events;
DROP TABLE audit.registry__events;
DROP FUNCTION audit.reject_mutation();
