-- SPDX-License-Identifier: Apache-2.0

-- Authz core tables: the tuple store, the per-module model-fragment cache (loaded from
-- registry-known modules ONLY — unknown/disabled modules' fragments are inert), and the grant
-- ledger (audited grant/revoke history, the paper trail for grants written inside the caller's
-- own transaction).
CREATE TABLE authz.tuple (
    object_type       text NOT NULL,
    object_id         text NOT NULL,
    relation          text NOT NULL,
    subject_type      text NOT NULL,
    subject_id        text NOT NULL,
    subject_relation  text NOT NULL DEFAULT '', -- '' = direct subject; else userset subject
    created_at        timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (object_type, object_id, relation, subject_type, subject_id, subject_relation)
);

CREATE INDEX tuple_by_subject ON authz.tuple (subject_type, subject_id, relation, object_type);
CREATE INDEX tuple_by_object_rel ON authz.tuple (object_type, object_id, relation);

-- model_fragment: one row per module, holding its authz.fragment.json "relations" section
-- as loaded and subset-validated. active=false means the module is disabled or unknown —
-- the fragment stays on record for audit/debugging but the engine treats its object types as
-- absent from the effective model (fail-closed: any check against them denies, never errors the
-- request into a 5xx).
CREATE TABLE authz.model_fragment (
    module_key text PRIMARY KEY,
    fragment   jsonb NOT NULL,
    loaded_at  timestamptz NOT NULL DEFAULT now(),
    active     boolean NOT NULL DEFAULT true
);

-- grant_ledger: append-style history of every Grant/Revoke call (distinct from audit.authz__events
-- — this is the tuple-shaped grant history; audit.authz__events is the
-- platform-wide audit trail every service keeps). Never updated/deleted by application code (no
-- DB-level trigger fence here, a plain table — audit.authz__events carries
-- the hard append-only trigger).
CREATE TABLE authz.grant_ledger (
    id                bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    actor             text NOT NULL,
    object_type       text NOT NULL,
    object_id         text NOT NULL,
    relation          text NOT NULL,
    subject_type      text NOT NULL,
    subject_id        text NOT NULL,
    subject_relation  text NOT NULL DEFAULT '',
    op                text NOT NULL CHECK (op IN ('grant', 'revoke')),
    occurred_at       timestamptz NOT NULL DEFAULT now(),
    correlation_id    text
);

CREATE INDEX grant_ledger_object_idx ON authz.grant_ledger (object_type, object_id, relation);

GRANT SELECT, INSERT, UPDATE, DELETE ON
    authz.tuple,
    authz.model_fragment,
    authz.grant_ledger
TO kiban_authz;

GRANT USAGE ON ALL SEQUENCES IN SCHEMA authz TO kiban_authz;

---- create above / drop below ----

REVOKE ALL ON
    authz.tuple,
    authz.model_fragment,
    authz.grant_ledger
FROM kiban_authz;

DROP TABLE authz.grant_ledger;
DROP TABLE authz.model_fragment;
DROP TABLE authz.tuple;
