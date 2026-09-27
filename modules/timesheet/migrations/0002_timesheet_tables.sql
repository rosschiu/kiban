-- SPDX-License-Identifier: Apache-2.0

-- Timesheet tables, keyed by member_id (an org member, not a user). company_id/member_id/project_id
-- are plain uuid columns — never a cross-schema FK into org (modules never reach into foundation
-- schemas); company/member/project existence is verified by the
-- service at request time via org's internal facts APIs and this module's own `project` table.
CREATE EXTENSION IF NOT EXISTS pgcrypto; -- gen_random_uuid()

-- project: module-owned master data. admin CRUD only.
CREATE TABLE timesheet.project (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id uuid NOT NULL,
    code       text NOT NULL CHECK (code ~ '^[A-Z0-9_-]{1,20}$'),
    name       text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 100),
    status     text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'inactive')),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (company_id, code)
);

CREATE INDEX project_company_id_idx ON timesheet.project (company_id);

-- configuration: one row per company, the four configuration knobs with their defaults.
CREATE TABLE timesheet.configuration (
    company_id                       uuid PRIMARY KEY,
    enforce_billable_within_actual   boolean NOT NULL DEFAULT true,
    allow_billable_above_eight_hours boolean NOT NULL DEFAULT false,
    allowed_previous_weeks           integer NOT NULL DEFAULT 4 CHECK (allowed_previous_weeks >= 0),
    allowed_future_weeks             integer NOT NULL DEFAULT 1 CHECK (allowed_future_weeks >= 0),
    created_at                       timestamptz NOT NULL DEFAULT now(),
    updated_at                       timestamptz NOT NULL DEFAULT now()
);

-- entry: one per member/project/day; draft-only mutation; hours 0-24; billable<=real enforced
-- server-side (configurable — needs the configuration row, not a CHECK constraint).
CREATE TABLE timesheet.entry (
    id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id     uuid NOT NULL,
    member_id      uuid NOT NULL,
    project_id     uuid NOT NULL REFERENCES timesheet.project (id),
    entry_date     date NOT NULL,
    real_hours     numeric(6,2) NOT NULL DEFAULT 0 CHECK (real_hours >= 0 AND real_hours <= 24),
    billable_hours numeric(6,2) NOT NULL DEFAULT 0 CHECK (billable_hours >= 0 AND billable_hours <= 24),
    status         text NOT NULL DEFAULT 'draft' CHECK (status IN ('draft', 'submitted', 'approved', 'rejected')),
    created_at     timestamptz NOT NULL DEFAULT now(),
    updated_at     timestamptz NOT NULL DEFAULT now(),
    UNIQUE (company_id, member_id, project_id, entry_date)
);

CREATE INDEX entry_company_member_date_idx ON timesheet.entry (company_id, member_id, entry_date);

-- approver_assignment: which member's submissions are routed to which approver. This is a
-- READ-SIDE index for the approvers-list API only — the enforceable grant of record is the
-- company_module#submitter/#approver tuple written through /internal/authz/grants at the same
-- time this row is written (service/approversclient.go); this table is never consulted for an
-- authorization decision itself (never a parallel grant store — it exists only because authz has no
-- list-by-object query).
CREATE TABLE timesheet.approver_assignment (
    company_id          uuid NOT NULL,
    member_id           uuid NOT NULL,
    member_kc_sub       text NOT NULL,
    approver_member_id  uuid NOT NULL,
    approver_kc_sub     text NOT NULL,
    assigned_by_kc_sub  text NOT NULL,
    assigned_at         timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (company_id, member_id)
);

-- submission: versioned, immutable snapshot header. version_number/root_id/supersedes_id form
-- the version chain; partial-unique is_current per company+member+week.
CREATE TABLE timesheet.submission (
    id                          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id                  uuid NOT NULL,
    member_id                   uuid NOT NULL,
    week_start                  date NOT NULL, -- ISO Monday, UTC
    version_number              integer NOT NULL,
    root_id                     uuid NOT NULL,
    supersedes_id               uuid REFERENCES timesheet.submission (id),
    is_current                  boolean NOT NULL DEFAULT true,
    status                      text NOT NULL CHECK (status IN ('submitted', 'approved', 'rejected')),
    assigned_approver_member_id uuid NOT NULL,
    assigned_approver_kc_sub    text NOT NULL,
    submitted_by_kc_sub         text NOT NULL,
    submitted_at                timestamptz NOT NULL DEFAULT now(),
    decided_by_kc_sub           text,
    decided_at                  timestamptz,
    reject_reason               text,
    idempotency_key             text, -- payload-bound Idempotency-Key on submit
    created_at                  timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX submission_company_member_idx ON timesheet.submission (company_id, member_id);
CREATE INDEX submission_approver_idx ON timesheet.submission (company_id, assigned_approver_member_id);
CREATE UNIQUE INDEX submission_current_unique
    ON timesheet.submission (company_id, member_id, week_start) WHERE is_current;
CREATE UNIQUE INDEX submission_idempotency_key_unique
    ON timesheet.submission (company_id, member_id, idempotency_key) WHERE idempotency_key IS NOT NULL;

-- submission_entry: immutable snapshot rows, denormalized project code/name.
CREATE TABLE timesheet.submission_entry (
    id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    submission_id  uuid NOT NULL REFERENCES timesheet.submission (id) ON DELETE CASCADE,
    project_id     uuid NOT NULL,
    project_code   text NOT NULL,
    project_name   text NOT NULL,
    entry_date     date NOT NULL,
    real_hours     numeric(6,2) NOT NULL,
    billable_hours numeric(6,2) NOT NULL
);

CREATE INDEX submission_entry_submission_id_idx ON timesheet.submission_entry (submission_id);

GRANT SELECT, INSERT, UPDATE, DELETE ON
    timesheet.project,
    timesheet.configuration,
    timesheet.entry,
    timesheet.approver_assignment,
    timesheet.submission,
    timesheet.submission_entry
TO kiban_timesheet;

---- create above / drop below ----

REVOKE ALL ON
    timesheet.project,
    timesheet.configuration,
    timesheet.entry,
    timesheet.approver_assignment,
    timesheet.submission,
    timesheet.submission_entry
FROM kiban_timesheet;

DROP TABLE timesheet.submission_entry;
DROP TABLE timesheet.submission;
DROP TABLE timesheet.approver_assignment;
DROP TABLE timesheet.entry;
DROP TABLE timesheet.configuration;
DROP TABLE timesheet.project;
