-- SPDX-License-Identifier: Apache-2.0

-- Helpdesk tables: ticket (title/description/status/reporter/assignee), comment
-- (append-only), and agent (the read-side index of who currently holds the company_module#editor
-- "agent" tier for this module — authz has a grant/revoke API but no list-by-relation query yet,
-- the same gap docs.share/timesheet.approver_assignment already document). company_id is a plain
-- uuid column, never a cross-schema FK to org (modules never reach into
-- foundation schemas). Reporter/assignee are recorded BOTH as a member_id (for the member-
-- directory-fed UI) and a kcsub (for cheap identity comparisons in service logic — visibility and
-- transition rules are plain row comparisons against these columns, never an authz relation check
-- per ticket: no new object type, no per-ticket tuples).
CREATE EXTENSION IF NOT EXISTS pgcrypto; -- gen_random_uuid()

CREATE TABLE helpdesk.ticket (
    id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id         uuid NOT NULL,
    title              text NOT NULL CHECK (char_length(title) BETWEEN 1 AND 200),
    description        text NOT NULL DEFAULT '',
    status             text NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'in_progress', 'resolved', 'closed')),
    reporter_member_id uuid NOT NULL,
    reporter_kcsub     text NOT NULL,
    assignee_member_id uuid,
    assignee_kcsub     text,
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX ticket_company_id_idx ON helpdesk.ticket (company_id);
CREATE INDEX ticket_reporter_kcsub_idx ON helpdesk.ticket (company_id, reporter_kcsub);
CREATE INDEX ticket_assignee_member_id_idx ON helpdesk.ticket (assignee_member_id);

-- comment: append-only (nobody edits comments). No UPDATE grant is given to
-- kiban_helpdesk below — enforced structurally, not just by service code.
CREATE TABLE helpdesk.comment (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    ticket_id   uuid NOT NULL REFERENCES helpdesk.ticket (id) ON DELETE CASCADE,
    author_kcsub text NOT NULL,
    body        text NOT NULL CHECK (char_length(body) BETWEEN 1 AND 10000),
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX comment_ticket_id_idx ON helpdesk.comment (ticket_id);

-- agent: ONE row per member this module has asked authz to grant company_module#editor to.
-- Never authoritative on its own (every visibility/authorization decision re-verifies via
-- AuthzClient.Can) — exists so GET /agents and the "assignee already an agent?" auto-grant check
-- don't need a list-by-relation query authz doesn't offer. A row exists only while the grant is
-- live; DELETE FROM helpdesk.agent on remove-agent, mirroring docs.share's hard-delete precedent
-- (durable history lives in audit.helpdesk__events, never a soft-delete flag here).
CREATE TABLE helpdesk.agent (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id uuid NOT NULL,
    member_id  uuid NOT NULL,
    kcsub      text NOT NULL,
    granted_by text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (company_id, member_id)
);

CREATE INDEX agent_company_id_idx ON helpdesk.agent (company_id);

GRANT SELECT, INSERT, UPDATE, DELETE ON helpdesk.ticket, helpdesk.agent TO kiban_helpdesk;
GRANT SELECT, INSERT ON helpdesk.comment TO kiban_helpdesk;

---- create above / drop below ----

REVOKE ALL ON helpdesk.ticket, helpdesk.comment, helpdesk.agent FROM kiban_helpdesk;

DROP TABLE helpdesk.agent;
DROP TABLE helpdesk.comment;
DROP TABLE helpdesk.ticket;
