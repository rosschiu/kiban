-- SPDX-License-Identifier: Apache-2.0

-- Docs tables: document (title/body, owner is a plain kcSub column recording who
-- created it — authorization itself is NEVER read from this table, only from authz's own tuples;
-- no authorization decision is made from the read-side index alone) and share (the
-- read-side index of who has been granted viewer/editor on which document — authz has a
-- grant/revoke API but no list-by-object query yet, same gap timesheet's approver_assignment
-- table already documents). company_id is a plain uuid column, never a cross-schema FK to org
-- (modules never reach into foundation schemas).
CREATE EXTENSION IF NOT EXISTS pgcrypto; -- gen_random_uuid()

CREATE TABLE docs.document (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id uuid NOT NULL,
    title      text NOT NULL CHECK (char_length(title) BETWEEN 1 AND 200),
    body       text NOT NULL DEFAULT '',
    owner_kcsub text NOT NULL, -- creator's kcSub, informational only — never the authority for access
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX document_company_id_idx ON docs.document (company_id);

-- share: ONE row per (document, member, relation) grant this module has asked authz to write.
-- Never authoritative (every read/write re-verifies
-- via authz's object-mode check); this table exists purely so the UI/API can list "who has this
-- doc" and "what does this member have" without a list-by-object query on the authz side.
-- A share row exists only while the grant is live — RevokeShare deletes it outright (the durable
-- history lives in audit.docs__events, this module's own audit trail, not a soft-delete flag
-- here). ON CONFLICT (document_id, member_id) upserts the relation in place for the
-- "upgrade to editor" flow (viewer -> editor on the same member, same row).
CREATE TABLE docs.share (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    document_id uuid NOT NULL REFERENCES docs.document (id) ON DELETE CASCADE,
    member_id   uuid NOT NULL,
    relation    text NOT NULL CHECK (relation IN ('viewer', 'editor')),
    granted_by  text NOT NULL, -- granting actor's kcSub
    created_at  timestamptz NOT NULL DEFAULT now(),
    UNIQUE (document_id, member_id)
);

CREATE INDEX share_document_id_idx ON docs.share (document_id);
CREATE INDEX share_member_id_idx ON docs.share (member_id);

GRANT SELECT, INSERT, UPDATE, DELETE ON docs.document, docs.share TO kiban_docs;

---- create above / drop below ----

REVOKE ALL ON docs.document, docs.share FROM kiban_docs;

DROP TABLE docs.share;
DROP TABLE docs.document;
