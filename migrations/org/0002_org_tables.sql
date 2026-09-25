-- SPDX-License-Identifier: Apache-2.0

-- Org triangle tables: typed org-unit tree, members (company-scoped
-- persons, optional user link), position slots (a position plus assignments with validity
-- windows; no vacancy, headcount or succession workflow). Facts only — nothing here enacts a
-- workflow.
CREATE EXTENSION IF NOT EXISTS pgcrypto;   -- gen_random_uuid()
CREATE EXTENSION IF NOT EXISTS btree_gist; -- equality operator class for the exclusion constraint below

-- org_unit_type: taxonomy is deployment configuration, not behavior — seeded below,
-- an operator may add more rows (e.g. "division"), but exactly ONE row may ever carry
-- is_company=true (the sole tenancy/authz anchor), enforced by the partial unique index.
CREATE TABLE org.org_unit_type (
    key        text PRIMARY KEY CHECK (key ~ '^[a-z][a-z0-9_]{1,31}$'),
    label      text NOT NULL,
    is_company boolean NOT NULL DEFAULT false
);

CREATE UNIQUE INDEX org_unit_type_one_company ON org.org_unit_type (is_company) WHERE is_company;

INSERT INTO org.org_unit_type (key, label, is_company) VALUES
    ('company', 'Company', true),
    ('territory', 'Territory', false),
    ('business_unit', 'Business Unit', false);

-- org_unit: the ONE hierarchy (territories/BUs partition data via the row-scope layer,
-- never via a second tuple hierarchy). Company code/name rule (code normalized
-- trim/upper/spaces→-, /^[A-Z0-9_-]{2,32}$/; name 2-120) is applied uniformly to every org_unit
-- row (there is no separate rule for non-company units) — normalization itself
-- (trim/upper/spaces→-) happens in application code (internal/org/store.go) before insert, this
-- CHECK is the storage-level backstop.
CREATE TABLE org.org_unit (
    id        uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    type_key  text NOT NULL REFERENCES org.org_unit_type (key),
    parent_id uuid REFERENCES org.org_unit (id),
    code      text NOT NULL CHECK (code ~ '^[A-Z0-9_-]{2,32}$'),
    name      text NOT NULL CHECK (char_length(name) BETWEEN 2 AND 120),
    is_active boolean NOT NULL DEFAULT true,
    CHECK (parent_id IS NULL OR parent_id <> id)
);

-- UNIQUE(parent_id, code). A plain UNIQUE constraint on a nullable column treats every
-- NULL as distinct, which would let unlimited root (parent_id IS NULL — i.e. company) rows share
-- a code; the partial index below closes that gap for roots specifically.
CREATE UNIQUE INDEX org_unit_code_unique ON org.org_unit (parent_id, code);
CREATE UNIQUE INDEX org_unit_root_code_unique ON org.org_unit (code) WHERE parent_id IS NULL;

CREATE INDEX org_unit_parent_id_idx ON org.org_unit (parent_id);

-- member: company-scoped persons, exist with or without a user link. The cross-schema
-- FK to identity.user_account is the ONE deliberate exception to the no-cross-schema-FK rule —
-- member<->user integrity is the triangle's core promise.
CREATE TABLE org.member (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id   uuid NOT NULL REFERENCES org.org_unit (id),
    code         text NOT NULL CHECK (code ~ '^[A-Z0-9_-]{2,32}$'),
    display_name text NOT NULL CHECK (char_length(display_name) BETWEEN 1 AND 120),
    email        text, -- the only PII field v1 (field-policy-eligible)
    user_id      uuid REFERENCES identity.user_account (id),
    is_active    boolean NOT NULL DEFAULT true,
    UNIQUE (company_id, code)
);

-- member<->user uniqueness is company-scoped, not tenant-global: one user may be a member of
-- several companies, but at most once per company. Partial so NULL (unlinked members) never
-- collide.
CREATE UNIQUE INDEX member_company_user_unique ON org.member (company_id, user_id) WHERE user_id IS NOT NULL;
CREATE INDEX member_company_id_idx ON org.member (company_id);

-- Enforce company_id references a COMPANY-typed org_unit (FK to org_unit plus a
-- company-typed check — a plain CHECK can't join org_unit_type, so a trigger does
-- the equivalent validation at insert/update time).
CREATE FUNCTION org.validate_member_company() RETURNS trigger AS $$
DECLARE
    company_typed boolean;
BEGIN
    SELECT ut.is_company INTO company_typed
    FROM org.org_unit u JOIN org.org_unit_type ut ON ut.key = u.type_key
    WHERE u.id = NEW.company_id;

    IF company_typed IS NOT TRUE THEN
        RAISE EXCEPTION 'org.member.company_id must reference a company-typed org_unit (got %)', NEW.company_id
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER member_company_must_be_company_typed
    BEFORE INSERT OR UPDATE OF company_id ON org.member
    FOR EACH ROW EXECUTE FUNCTION org.validate_member_company();

-- position: a first-class slot, sitting at a specific org_unit.
CREATE TABLE org.position (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id  uuid NOT NULL REFERENCES org.org_unit (id),
    code        text NOT NULL CHECK (code ~ '^[A-Z0-9_-]{2,32}$'),
    title       text NOT NULL CHECK (char_length(title) BETWEEN 1 AND 120),
    org_unit_id uuid NOT NULL REFERENCES org.org_unit (id),
    UNIQUE (company_id, code)
);

CREATE INDEX position_company_id_idx ON org.position (company_id);
CREATE INDEX position_org_unit_id_idx ON org.position (org_unit_id);

-- position_assignment: CRUD + assign only — validity-windowed, no overlap per position
-- (an exclusion constraint, not application-level locking).
CREATE TABLE org.position_assignment (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    position_id uuid NOT NULL REFERENCES org.position (id),
    member_id   uuid NOT NULL REFERENCES org.member (id),
    valid_from  date NOT NULL,
    valid_to    date,
    CHECK (valid_to IS NULL OR valid_to >= valid_from),
    EXCLUDE USING gist (
        position_id WITH =,
        daterange(valid_from, valid_to, '[]') WITH &&
    )
);

CREATE INDEX position_assignment_position_id_idx ON org.position_assignment (position_id);
CREATE INDEX position_assignment_member_id_idx ON org.position_assignment (member_id);

GRANT SELECT, INSERT, UPDATE, DELETE ON
    org.org_unit_type,
    org.org_unit,
    org.member,
    org.position,
    org.position_assignment
TO kiban_org;

---- create above / drop below ----

REVOKE ALL ON
    org.org_unit_type,
    org.org_unit,
    org.member,
    org.position,
    org.position_assignment
FROM kiban_org;

DROP TABLE org.position_assignment;
DROP TABLE org.position;
DROP TRIGGER member_company_must_be_company_typed ON org.member;
DROP FUNCTION org.validate_member_company();
DROP TABLE org.member;
DROP TABLE org.org_unit;
DROP TABLE org.org_unit_type;
