-- SPDX-License-Identifier: Apache-2.0

-- `org.group` + `org.group_member` — the third org fact type (member · position ·
-- group). A group is a company-scoped named set of members, with exactly one authoritative
-- source: `source` distinguishes a Kiban-native group (source='kiban', the only kind writable
-- through this migration's tables today) from a future externally-sourced one (populated by a
-- sync outside this schema; `external_ref` is the seam, not the sync code). The single-writer invariant itself
-- (membership of a non-'kiban' group is read-only through every human/API path) is enforced in
-- the STORE (internal/org/store.go), not here — this migration only shapes the data so that
-- enforcement is possible and the CHECK constraint below makes the 'kiban' ⟺ external_ref-is-NULL
-- pairing impossible to violate even by a future direct-SQL writer.
CREATE TABLE org.group (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id   uuid NOT NULL REFERENCES org.org_unit (id),
    code         text NOT NULL CHECK (code ~ '^[A-Z0-9_-]{2,32}$'),
    name         text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 120),
    source       text NOT NULL DEFAULT 'kiban' CHECK (source ~ '^[a-z][a-z0-9_]*(:[a-zA-Z0-9_.-]+)?$'),
    external_ref text CHECK ((source = 'kiban') = (external_ref IS NULL)),
    is_active    boolean NOT NULL DEFAULT true,
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now(),
    UNIQUE (company_id, code)
);

CREATE UNIQUE INDEX group_company_source_external_ref_unique
    ON org.group (company_id, source, external_ref) WHERE external_ref IS NOT NULL;

CREATE INDEX group_company_id_idx ON org.group (company_id);

-- group must sit at a company-typed org_unit — same validation shape as
-- org.validate_member_company()/org.validate_position_company().
CREATE FUNCTION org.validate_group_company() RETURNS trigger AS $$
DECLARE
    company_typed boolean;
BEGIN
    SELECT ut.is_company INTO company_typed
    FROM org.org_unit u JOIN org.org_unit_type ut ON ut.key = u.type_key
    WHERE u.id = NEW.company_id;

    IF company_typed IS NOT TRUE THEN
        RAISE EXCEPTION 'org.group.company_id must reference a company-typed org_unit (got %)', NEW.company_id
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER group_company_must_be_company_typed
    BEFORE INSERT OR UPDATE OF company_id ON org.group
    FOR EACH ROW EXECUTE FUNCTION org.validate_group_company();

-- No shared updated_at trigger exists elsewhere in org's schema (org.position has no
-- created_at/updated_at at all) — a small function scoped to this table, not new shared
-- infrastructure other tables must now also adopt.
CREATE FUNCTION org.group_touch_updated_at() RETURNS trigger AS $$
BEGIN
    NEW.updated_at := now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER group_set_updated_at
    BEFORE UPDATE ON org.group
    FOR EACH ROW EXECUTE FUNCTION org.group_touch_updated_at();

-- group_member: membership is a fact about MEMBERS, never users (the member-bridge:
-- a user reaches a group through its member link) — mirrors position_assignment's member_id shape, but flat (no validity window; a
-- group v1 has no tenure concept, only present/absent).
CREATE TABLE org.group_member (
    group_id  uuid NOT NULL REFERENCES org.group (id),
    member_id uuid NOT NULL REFERENCES org.member (id),
    added_by  text NOT NULL,
    added_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (group_id, member_id)
);

CREATE INDEX group_member_member_id_idx ON org.group_member (member_id);

-- validate_group_member_company: the added member's company must equal the group's company —
-- the DB-layer backstop for the store-level check (mirrors
-- org.validate_assignment_company()/migrations/org/0004).
CREATE FUNCTION org.validate_group_member_company() RETURNS trigger AS $$
DECLARE
    grp_company uuid;
    mem_company uuid;
BEGIN
    SELECT company_id INTO grp_company FROM org.group WHERE id = NEW.group_id;
    SELECT company_id INTO mem_company FROM org.member WHERE id = NEW.member_id;

    IF grp_company IS DISTINCT FROM mem_company THEN
        RAISE EXCEPTION 'org.group_member: member % (company %) does not belong to group %''s company (%)',
            NEW.member_id, mem_company, NEW.group_id, grp_company
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER group_member_must_match_group_company
    BEFORE INSERT OR UPDATE OF group_id, member_id ON org.group_member
    FOR EACH ROW EXECUTE FUNCTION org.validate_group_member_company();

GRANT SELECT, INSERT, UPDATE, DELETE ON org.group, org.group_member TO kiban_org;

---- create above / drop below ----

REVOKE ALL ON org.group, org.group_member FROM kiban_org;

DROP TRIGGER group_member_must_match_group_company ON org.group_member;
DROP FUNCTION org.validate_group_member_company();
DROP TABLE org.group_member;

DROP TRIGGER group_set_updated_at ON org.group;
DROP FUNCTION org.group_touch_updated_at();
DROP TRIGGER group_company_must_be_company_typed ON org.group;
DROP FUNCTION org.validate_group_company();
DROP TABLE org.group;
