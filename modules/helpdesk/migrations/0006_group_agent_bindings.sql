-- SPDX-License-Identifier: Apache-2.0

-- helpdesk.agent gains a THIRD binding shape — group-held tiers, alongside the
-- existing member and position shapes (0004_position_agent_bindings.sql). group_id + group_title (a display snapshot,
-- the same established pattern position_title/reporter_kcsub/assignee_kcsub all use) are added,
-- nullable. The exactly-one-of CHECK widens from two columns to three (member_id, position_id,
-- group_id) — exactly one must be set per row. UNIQUE(company_id, group_id) alongside the
-- pre-existing per-company uniqueness for member/position — a group may be bound to the agent
-- tier at most once per company, same as a position.
ALTER TABLE helpdesk.agent
    ADD COLUMN group_id uuid,
    ADD COLUMN group_title text;

ALTER TABLE helpdesk.agent
    DROP CONSTRAINT agent_exactly_one_of_member_or_position;

ALTER TABLE helpdesk.agent
    ADD CONSTRAINT agent_exactly_one_of_member_position_or_group
        CHECK (
            (CASE WHEN member_id IS NOT NULL THEN 1 ELSE 0 END) +
            (CASE WHEN position_id IS NOT NULL THEN 1 ELSE 0 END) +
            (CASE WHEN group_id IS NOT NULL THEN 1 ELSE 0 END) = 1
        );

CREATE UNIQUE INDEX agent_company_group_unique ON helpdesk.agent (company_id, group_id) WHERE group_id IS NOT NULL;

---- create above / drop below ----

DROP INDEX helpdesk.agent_company_group_unique;
ALTER TABLE helpdesk.agent DROP CONSTRAINT agent_exactly_one_of_member_position_or_group;
ALTER TABLE helpdesk.agent
    ADD CONSTRAINT agent_exactly_one_of_member_or_position
        CHECK ((member_id IS NOT NULL) <> (position_id IS NOT NULL));
ALTER TABLE helpdesk.agent
    DROP COLUMN group_title,
    DROP COLUMN group_id;
