-- SPDX-License-Identifier: Apache-2.0

-- helpdesk.agent gains a SECOND binding shape —
-- position-held tiers, not just per-member ones. member_id/kcsub become nullable (a
-- position-bound row has neither); position_id + position_title (a display snapshot, mirroring
-- the module's own established pattern of storing a display field alongside a foreign fact —
-- ticket.reporter_kcsub/assignee_kcsub do the same for identity) are added, nullable. Exactly one
-- of {member_id, position_id} must be set per row (CHECK), and each is unique per company
-- (UNIQUE(company_id, position_id) alongside the pre-existing UNIQUE(company_id, member_id)) — a
-- position may be bound to the agent tier at most once per company, same as a member.
ALTER TABLE helpdesk.agent
    ALTER COLUMN member_id DROP NOT NULL,
    ALTER COLUMN kcsub DROP NOT NULL,
    ADD COLUMN position_id uuid,
    ADD COLUMN position_title text;

ALTER TABLE helpdesk.agent
    ADD CONSTRAINT agent_exactly_one_of_member_or_position
        CHECK ((member_id IS NOT NULL) <> (position_id IS NOT NULL));

CREATE UNIQUE INDEX agent_company_position_unique ON helpdesk.agent (company_id, position_id) WHERE position_id IS NOT NULL;

---- create above / drop below ----

DROP INDEX helpdesk.agent_company_position_unique;
ALTER TABLE helpdesk.agent DROP CONSTRAINT agent_exactly_one_of_member_or_position;
ALTER TABLE helpdesk.agent
    DROP COLUMN position_title,
    DROP COLUMN position_id,
    ALTER COLUMN kcsub SET NOT NULL,
    ALTER COLUMN member_id SET NOT NULL;
