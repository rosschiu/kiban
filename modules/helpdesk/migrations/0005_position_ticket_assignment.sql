-- SPDX-License-Identifier: Apache-2.0

-- A ticket's assignee becomes EITHER a member (existing shape, unchanged) OR a
-- position — assignment to a position means "the current holder of this chair works this
-- ticket", resolved at READ time (helpdesk asks authz's object-mode `can` for
-- position:<id>#holder @ user:<callerKcSub> — see AuthzClient.IsPositionHolder), never
-- snapshotted into assignee_member_id/assignee_kcsub. assignee_position_title is a display
-- snapshot only (mirrors helpdesk.agent.position_title's own established pattern from
-- 0004_position_agent_bindings.sql) — never used for any authorization decision. Existing member-assigned rows are
-- unaffected: assignee_position_id stays NULL, the CHECK's at-most-one-of is already
-- satisfied by every existing row (assignee_member_id set XOR unset, assignee_position_id
-- always NULL until this migration's own new assignments start setting it).
ALTER TABLE helpdesk.ticket
    ADD COLUMN assignee_position_id uuid,
    ADD COLUMN assignee_position_title text;

ALTER TABLE helpdesk.ticket
    ADD CONSTRAINT ticket_at_most_one_of_assignee_member_or_position
        CHECK (assignee_member_id IS NULL OR assignee_position_id IS NULL);

CREATE INDEX ticket_assignee_position_id_idx ON helpdesk.ticket (assignee_position_id);

---- create above / drop below ----

DROP INDEX helpdesk.ticket_assignee_position_id_idx;
ALTER TABLE helpdesk.ticket DROP CONSTRAINT ticket_at_most_one_of_assignee_member_or_position;
ALTER TABLE helpdesk.ticket
    DROP COLUMN assignee_position_title,
    DROP COLUMN assignee_position_id;
