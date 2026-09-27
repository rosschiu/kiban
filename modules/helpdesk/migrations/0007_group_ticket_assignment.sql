-- SPDX-License-Identifier: Apache-2.0

-- A ticket's assignee gains a THIRD target — a group, alongside member (existing) and
-- position (0005_position_ticket_assignment.sql). Assignment to a group means "the current members of this group work this
-- ticket", resolved at READ time via authz's object-mode `can` for group:<id>#member @
-- user:<callerKcSub> (AuthzClient.IsGroupMember) — never snapshotted into assignee_member_id/
-- assignee_kcsub. assignee_group_title is a display snapshot only (mirrors
-- assignee_position_title's own pattern), never used for any authorization decision. The
-- at-most-one-of CHECK widens from two columns to three (assignee_member_id,
-- assignee_position_id, assignee_group_id) — at most one may be set (an unassigned ticket has
-- none). Existing rows are unaffected: assignee_group_id stays NULL everywhere until this
-- migration's own new assignments start setting it.
ALTER TABLE helpdesk.ticket
    ADD COLUMN assignee_group_id uuid,
    ADD COLUMN assignee_group_title text;

ALTER TABLE helpdesk.ticket
    DROP CONSTRAINT ticket_at_most_one_of_assignee_member_or_position;

ALTER TABLE helpdesk.ticket
    ADD CONSTRAINT ticket_at_most_one_of_assignee_member_position_or_group
        CHECK (
            (CASE WHEN assignee_member_id IS NOT NULL THEN 1 ELSE 0 END) +
            (CASE WHEN assignee_position_id IS NOT NULL THEN 1 ELSE 0 END) +
            (CASE WHEN assignee_group_id IS NOT NULL THEN 1 ELSE 0 END) <= 1
        );

CREATE INDEX ticket_assignee_group_id_idx ON helpdesk.ticket (assignee_group_id);

---- create above / drop below ----

DROP INDEX helpdesk.ticket_assignee_group_id_idx;
ALTER TABLE helpdesk.ticket DROP CONSTRAINT ticket_at_most_one_of_assignee_member_position_or_group;
ALTER TABLE helpdesk.ticket
    ADD CONSTRAINT ticket_at_most_one_of_assignee_member_or_position
        CHECK (assignee_member_id IS NULL OR assignee_position_id IS NULL);
ALTER TABLE helpdesk.ticket
    DROP COLUMN assignee_group_title,
    DROP COLUMN assignee_group_id;
