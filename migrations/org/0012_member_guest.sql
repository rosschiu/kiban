-- SPDX-License-Identifier: Apache-2.0

-- A guest member: an external person added to a company so objects can be shared with them,
-- who must not read the company's directories (members, positions, groups) or a group's
-- member list. Decisions treat a guest like any other active member; only the member-level
-- reads refuse them (internal/org/http.go's requireMemberOrAdmin). Set at creation or by a
-- company administrator later.
ALTER TABLE org.member ADD COLUMN is_guest boolean NOT NULL DEFAULT false;

---- create above / drop below ----

ALTER TABLE org.member DROP COLUMN is_guest;
