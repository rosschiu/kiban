-- SPDX-License-Identifier: Apache-2.0

-- name: GetOrgUnitType :one
SELECT * FROM org.org_unit_type WHERE key = $1;

-- name: CreateOrgUnit :one
INSERT INTO org.org_unit (type_key, parent_id, code, name, is_active)
VALUES ($1, $2, $3, $4, $5)
RETURNING *;

-- name: GetOrgUnit :one
SELECT * FROM org.org_unit WHERE id = $1;

-- name: UpdateOrgUnit :one
-- type_key is deliberately absent: org-unit type is immutable after creation.
UPDATE org.org_unit
SET parent_id = $2, code = $3, name = $4, is_active = $5
WHERE id = $1
RETURNING *;

-- name: DeleteOrgUnit :execrows
DELETE FROM org.org_unit WHERE id = $1;

-- name: CountOrgUnitChildren :one
SELECT count(*) FROM org.org_unit WHERE parent_id = $1;

-- name: CountMembersForCompany :one
SELECT count(*) FROM org.member WHERE company_id = $1;

-- name: SubtreeOrgUnits :many
-- Recursive CTE, depth-bounded 32. Powers GET /internal/org/units/{id}/subtree and the
-- cycle-proof parent-change validation (a candidate new parent must not already be in the
-- moved unit's own subtree).
WITH RECURSIVE subtree AS (
    SELECT r.id, r.type_key, r.parent_id, r.code, r.name, r.is_active, 0 AS depth
    FROM org.org_unit r
    WHERE r.id = $1
    UNION ALL
    SELECT u.id, u.type_key, u.parent_id, u.code, u.name, u.is_active, s.depth + 1
    FROM org.org_unit u
    JOIN subtree s ON u.parent_id = s.id
    WHERE s.depth < 32
)
SELECT subtree.id, subtree.type_key, subtree.parent_id, subtree.code, subtree.name, subtree.is_active, subtree.depth
FROM subtree ORDER BY depth, code;

-- name: CreateMember :one
INSERT INTO org.member (company_id, code, display_name, email, is_active)
VALUES ($1, $2, $3, $4, $5)
RETURNING *;

-- name: GetMember :one
SELECT * FROM org.member WHERE id = $1;

-- name: UpdateMember :one
UPDATE org.member
SET display_name = $2, email = $3, is_active = $4
WHERE id = $1
RETURNING *;

-- name: LinkMemberUser :one
UPDATE org.member SET user_id = $2 WHERE id = $1 RETURNING *;

-- name: UnlinkMemberUser :one
UPDATE org.member SET user_id = NULL WHERE id = $1 RETURNING *;

-- name: ListMembers :many
-- Member directory read: one SQL query, JOIN identity.user_read_v for linked-user display
-- fields, paginated/authorized in SQL — never per-row API calls.
SELECT m.id, m.company_id, m.code, m.display_name, m.email, m.user_id, m.is_active,
       u.kc_sub AS user_kc_sub, u.email AS user_email,
       u.preferred_username AS user_preferred_username, u.lifecycle AS user_lifecycle
FROM org.member m
LEFT JOIN identity.user_read_v u ON u.id = m.user_id
WHERE m.company_id = $1
ORDER BY m.code
LIMIT $2 OFFSET $3;

-- name: CountMembers :one
SELECT count(*) FROM org.member WHERE company_id = $1;

-- name: GetMemberWithUser :one
SELECT m.id, m.company_id, m.code, m.display_name, m.email, m.user_id, m.is_active,
       u.kc_sub AS user_kc_sub, u.email AS user_email,
       u.preferred_username AS user_preferred_username, u.lifecycle AS user_lifecycle
FROM org.member m
LEFT JOIN identity.user_read_v u ON u.id = m.user_id
WHERE m.id = $1;

-- name: GetIdentityUserByKcSub :one
-- The published read contract — the ONLY way org reads identity data. Resolves the
-- internal user_id to store in member.user_id after the HTTP-level liveness check
-- (internal/org/identityclient.go) has confirmed the account exists.
SELECT id, kc_sub, email, preferred_username, lifecycle FROM identity.user_read_v WHERE kc_sub = $1;

-- name: CreatePosition :one
INSERT INTO org.position (company_id, code, title, org_unit_id)
VALUES ($1, $2, $3, $4)
RETURNING *;

-- name: GetPosition :one
SELECT * FROM org.position WHERE id = $1;

-- name: UpdatePosition :one
UPDATE org.position SET title = $2, org_unit_id = $3 WHERE id = $1 RETURNING *;

-- name: DeletePosition :execrows
DELETE FROM org.position WHERE id = $1;

-- name: ListPositions :many
SELECT * FROM org.position WHERE company_id = $1 ORDER BY code LIMIT $2 OFFSET $3;

-- name: CountPositions :one
SELECT count(*) FROM org.position WHERE company_id = $1;

-- name: ListPositionsWithHolder :many
-- The admin list surface — each row carries the CURRENT assignment (assignmentId/memberId/
-- holder displayName), the fields the UI needs to END a tenure. "current" = today's half-open
-- window (migrations/org/0009): valid_from <= today AND
-- (valid_to IS NULL OR valid_to > today). today is the store's tenant-timezone date (the same
-- clock assign-NOW/end-NOW stamp), never CURRENT_DATE (the DB session's zone — a second clock).
-- LEFT JOINs so an unassigned position still returns a row with NULL assignment fields, never
-- omitted.
SELECT p.id, p.company_id, p.code, p.title, p.org_unit_id,
       a.id AS assignment_id, a.member_id AS assignment_member_id,
       mem.display_name AS holder_display_name
FROM org.position p
LEFT JOIN org.position_assignment a
       ON a.position_id = p.id
      AND a.valid_from <= sqlc.arg('today')::date
      AND (a.valid_to IS NULL OR a.valid_to > sqlc.arg('today')::date)
LEFT JOIN org.member mem ON mem.id = a.member_id
WHERE p.company_id = $1
ORDER BY p.code
LIMIT $2 OFFSET $3;

-- name: CreateAssignment :one
INSERT INTO org.position_assignment (position_id, member_id, valid_from, valid_to)
VALUES ($1, $2, $3, $4)
RETURNING *;

-- name: GetAssignment :one
SELECT * FROM org.position_assignment WHERE id = $1;

-- name: EndAssignment :one
UPDATE org.position_assignment SET valid_to = $2 WHERE id = $1 RETURNING *;

-- name: CountOtherOpenAssignments :one
-- Open (valid_to IS NULL) assignments for the same (position, member) pair other than $1 — the
-- holder tuple is revoked only when this count is zero (ending one of several open windows must
-- not revoke the access another still-open window confers).
SELECT count(*) FROM org.position_assignment
WHERE position_id = $2 AND member_id = $3 AND valid_to IS NULL AND id <> $1;

-- name: GetAssignmentOnDate :one
-- "who holds position P on date D". valid_to is HALF-OPEN/EXCLUSIVE
-- (migrations/org/0009) — D is held when valid_from <= D < valid_to (or valid_to IS NULL), never
-- valid_to >= D (which would have D's holder-of-record still be the PREVIOUS occupant on the
-- exact day a same-day handover's successor starts).
SELECT * FROM org.position_assignment
WHERE position_id = $1 AND valid_from <= $2 AND (valid_to IS NULL OR valid_to > $2)
LIMIT 1;

-- name: GetCompanyState :one
-- Company-state fact for authz's decision.CompanySource. A row is only returned when id
-- resolves to a COMPANY-typed org_unit (org_unit_type.is_company = true) — a non-company unit or
-- an unknown id both come back as no-rows, which the store maps to exists=false (never a
-- fabricated company for an org_unit of the wrong type).
SELECT ou.id, ou.is_active
FROM org.org_unit ou
JOIN org.org_unit_type ut ON ut.key = ou.type_key
WHERE ou.id = $1 AND ut.is_company = true;

-- name: GetMemberByCompanyAndKcSub :one
-- Membership fact for authz's decision.MembershipSource. Resolves the member linked to
-- kcSub within companyId via the published identity.user_read_v join (same read path
-- ListMembers/GetMemberWithUser already use) — never a per-row identity call.
SELECT m.id, m.is_active
FROM org.member m
JOIN identity.user_read_v u ON u.id = m.user_id
WHERE m.company_id = $1 AND u.kc_sub = $2;

-- name: ListActiveCompaniesForKcSub :many
-- The company-switcher source — companies where kcSub has an ACTIVE membership in an ACTIVE
-- company. One SQL query (member JOIN identity.user_read_v JOIN org_unit), filtered/sorted in
-- SQL — never in-memory. Self-scoped by construction: kcSub is the caller's own identity, a
-- param at the internal layer; the gateway injects the bearer's own kcSub, never trusting a
-- client-supplied value.
-- Both m.is_active (the membership) and ou.is_active (the company itself) are required — an
-- inactive company is never offered as a switch target even if the membership row is still
-- active.
SELECT ou.id, ou.code, ou.name, ou.is_active
FROM org.member m
JOIN identity.user_read_v u ON u.id = m.user_id
JOIN org.org_unit ou ON ou.id = m.company_id
WHERE u.kc_sub = $1 AND m.is_active = true AND ou.is_active = true
ORDER BY ou.code;

-- name: ListMemberDirectory :many
-- The browser-reachable member directory (share-with/assign-to picker). REDUCED view
-- (id/displayName/email/hasLinkedUser only — least disclosure) over ACTIVE members of one
-- company, optional case-insensitive LITERAL substring filter on displayName/email (sqlc.narg —
-- NULL means "no filter"; the store escapes `\`, `%`, `_` in q, hence ESCAPE '\'),
-- filtered/sorted/paginated entirely in SQL.
SELECT m.id, m.display_name, m.email, (m.user_id IS NOT NULL)::boolean AS has_linked_user
FROM org.member m
WHERE m.company_id = $1 AND m.is_active = true
  AND (sqlc.narg('q')::text IS NULL
       OR m.display_name ILIKE '%' || sqlc.narg('q')::text || '%' ESCAPE '\'
       OR m.email ILIKE '%' || sqlc.narg('q')::text || '%' ESCAPE '\')
ORDER BY m.display_name
LIMIT $2 OFFSET $3;

-- name: CountMemberDirectory :one
SELECT count(*)
FROM org.member m
WHERE m.company_id = $1 AND m.is_active = true
  AND (sqlc.narg('q')::text IS NULL
       OR m.display_name ILIKE '%' || sqlc.narg('q')::text || '%' ESCAPE '\'
       OR m.email ILIKE '%' || sqlc.narg('q')::text || '%' ESCAPE '\');

-- name: CreateGroup :one
-- source defaults to 'kiban' at the DB level; only an external sync writer would pass another
-- source value explicitly, the org admin API never does.
INSERT INTO org.group (company_id, code, name, source, external_ref)
VALUES ($1, $2, $3, $4, $5)
RETURNING *;

-- name: GetGroup :one
SELECT * FROM org.group WHERE id = $1;

-- name: CountGroups :one
SELECT count(*) FROM org.group WHERE company_id = $1;

-- name: ListGroupsWithMemberCount :many
-- The admin list surface: each row carries its member
-- count so the UI can render "N members" without a second round trip per row.
SELECT g.id, g.company_id, g.code, g.name, g.source, g.external_ref, g.is_active, g.created_at, g.updated_at,
       count(gm.member_id) AS member_count
FROM org.group g
LEFT JOIN org.group_member gm ON gm.group_id = g.id
WHERE g.company_id = $1
GROUP BY g.id
ORDER BY g.code
LIMIT $2 OFFSET $3;

-- name: ListGroupMembers :many
-- Group membership read: member rows for a group, joined for display fields — the shape the
-- admin surface and the assignable-groups module read both need.
SELECT gm.group_id, gm.member_id, gm.added_by, gm.added_at,
       m.display_name AS member_display_name, m.email AS member_email
FROM org.group_member gm
JOIN org.member m ON m.id = gm.member_id
WHERE gm.group_id = $1
ORDER BY m.display_name;

-- name: AddGroupMember :execrows
-- 0 rows affected = already a member (idempotent add); the store then reads the STORED row
-- back with GetGroupMember so the response carries the original added_by/added_at.
INSERT INTO org.group_member (group_id, member_id, added_by)
VALUES ($1, $2, $3)
ON CONFLICT DO NOTHING;

-- name: GetGroupMember :one
SELECT * FROM org.group_member WHERE group_id = $1 AND member_id = $2;

-- name: RemoveGroupMember :execrows
DELETE FROM org.group_member WHERE group_id = $1 AND member_id = $2;
