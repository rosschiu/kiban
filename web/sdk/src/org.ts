// SPDX-License-Identifier: Apache-2.0

// Typed client over org's gateway-exposed HTTP surface: the caller's own companies, the member
// directory, and the superadmin position/group admin routes. Every method here works through the
// edge; org's `/internal/org/...` CRUD surface (not mounted by the gateway — see
// internal/gateway/routes.go) lives on `createInternalOrgClient` (orgInternal.ts) instead.
//
// `meCompanies()` — `GET /api/org/me/companies` (internal/gateway/foundation_routes.go). The
// gateway injects the caller's own kcSub from the validated bearer; there is no kcSub parameter on
// this method at all, by construction — the company-switcher source can only ever answer for the
// caller themselves.
import type { ApiClient } from "./client.js";
import type {
  MemberDirectoryEntry,
  OrgAssignment,
  OrgGroup,
  OrgGroupMember,
  OrgGroupWithMemberCount,
  OrgMeCompany,
  OrgPosition,
  OrgPositionWithHolder,
  Page
} from "./types.js";

/** Typed client over org's gateway-exposed HTTP surface: `meCompanies`, `memberDirectory`, and
 * the superadmin-only `admin*` position/group methods. */
export interface OrgClient {
  /** GET /api/org/me/companies — companies where the CALLER (kcSub-injected by the gateway) has
   * an active membership in an active company; the company-switcher source. */
  meCompanies(): Promise<OrgMeCompany[]>;

  /** GET /api/org/companies/{companyId}/members — the gateway-exposed, least-disclosure
   * member picker (share-with/assign-to). q is an optional case-insensitive substring filter
   * over displayName/email. */
  memberDirectory(companyId: string, q?: string, page?: number, pageSize?: number): Promise<Page<MemberDirectoryEntry>>;

  // ---- The sample shell's minimal position-based-access admin surface (`/api/org/admin/...`,
  // internal/gateway/admin_position_routes.go) — every call requires the caller to hold
  // `auth.platform_administration.access` (superadmin); 403 KibanApiError otherwise, 503 if the
  // guard itself can't reach a definite answer (fail-closed, never a silent allow).

  /** GET /api/org/admin/companies/{companyId}/positions — list, each row carrying its CURRENT
   * assignment (assignmentId/memberId/holderDisplayName — null when unassigned). */
  adminListPositions(companyId: string, page?: number, pageSize?: number): Promise<Page<OrgPositionWithHolder>>;
  /** POST /api/org/admin/companies/{companyId}/positions {code,title} — companyId comes from the
   * PATH only; org-unit defaults to the company root. */
  adminCreatePosition(companyId: string, input: { code: string; title: string }): Promise<OrgPosition>;
  /** POST /api/org/admin/positions/{id}/assignments {memberId} — assign-NOW (server-dated). */
  adminAssignPosition(positionId: string, memberId: string): Promise<OrgAssignment>;
  /** POST /api/org/admin/assignments/{id}/end — end-NOW, no body (server-dated). */
  adminEndAssignment(assignmentId: string): Promise<OrgAssignment>;

  // ---- The group admin surface. Same posture as the four position methods above —
  // gateway-exposed (`/api/org/admin/...`, internal/gateway/admin_group_routes.go),
  // superadmin-only.

  /** GET /api/org/admin/companies/{companyId}/groups — list, each row carrying its member count
   * and source (externally-sourced groups render read-only with a source badge). */
  adminListGroups(companyId: string, page?: number, pageSize?: number): Promise<Page<OrgGroupWithMemberCount>>;
  /** POST /api/org/admin/companies/{companyId}/groups {code,name} — companyId comes from the PATH
   * only; the group is always created with source="kiban" (the only source this surface can
   * create). */
  adminCreateGroup(companyId: string, input: { code: string; name: string }): Promise<OrgGroup>;
  /** GET /api/org/admin/groups/{id}/members — the Groups admin page's own member-list read, needed
   * to render a remove button per current member (add/remove alone can't drive a UI without
   * knowing WHO to remove). */
  adminListGroupMembers(groupId: string): Promise<OrgGroupMember[]>;
  /** POST /api/org/admin/groups/{id}/members {memberId} — add a member. 409
   * GROUP_EXTERNALLY_MANAGED if the group's source isn't "kiban" (the single-writer invariant). */
  adminAddGroupMember(groupId: string, memberId: string): Promise<OrgGroupMember>;
  /** DELETE /api/org/admin/groups/{id}/members/{memberId} — remove a member. Same 409
   * GROUP_EXTERNALLY_MANAGED refusal as adminAddGroupMember. */
  adminRemoveGroupMember(groupId: string, memberId: string): Promise<{ groupId: string; memberId: string }>;
}

/** Builds an {@link OrgClient} over `client`. */
export function createOrgClient(client: ApiClient): OrgClient {
  return {
    meCompanies: () => client.request("/api/org/me/companies"),

    memberDirectory: (companyId, q, page, pageSize) =>
      client.request(`/api/org/companies/${encodeURIComponent(companyId)}/members`, { query: { q, page, pageSize } }),

    adminListPositions: (companyId, page, pageSize) =>
      client.request(`/api/org/admin/companies/${encodeURIComponent(companyId)}/positions`, {
        query: { page, pageSize }
      }),
    adminCreatePosition: (companyId, input) =>
      client.request(`/api/org/admin/companies/${encodeURIComponent(companyId)}/positions`, {
        method: "POST",
        body: input
      }),
    adminAssignPosition: (positionId, memberId) =>
      client.request(`/api/org/admin/positions/${encodeURIComponent(positionId)}/assignments`, {
        method: "POST",
        body: { memberId }
      }),
    adminEndAssignment: (assignmentId) =>
      client.request(`/api/org/admin/assignments/${encodeURIComponent(assignmentId)}/end`, { method: "POST" }),

    adminListGroups: (companyId, page, pageSize) =>
      client.request(`/api/org/admin/companies/${encodeURIComponent(companyId)}/groups`, {
        query: { page, pageSize }
      }),
    adminCreateGroup: (companyId, input) =>
      client.request(`/api/org/admin/companies/${encodeURIComponent(companyId)}/groups`, {
        method: "POST",
        body: input
      }),
    adminListGroupMembers: (groupId) =>
      client.request(`/api/org/admin/groups/${encodeURIComponent(groupId)}/members`),
    adminAddGroupMember: (groupId, memberId) =>
      client.request(`/api/org/admin/groups/${encodeURIComponent(groupId)}/members`, {
        method: "POST",
        body: { memberId }
      }),
    adminRemoveGroupMember: (groupId, memberId) =>
      client.request(
        `/api/org/admin/groups/${encodeURIComponent(groupId)}/members/${encodeURIComponent(memberId)}`,
        { method: "DELETE" }
      )
  };
}
