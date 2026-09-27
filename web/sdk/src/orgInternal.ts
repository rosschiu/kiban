// SPDX-License-Identifier: Apache-2.0

// Typed client over org's `/internal/org/...` surface (internal/org/http.go): unit/member/position
// CRUD, assignments, and the two company-fact reads authz's own decision step 5 depends on.
//
// NOT GATEWAY-EXPOSED: every route here returns 404 from outside the edge
// (internal/gateway/routes.go). The methods are built and unit-tested against the real Go wire
// shapes so they are ready once those routes are mounted, but they are deliberately kept off the
// public `OrgClient` (org.ts) and out of the typedoc reference (`@internal`) — see the package
// README's "Known gaps" section.
import type { ApiClient } from "./client.js";
import type {
  OrgAssignment,
  OrgCompanyState,
  OrgMember,
  OrgMembershipState,
  OrgPosition,
  OrgUnit,
  Page
} from "./types.js";

/** Body shape for {@link InternalOrgClient.createUnit}/`updateUnit`.
 * @internal */
export interface CreateOrgUnitInput {
  typeKey: string;
  parentId?: string | null;
  code: string;
  name: string;
  isActive?: boolean;
}

/** Body shape for {@link InternalOrgClient.createMember}.
 * @internal */
export interface CreateOrgMemberInput {
  companyId: string;
  code: string;
  displayName: string;
  email: string;
  isActive?: boolean;
}

/** Body shape for {@link InternalOrgClient.createPosition}.
 * @internal */
export interface CreateOrgPositionInput {
  companyId: string;
  code: string;
  title: string;
  orgUnitId: string;
}

/** Typed client over org's `/internal/org/...` routes — none of which the gateway mounts (they
 * 404 from outside the edge). In-cluster callers only.
 * @internal */
export interface InternalOrgClient {
  /** POST /internal/org/units — create an org-taxonomy unit. */
  createUnit(input: CreateOrgUnitInput): Promise<OrgUnit>;
  /** GET /internal/org/units/{id}. */
  getUnit(id: string): Promise<OrgUnit>;
  /** PUT /internal/org/units/{id}. */
  updateUnit(id: string, input: CreateOrgUnitInput): Promise<OrgUnit>;
  /** DELETE /internal/org/units/{id}. */
  deleteUnit(id: string): Promise<{ id: string }>;
  /** GET /internal/org/units/{id}/subtree — the unit and its descendants, each with `depth`. */
  subtree(id: string): Promise<(OrgUnit & { depth: number })[]>;

  /** GET /internal/org/companies/{companyId}/state — whether the company exists and is active. */
  companyState(companyId: string): Promise<OrgCompanyState>;
  /** GET /internal/org/companies/{companyId}/members/by-kcsub/{kcSub} — whether kcSub is an
   * active member of the company. */
  memberByKcSub(companyId: string, kcSub: string): Promise<OrgMembershipState>;

  /** POST /internal/org/members — create a company member row. */
  createMember(input: CreateOrgMemberInput): Promise<OrgMember>;
  /** GET /internal/org/members/{id}. */
  getMember(id: string): Promise<OrgMember>;
  /** GET /internal/org/members?companyId=... — paginated. */
  listMembers(companyId: string, page?: number, pageSize?: number): Promise<Page<OrgMember>>;
  /** PUT /internal/org/members/{id}. */
  updateMember(id: string, input: Omit<CreateOrgMemberInput, "companyId">): Promise<OrgMember>;
  /** POST /internal/org/members/{id}/link-user — link a Keycloak kcSub to this member. */
  linkUser(id: string, kcSub: string): Promise<OrgMember>;
  /** DELETE /internal/org/members/{id}/link-user — unlink. */
  unlinkUser(id: string): Promise<OrgMember>;

  /** POST /internal/org/positions — create a position. */
  createPosition(input: CreateOrgPositionInput): Promise<OrgPosition>;
  /** GET /internal/org/positions/{id}. */
  getPosition(id: string): Promise<OrgPosition>;
  /** GET /internal/org/positions?companyId=... — paginated. */
  listPositions(companyId: string, page?: number, pageSize?: number): Promise<Page<OrgPosition>>;
  /** PUT /internal/org/positions/{id}. */
  updatePosition(id: string, title: string, orgUnitId: string): Promise<OrgPosition>;
  /** DELETE /internal/org/positions/{id}. */
  deletePosition(id: string): Promise<{ id: string }>;
  /** GET /internal/org/positions/{positionId}/holder?date=... — who held the position on a date. */
  holderOnDate(positionId: string, date: string): Promise<OrgAssignment>;

  /** POST /internal/org/positions:create-and-assign — create a position and its first assignment
   * atomically. */
  createAndAssign(input: {
    companyId: string;
    code: string;
    title: string;
    orgUnitId: string;
    memberId: string;
    validFrom: string;
    validTo?: string | null;
  }): Promise<{ position: OrgPosition; assignment: OrgAssignment }>;
  /** POST /internal/org/assignments/{id}/end {validTo} — end a tenure on a specific date
   * (`OrgClient.adminEndAssignment` is the gateway-exposed, server-dated "end now" variant). */
  endAssignment(id: string, validTo: string): Promise<OrgAssignment>;
}

/** Builds an {@link InternalOrgClient} over `client`.
 * @internal */
export function createInternalOrgClient(client: ApiClient): InternalOrgClient {
  return {
    createUnit: (input) => client.request("/internal/org/units", { method: "POST", body: input }),
    getUnit: (id) => client.request(`/internal/org/units/${encodeURIComponent(id)}`),
    updateUnit: (id, input) =>
      client.request(`/internal/org/units/${encodeURIComponent(id)}`, { method: "PUT", body: input }),
    deleteUnit: (id) => client.request(`/internal/org/units/${encodeURIComponent(id)}`, { method: "DELETE" }),
    subtree: (id) => client.request(`/internal/org/units/${encodeURIComponent(id)}/subtree`),

    companyState: (companyId) => client.request(`/internal/org/companies/${encodeURIComponent(companyId)}/state`),
    memberByKcSub: (companyId, kcSub) =>
      client.request(
        `/internal/org/companies/${encodeURIComponent(companyId)}/members/by-kcsub/${encodeURIComponent(kcSub)}`
      ),

    createMember: (input) => client.request("/internal/org/members", { method: "POST", body: input }),
    getMember: (id) => client.request(`/internal/org/members/${encodeURIComponent(id)}`),
    listMembers: (companyId, page, pageSize) =>
      client.request("/internal/org/members", { query: { companyId, page, pageSize } }),
    updateMember: (id, input) =>
      client.request(`/internal/org/members/${encodeURIComponent(id)}`, { method: "PUT", body: input }),
    linkUser: (id, kcSub) =>
      client.request(`/internal/org/members/${encodeURIComponent(id)}/link-user`, {
        method: "POST",
        body: { kcSub }
      }),
    unlinkUser: (id) =>
      client.request(`/internal/org/members/${encodeURIComponent(id)}/link-user`, { method: "DELETE" }),

    createPosition: (input) => client.request("/internal/org/positions", { method: "POST", body: input }),
    getPosition: (id) => client.request(`/internal/org/positions/${encodeURIComponent(id)}`),
    listPositions: (companyId, page, pageSize) =>
      client.request("/internal/org/positions", { query: { companyId, page, pageSize } }),
    updatePosition: (id, title, orgUnitId) =>
      client.request(`/internal/org/positions/${encodeURIComponent(id)}`, {
        method: "PUT",
        body: { title, orgUnitId }
      }),
    deletePosition: (id) => client.request(`/internal/org/positions/${encodeURIComponent(id)}`, { method: "DELETE" }),
    holderOnDate: (positionId, date) =>
      client.request(`/internal/org/positions/${encodeURIComponent(positionId)}/holder`, { query: { date } }),

    createAndAssign: (input) =>
      client.request("/internal/org/positions:create-and-assign", { method: "POST", body: input }),
    endAssignment: (id, validTo) =>
      client.request(`/internal/org/assignments/${encodeURIComponent(id)}/end`, {
        method: "POST",
        body: { validTo }
      })
  };
}
