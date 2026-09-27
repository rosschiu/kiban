// SPDX-License-Identifier: Apache-2.0

// Thin, hand-written client for the helpdesk module's own HTTP surface (modules/helpdesk/
// openapi.yaml), built directly on the shared @rosschiu/kiban-sdk `ApiClient` — same pattern as
// web/shell/src/modules/{notification,timesheet,docs}/api.ts (a module's own
// API surface is the module's own concern, never added to the shared SDK package).
import type { ApiClient } from "@rosschiu/kiban-sdk";

export type TicketStatus = "open" | "in_progress" | "resolved" | "closed";
export type HelpdeskTier = "member" | "agent" | "admin";

export type AssigneeKind = "member" | "position" | "group" | "";

export interface HelpdeskTicket {
  id: string;
  companyId: string;
  title: string;
  description: string;
  status: TicketStatus;
  reporterMemberId: string;
  assigneeMemberId?: string | null;
  /** Which of the three assignee shapes this ticket carries ("" = unassigned). */
  assigneeKind?: AssigneeKind;
  assigneePositionId?: string | null;
  assigneePositionTitle?: string | null;
  /** The group assignee shape — a group has MANY members, not one holder. */
  assigneeGroupId?: string | null;
  assigneeGroupTitle?: string | null;
  /** Server-resolved — a member's displayName, "<title> — held by <holder>" (or
   * just "<title>" if currently unheld) for a position-assigned ticket, or "<name> (N
   * member(s))" for a group-assigned ticket — the browser has no non-superadmin positions/groups
   * route of its own. */
  assigneeDisplayName?: string | null;
  myTier?: HelpdeskTier;
  isReporter: boolean;
  isAssignee: boolean;
  createdAt: string;
  updatedAt: string;
}

// The non-superadmin read the assign sheet (Positions-first) and the agents-admin
// holder-name display both need — agent-BOUND positions only (this module's own index), never the
// org chart at large (least disclosure).
export interface AssignablePosition {
  positionId: string;
  title: string;
  holderMemberId?: string | null;
  holderDisplayName?: string | null;
}

// The group sibling of AssignablePosition — a group has MANY members, so this carries
// a member COUNT rather than a single holder name.
export interface AssignableGroup {
  groupId: string;
  title: string;
  memberCount: number;
}

export interface HelpdeskComment {
  id: string;
  ticketId: string;
  authorKcSub: string;
  body: string;
  createdAt: string;
}

export interface HelpdeskAuditEvent {
  occurredAt: string;
  actor: string;
  action: string;
  subject: string;
  payload: Record<string, unknown>;
}

// An agent binding is EXACTLY ONE of a per-member, per-position,
// or per-group row — bindingKind tells the UI which; the position/group paths carry a
// title snapshot for display (org's own title/name at bind time, not live-refreshed).
export interface HelpdeskAgent {
  id: string;
  companyId: string;
  bindingKind: "member" | "position" | "group";
  memberId?: string;
  positionId?: string;
  positionTitle?: string;
  groupId?: string;
  groupTitle?: string;
  grantedBy: string;
  createdAt: string;
}

export interface HelpdeskClient {
  myTier(companyId: string): Promise<HelpdeskTier>;
  listTickets(companyId: string, view: "mine" | "all", status?: TicketStatus): Promise<HelpdeskTicket[]>;
  createTicket(companyId: string, input: { title: string; description: string }): Promise<HelpdeskTicket>;
  getTicket(companyId: string, ticketId: string): Promise<HelpdeskTicket>;
  getTicketAudit(companyId: string, ticketId: string): Promise<HelpdeskAuditEvent[]>;
  assignTicket(companyId: string, ticketId: string, assigneeMemberId: string): Promise<HelpdeskTicket>;
  /** Assign a ticket to a POSITION rather than a member — "the current holder of this
   * chair works this ticket", resolved at read time, never snapshotted. The position must
   * already be bound as a helpdesk agent (422 otherwise). */
  assignTicketToPosition(companyId: string, ticketId: string, assigneePositionId: string): Promise<HelpdeskTicket>;
  /** Assign a ticket to a GROUP — "the current MEMBERS of this group work this ticket",
   * resolved at read time, never snapshotted. The group must already be bound as a helpdesk
   * agent (422 otherwise). */
  assignTicketToGroup(companyId: string, ticketId: string, assigneeGroupId: string): Promise<HelpdeskTicket>;
  /** The assign target set — agent-bound positions with their current holder. */
  listAssignablePositions(companyId: string): Promise<AssignablePosition[]>;
  /** The group sibling — agent-bound groups with their current member count. */
  listAssignableGroups(companyId: string): Promise<AssignableGroup[]>;
  transitionStatus(companyId: string, ticketId: string, status: TicketStatus): Promise<HelpdeskTicket>;
  listComments(companyId: string, ticketId: string): Promise<HelpdeskComment[]>;
  createComment(companyId: string, ticketId: string, body: string): Promise<HelpdeskComment>;
  listAgents(companyId: string): Promise<HelpdeskAgent[]>;
  makeAgent(companyId: string, memberId: string): Promise<HelpdeskAgent>;
  /** Binds the agent tier to a POSITION rather than a member (the
   * `{positionId}` variant of POST /agents) — successor inherits the position's access, zero
   * permission edits on handover. */
  makeAgentForPosition(companyId: string, positionId: string): Promise<HelpdeskAgent>;
  /** Binds the agent tier to a GROUP (the `{groupId}` variant of POST
   * /agents) — every CURRENT member inherits the tier, zero permission edits as membership
   * changes. */
  makeAgentForGroup(companyId: string, groupId: string): Promise<HelpdeskAgent>;
  removeAgent(companyId: string, memberId: string): Promise<void>;
  /** DELETE /agents/positions/{positionId} — the unambiguous position-revoke route,
   * never overloaded onto removeAgent's per-member path. */
  removeAgentForPosition(companyId: string, positionId: string): Promise<void>;
  /** DELETE /agents/groups/{groupId} — the group sibling of removeAgentForPosition. */
  removeAgentForGroup(companyId: string, groupId: string): Promise<void>;
}

function base(companyId: string): string {
  return `/api/helpdesk/v1/companies/${encodeURIComponent(companyId)}`;
}

export function createHelpdeskClient(client: ApiClient): HelpdeskClient {
  return {
    myTier: async (companyId) => {
      const res = await client.request<{ tier: HelpdeskTier }>(`${base(companyId)}/me`);
      return res.tier;
    },

    listTickets: (companyId, view, status) =>
      client.request(`${base(companyId)}/tickets`, { query: { view, status } }),

    createTicket: (companyId, input) => client.request(`${base(companyId)}/tickets`, { method: "POST", body: input }),

    getTicket: (companyId, ticketId) => client.request(`${base(companyId)}/tickets/${encodeURIComponent(ticketId)}`),

    getTicketAudit: (companyId, ticketId) => client.request(`${base(companyId)}/tickets/${encodeURIComponent(ticketId)}/audit`),

    assignTicket: (companyId, ticketId, assigneeMemberId) =>
      client.request(`${base(companyId)}/tickets/${encodeURIComponent(ticketId)}/assign`, {
        method: "POST",
        body: { assigneeMemberId }
      }),

    assignTicketToPosition: (companyId, ticketId, assigneePositionId) =>
      client.request(`${base(companyId)}/tickets/${encodeURIComponent(ticketId)}/assign`, {
        method: "POST",
        body: { assigneePositionId }
      }),

    assignTicketToGroup: (companyId, ticketId, assigneeGroupId) =>
      client.request(`${base(companyId)}/tickets/${encodeURIComponent(ticketId)}/assign`, {
        method: "POST",
        body: { assigneeGroupId }
      }),

    listAssignablePositions: (companyId) => client.request(`${base(companyId)}/assignable-positions`),

    listAssignableGroups: (companyId) => client.request(`${base(companyId)}/assignable-groups`),

    transitionStatus: (companyId, ticketId, status) =>
      client.request(`${base(companyId)}/tickets/${encodeURIComponent(ticketId)}/status`, { method: "POST", body: { status } }),

    listComments: (companyId, ticketId) => client.request(`${base(companyId)}/tickets/${encodeURIComponent(ticketId)}/comments`),

    createComment: (companyId, ticketId, body) =>
      client.request(`${base(companyId)}/tickets/${encodeURIComponent(ticketId)}/comments`, { method: "POST", body: { body } }),

    listAgents: (companyId) => client.request(`${base(companyId)}/agents`),

    makeAgent: (companyId, memberId) => client.request(`${base(companyId)}/agents`, { method: "POST", body: { memberId } }),

    makeAgentForPosition: (companyId, positionId) =>
      client.request(`${base(companyId)}/agents`, { method: "POST", body: { positionId } }),

    makeAgentForGroup: (companyId, groupId) =>
      client.request(`${base(companyId)}/agents`, { method: "POST", body: { groupId } }),

    removeAgent: (companyId, memberId) =>
      client.request(`${base(companyId)}/agents/${encodeURIComponent(memberId)}`, { method: "DELETE" }),

    removeAgentForPosition: (companyId, positionId) =>
      client.request(`${base(companyId)}/agents/positions/${encodeURIComponent(positionId)}`, { method: "DELETE" }),

    removeAgentForGroup: (companyId, groupId) =>
      client.request(`${base(companyId)}/agents/groups/${encodeURIComponent(groupId)}`, { method: "DELETE" })
  };
}
