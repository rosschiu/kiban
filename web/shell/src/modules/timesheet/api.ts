// SPDX-License-Identifier: Apache-2.0

// Thin, hand-written client for the timesheet module's own HTTP surface
// (modules/timesheet/openapi.yaml), built on the shared @rosschiu/kiban-sdk `ApiClient` — same pattern as
// web/shell/src/modules/notification/api.ts (no SDK change needed).
import type { ApiClient, Page } from "@rosschiu/kiban-sdk";

export interface TimesheetProject {
  id: string;
  companyId: string;
  code: string;
  name: string;
  status: "active" | "inactive";
}

export interface TimesheetEntry {
  id: string;
  companyId: string;
  memberId: string;
  projectId: string;
  entryDate: string;
  realHours: number;
  billableHours: number;
  status: "draft" | "submitted" | "approved" | "rejected";
}

export interface TimesheetSubmission {
  id: string;
  companyId: string;
  memberId: string;
  weekStart: string;
  versionNumber: number;
  rootId: string;
  supersedesId: string | null;
  isCurrent: boolean;
  status: "submitted" | "approved" | "rejected";
  assignedApproverMemberId: string;
  rejectReason: string | null;
  permissions: { canApprove: boolean; canReject: boolean; canRevert: boolean };
}

export interface TimesheetApproverAssignment {
  companyId: string;
  memberId: string;
  approverMemberId: string;
  assignedAt: string;
}

function companyBase(companyId: string): string {
  return `/api/timesheet/v1/companies/${encodeURIComponent(companyId)}`;
}

export interface TimesheetClient {
  listProjects(companyId: string, page?: number, pageSize?: number): Promise<Page<TimesheetProject>>;
  createProject(companyId: string, input: { code: string; name: string }): Promise<TimesheetProject>;
  listEntries(companyId: string, weekStart: string): Promise<{ items: TimesheetEntry[] }>;
  upsertEntry(
    companyId: string,
    input: { projectId: string; entryDate: string; realHours: number; billableHours: number },
  ): Promise<TimesheetEntry>;
  deleteEntry(companyId: string, entryId: string): Promise<void>;
  submitWeek(companyId: string, weekStart: string, idempotencyKey?: string): Promise<TimesheetSubmission>;
  listSubmissions(
    companyId: string,
    scope: "mine" | "approvals" | "all",
    page?: number,
    pageSize?: number,
  ): Promise<Page<TimesheetSubmission>>;
  approveSubmission(companyId: string, submissionId: string): Promise<TimesheetSubmission>;
  rejectSubmission(companyId: string, submissionId: string, reason: string): Promise<TimesheetSubmission>;
  listApprovers(companyId: string, page?: number, pageSize?: number): Promise<Page<TimesheetApproverAssignment>>;
  assignApprover(companyId: string, memberId: string, approverMemberId: string): Promise<TimesheetApproverAssignment>;
}

export function createTimesheetClient(client: ApiClient): TimesheetClient {
  return {
    listProjects: (companyId, page, pageSize) => client.request(`${companyBase(companyId)}/projects`, { query: { page, pageSize } }),

    createProject: (companyId, input) => client.request(`${companyBase(companyId)}/projects`, { method: "POST", body: input }),

    listEntries: (companyId, weekStart) => client.request(`${companyBase(companyId)}/entries`, { query: { weekStart } }),

    upsertEntry: (companyId, input) => client.request(`${companyBase(companyId)}/entries`, { method: "POST", body: input }),

    deleteEntry: (companyId, entryId) =>
      client.request(`${companyBase(companyId)}/entries/${encodeURIComponent(entryId)}`, { method: "DELETE" }),

    submitWeek: (companyId, weekStart, idempotencyKey) =>
      client.request(`${companyBase(companyId)}/submissions`, {
        method: "POST",
        body: { weekStart },
        ...(idempotencyKey ? { headers: { "Idempotency-Key": idempotencyKey } } : {}),
      }),

    listSubmissions: (companyId, scope, page, pageSize) =>
      client.request(`${companyBase(companyId)}/submissions`, { query: { view: scope, page, pageSize } }),

    approveSubmission: (companyId, submissionId) =>
      client.request(`${companyBase(companyId)}/submissions/${encodeURIComponent(submissionId)}/approve`, { method: "POST" }),

    rejectSubmission: (companyId, submissionId, reason) =>
      client.request(`${companyBase(companyId)}/submissions/${encodeURIComponent(submissionId)}/reject`, {
        method: "POST",
        body: { reason },
      }),

    listApprovers: (companyId, page, pageSize) => client.request(`${companyBase(companyId)}/approvers`, { query: { page, pageSize } }),

    assignApprover: (companyId, memberId, approverMemberId) =>
      client.request(`${companyBase(companyId)}/approvers`, { method: "POST", body: { memberId, approverMemberId } }),
  };
}
