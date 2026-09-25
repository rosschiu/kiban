// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it, vi } from "vitest";
import { createTimesheetClient } from "../../../src/modules/timesheet/api";

function fakeClient() {
  return { baseUrl: "https://gw.example", request: vi.fn().mockResolvedValue(undefined) };
}

describe("createTimesheetClient", () => {
  it("lists projects with pagination query params", async () => {
    const client = fakeClient();
    await createTimesheetClient(client).listProjects("company-a", 2, 25);
    expect(client.request).toHaveBeenCalledWith("/api/timesheet/v1/companies/company-a/projects", {
      query: { page: 2, pageSize: 25 },
    });
  });

  it("creates a project via POST with the input as the body", async () => {
    const client = fakeClient();
    const input = { code: "PRJ1", name: "Project One" };
    await createTimesheetClient(client).createProject("company-a", input);
    expect(client.request).toHaveBeenCalledWith("/api/timesheet/v1/companies/company-a/projects", {
      method: "POST",
      body: input,
    });
  });

  it("lists entries for a week", async () => {
    const client = fakeClient();
    await createTimesheetClient(client).listEntries("company-a", "2026-08-10");
    expect(client.request).toHaveBeenCalledWith("/api/timesheet/v1/companies/company-a/entries", {
      query: { weekStart: "2026-08-10" },
    });
  });

  it("upserts an entry via POST with the input as the body", async () => {
    const client = fakeClient();
    const input = { projectId: "p1", entryDate: "2026-08-10", realHours: 8, billableHours: 6 };
    await createTimesheetClient(client).upsertEntry("company-a", input);
    expect(client.request).toHaveBeenCalledWith("/api/timesheet/v1/companies/company-a/entries", {
      method: "POST",
      body: input,
    });
  });

  it("deletes an entry via DELETE", async () => {
    const client = fakeClient();
    await createTimesheetClient(client).deleteEntry("company-a", "entry-1");
    expect(client.request).toHaveBeenCalledWith("/api/timesheet/v1/companies/company-a/entries/entry-1", {
      method: "DELETE",
    });
  });

  it("submits a week without an Idempotency-Key header when none is given", async () => {
    const client = fakeClient();
    await createTimesheetClient(client).submitWeek("company-a", "2026-08-10");
    expect(client.request).toHaveBeenCalledWith("/api/timesheet/v1/companies/company-a/submissions", {
      method: "POST",
      body: { weekStart: "2026-08-10" },
    });
  });

  it("submits a week with an Idempotency-Key header when given", async () => {
    const client = fakeClient();
    await createTimesheetClient(client).submitWeek("company-a", "2026-08-10", "idem-1");
    expect(client.request).toHaveBeenCalledWith("/api/timesheet/v1/companies/company-a/submissions", {
      method: "POST",
      body: { weekStart: "2026-08-10" },
      headers: { "Idempotency-Key": "idem-1" },
    });
  });

  it("lists submissions with scope and pagination query params", async () => {
    const client = fakeClient();
    await createTimesheetClient(client).listSubmissions("company-a", "approvals", 1, 25);
    expect(client.request).toHaveBeenCalledWith("/api/timesheet/v1/companies/company-a/submissions", {
      query: { view: "approvals", page: 1, pageSize: 25 },
    });
  });

  it("approves a submission via POST to its /approve sub-resource", async () => {
    const client = fakeClient();
    await createTimesheetClient(client).approveSubmission("company-a", "sub-1");
    expect(client.request).toHaveBeenCalledWith("/api/timesheet/v1/companies/company-a/submissions/sub-1/approve", {
      method: "POST",
    });
  });

  it("rejects a submission via POST with the reason as the body", async () => {
    const client = fakeClient();
    await createTimesheetClient(client).rejectSubmission("company-a", "sub-1", "wrong hours");
    expect(client.request).toHaveBeenCalledWith("/api/timesheet/v1/companies/company-a/submissions/sub-1/reject", {
      method: "POST",
      body: { reason: "wrong hours" },
    });
  });

  it("lists approvers with pagination query params", async () => {
    const client = fakeClient();
    await createTimesheetClient(client).listApprovers("company-a", 1, 25);
    expect(client.request).toHaveBeenCalledWith("/api/timesheet/v1/companies/company-a/approvers", {
      query: { page: 1, pageSize: 25 },
    });
  });

  it("assigns an approver via POST with memberId/approverMemberId as the body", async () => {
    const client = fakeClient();
    await createTimesheetClient(client).assignApprover("company-a", "m1", "m2");
    expect(client.request).toHaveBeenCalledWith("/api/timesheet/v1/companies/company-a/approvers", {
      method: "POST",
      body: { memberId: "m1", approverMemberId: "m2" },
    });
  });

  it("URI-encodes path segments", async () => {
    const client = fakeClient();
    await createTimesheetClient(client).deleteEntry("company a/b", "entry 1");
    expect(client.request).toHaveBeenCalledWith("/api/timesheet/v1/companies/company%20a%2Fb/entries/entry%201", {
      method: "DELETE",
    });
  });
});
