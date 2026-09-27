// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it, vi } from "vitest";
import { createHelpdeskClient } from "../../../src/modules/helpdesk/api";

function fakeClient() {
  return { baseUrl: "https://gw.example", request: vi.fn().mockResolvedValue(undefined) };
}

describe("createHelpdeskClient", () => {
  it("gets the caller's own tier", async () => {
    const client = fakeClient();
    client.request.mockResolvedValue({ tier: "admin" });
    const tier = await createHelpdeskClient(client).myTier("company-a");
    expect(client.request).toHaveBeenCalledWith("/api/helpdesk/v1/companies/company-a/me");
    expect(tier).toBe("admin");
  });

  it("lists tickets with view and optional status query params", async () => {
    const client = fakeClient();
    await createHelpdeskClient(client).listTickets("company-a", "all", "open");
    expect(client.request).toHaveBeenCalledWith("/api/helpdesk/v1/companies/company-a/tickets", {
      query: { view: "all", status: "open" },
    });
  });

  it("creates a ticket via POST with the input as the body", async () => {
    const client = fakeClient();
    const input = { title: "T", description: "D" };
    await createHelpdeskClient(client).createTicket("company-a", input);
    expect(client.request).toHaveBeenCalledWith("/api/helpdesk/v1/companies/company-a/tickets", {
      method: "POST",
      body: input,
    });
  });

  it("gets a single ticket", async () => {
    const client = fakeClient();
    await createHelpdeskClient(client).getTicket("company-a", "ticket-1");
    expect(client.request).toHaveBeenCalledWith("/api/helpdesk/v1/companies/company-a/tickets/ticket-1");
  });

  it("gets a ticket's audit trail", async () => {
    const client = fakeClient();
    await createHelpdeskClient(client).getTicketAudit("company-a", "ticket-1");
    expect(client.request).toHaveBeenCalledWith("/api/helpdesk/v1/companies/company-a/tickets/ticket-1/audit");
  });

  it("assigns a ticket via POST with assigneeMemberId as the body", async () => {
    const client = fakeClient();
    await createHelpdeskClient(client).assignTicket("company-a", "ticket-1", "member-1");
    expect(client.request).toHaveBeenCalledWith("/api/helpdesk/v1/companies/company-a/tickets/ticket-1/assign", {
      method: "POST",
      body: { assigneeMemberId: "member-1" },
    });
  });

  it("transitions status via POST with status as the body", async () => {
    const client = fakeClient();
    await createHelpdeskClient(client).transitionStatus("company-a", "ticket-1", "in_progress");
    expect(client.request).toHaveBeenCalledWith("/api/helpdesk/v1/companies/company-a/tickets/ticket-1/status", {
      method: "POST",
      body: { status: "in_progress" },
    });
  });

  it("lists a ticket's comments", async () => {
    const client = fakeClient();
    await createHelpdeskClient(client).listComments("company-a", "ticket-1");
    expect(client.request).toHaveBeenCalledWith("/api/helpdesk/v1/companies/company-a/tickets/ticket-1/comments");
  });

  it("creates a comment via POST with body wrapped as {body}", async () => {
    const client = fakeClient();
    await createHelpdeskClient(client).createComment("company-a", "ticket-1", "hello");
    expect(client.request).toHaveBeenCalledWith("/api/helpdesk/v1/companies/company-a/tickets/ticket-1/comments", {
      method: "POST",
      body: { body: "hello" },
    });
  });

  it("lists agents", async () => {
    const client = fakeClient();
    await createHelpdeskClient(client).listAgents("company-a");
    expect(client.request).toHaveBeenCalledWith("/api/helpdesk/v1/companies/company-a/agents");
  });

  it("makes an agent via POST with memberId as the body", async () => {
    const client = fakeClient();
    await createHelpdeskClient(client).makeAgent("company-a", "member-1");
    expect(client.request).toHaveBeenCalledWith("/api/helpdesk/v1/companies/company-a/agents", {
      method: "POST",
      body: { memberId: "member-1" },
    });
  });

  it("removes an agent via DELETE to the member's own sub-resource", async () => {
    const client = fakeClient();
    await createHelpdeskClient(client).removeAgent("company-a", "member-1");
    expect(client.request).toHaveBeenCalledWith("/api/helpdesk/v1/companies/company-a/agents/member-1", {
      method: "DELETE",
    });
  });

  it("URI-encodes path segments", async () => {
    const client = fakeClient();
    await createHelpdeskClient(client).getTicket("company a/b", "ticket 1");
    expect(client.request).toHaveBeenCalledWith("/api/helpdesk/v1/companies/company%20a%2Fb/tickets/ticket%201");
  });
});
