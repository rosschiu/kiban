// SPDX-License-Identifier: Apache-2.0

import { createMemoryHistory, createRootRoute, createRouter, RouterProvider } from "@tanstack/react-router";
import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { ModulePageContext } from "../../../src/resolver/resolver";

const request = vi.fn();
vi.mock("../../../src/auth/sdk", () => ({
  getShellSdk: () => ({ apiClient: { baseUrl: "https://gw.example", request } }),
}));

const { TicketDetailPage } = await import("../../../src/modules/helpdesk/ticket-detail-page");

function context(companyId?: string, ticketId?: string): ModulePageContext {
  return {
    moduleKey: "helpdesk",
    companyId,
    featureKey: "helpdesk.access",
    params: ticketId ? { ticketId } : {},
    remoteExport: "TicketDetailPage",
  };
}

function ticket(overrides: Partial<Record<string, unknown>> = {}) {
  return {
    id: "ticket-1",
    companyId: "company-a",
    title: "Printer on fire",
    description: "Send help",
    status: "open",
    reporterMemberId: "member-reporter",
    assigneeMemberId: "member-assignee",
    isReporter: false,
    isAssignee: true,
    createdAt: "2026-01-01T00:00:00Z",
    updatedAt: "2026-01-01T00:00:00Z",
    ...overrides,
  };
}

async function renderPage(companyId?: string, ticketId?: string) {
  const rootRoute = createRootRoute({ component: () => <TicketDetailPage context={context(companyId, ticketId)} /> });
  const routeTree = rootRoute.addChildren([]);
  const router = createRouter({ routeTree, history: createMemoryHistory({ initialEntries: ["/app"] }) });
  await act(async () => {
    render(<RouterProvider router={router} />);
    await router.load();
  });
}

function mockAll(t: ReturnType<typeof ticket>, audit: unknown[] = [], comments: unknown[] = []) {
  request.mockImplementation((url: string) => {
    if (url.endsWith("/me")) return Promise.resolve({ tier: "agent" });
    if (url.endsWith("/audit")) return Promise.resolve(audit);
    if (url.endsWith("/comments")) return Promise.resolve(comments);
    if (url.endsWith("/tickets/ticket-1")) return Promise.resolve(t);
    return Promise.resolve(undefined);
  });
}

describe("TicketDetailPage", () => {
  beforeEach(() => {
    request.mockReset();
  });

  it("renders nothing without a companyId or ticketId", async () => {
    await renderPage(undefined, "ticket-1");
    expect(screen.queryByTestId("helpdesk-ticket-detail-page")).not.toBeInTheDocument();
    await renderPage("company-a", undefined);
    expect(screen.queryByTestId("helpdesk-ticket-detail-page")).not.toBeInTheDocument();
  });

  it("shows the denied state when the ticket load fails", async () => {
    request.mockImplementation((url: string) => {
      if (url.endsWith("/me")) return Promise.resolve({ tier: "member" });
      return Promise.reject(new Error("403"));
    });
    await renderPage("company-a", "ticket-1");
    await waitFor(() => expect(screen.getByTestId("helpdesk-ticket-denied")).toBeInTheDocument());
  });

  it("shows title, description, and status chip", async () => {
    mockAll(ticket());
    await renderPage("company-a", "ticket-1");
    await waitFor(() => expect(screen.getByTestId("helpdesk-ticket-title")).toHaveTextContent("Printer on fire"));
    expect(screen.getByTestId("helpdesk-ticket-description")).toHaveTextContent("Send help");
    expect(screen.getByTestId("helpdesk-status-chip-open")).toBeInTheDocument();
  });

  it("the assignee sees the progress action and can trigger it", async () => {
    const user = userEvent.setup();
    mockAll(ticket());
    request.mockImplementation((url: string, opts?: { method?: string }) => {
      if (url.endsWith("/me")) return Promise.resolve({ tier: "agent" });
      if (url.endsWith("/audit")) return Promise.resolve([]);
      if (url.endsWith("/comments")) return Promise.resolve([]);
      if (url.includes("/status") && opts?.method === "POST") return Promise.resolve(ticket({ status: "in_progress" }));
      if (url.endsWith("/tickets/ticket-1")) return Promise.resolve(ticket());
      return Promise.resolve(undefined);
    });
    await renderPage("company-a", "ticket-1");
    await waitFor(() => expect(screen.getByTestId("helpdesk-transition-in_progress")).toBeInTheDocument());
    await user.click(screen.getByTestId("helpdesk-transition-in_progress"));
    await waitFor(() =>
      expect(request).toHaveBeenCalledWith("/api/helpdesk/v1/companies/company-a/tickets/ticket-1/status", {
        method: "POST",
        body: { status: "in_progress" },
      }),
    );
  });

  it("a non-assignee, non-admin sees no actions on an open ticket", async () => {
    mockAll(ticket({ isAssignee: false, isReporter: false }));
    request.mockImplementation((url: string) => {
      if (url.endsWith("/me")) return Promise.resolve({ tier: "member" });
      if (url.endsWith("/audit")) return Promise.resolve([]);
      if (url.endsWith("/comments")) return Promise.resolve([]);
      if (url.endsWith("/tickets/ticket-1")) return Promise.resolve(ticket({ isAssignee: false, isReporter: false }));
      return Promise.resolve(undefined);
    });
    await renderPage("company-a", "ticket-1");
    await waitFor(() => expect(screen.getByTestId("helpdesk-ticket-detail-page")).toBeInTheDocument());
    expect(screen.queryByTestId("helpdesk-ticket-actions")).not.toBeInTheDocument();
  });

  it("posts a comment and reloads the thread", async () => {
    const user = userEvent.setup();
    let comments: unknown[] = [];
    request.mockImplementation((url: string, opts?: { method?: string }) => {
      if (url.endsWith("/me")) return Promise.resolve({ tier: "agent" });
      if (url.endsWith("/audit")) return Promise.resolve([]);
      if (url.endsWith("/comments") && opts?.method === "POST") {
        comments = [{ id: "c-1", ticketId: "ticket-1", authorKcSub: "agent", body: "on it", createdAt: "2026-01-01T00:00:00Z" }];
        return Promise.resolve(comments[0]);
      }
      if (url.endsWith("/comments")) return Promise.resolve(comments);
      if (url.endsWith("/tickets/ticket-1")) return Promise.resolve(ticket());
      return Promise.resolve(undefined);
    });
    await renderPage("company-a", "ticket-1");
    await waitFor(() => expect(screen.getByTestId("helpdesk-ticket-detail-page")).toBeInTheDocument());

    await user.type(screen.getByTestId("helpdesk-comment-input"), "on it");
    await user.click(screen.getByTestId("helpdesk-comment-submit"));

    await waitFor(() =>
      expect(request).toHaveBeenCalledWith("/api/helpdesk/v1/companies/company-a/tickets/ticket-1/comments", {
        method: "POST",
        body: { body: "on it" },
      }),
    );
    await waitFor(() => expect(screen.getByText("on it")).toBeInTheDocument());
  });

  it("shows the status timeline built from audit events", async () => {
    mockAll(ticket(), [
      { occurredAt: "2026-01-01T00:00:00Z", actor: "alice", action: "helpdesk.ticket.create", subject: "helpdesk_ticket:ticket-1", payload: {} },
      {
        occurredAt: "2026-01-01T01:00:00Z",
        actor: "carol-admin",
        action: "helpdesk.ticket.status",
        subject: "helpdesk_ticket:ticket-1",
        payload: { from: "open", to: "in_progress" },
      },
    ]);
    await renderPage("company-a", "ticket-1");
    await waitFor(() => expect(screen.getByText("alice raised this ticket")).toBeInTheDocument());
    expect(screen.getByText("carol-admin changed status: open → in_progress")).toBeInTheDocument();
  });
});
