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

const { AllTicketsPage } = await import("../../../src/modules/helpdesk/all-tickets-page");

function context(companyId?: string): ModulePageContext {
  return { moduleKey: "helpdesk", companyId, featureKey: "helpdesk.access", params: {}, remoteExport: "AllTicketsPage" };
}

function ticket(overrides: Partial<Record<string, unknown>> = {}) {
  return {
    id: "ticket-1",
    companyId: "company-a",
    title: "Printer on fire",
    description: "help",
    status: "open",
    reporterMemberId: "member-reporter",
    assigneeMemberId: null,
    isReporter: false,
    isAssignee: false,
    createdAt: "2026-01-01T00:00:00Z",
    updatedAt: "2026-01-01T00:00:00Z",
    ...overrides,
  };
}

async function renderPage(companyId?: string) {
  const rootRoute = createRootRoute({ component: () => <AllTicketsPage context={context(companyId)} /> });
  const routeTree = rootRoute.addChildren([]);
  const router = createRouter({ routeTree, history: createMemoryHistory({ initialEntries: ["/app"] }) });
  await act(async () => {
    render(<RouterProvider router={router} />);
    await router.load();
  });
}

describe("AllTicketsPage", () => {
  beforeEach(() => {
    request.mockReset();
  });

  it("renders nothing without a companyId", async () => {
    await renderPage(undefined);
    expect(screen.queryByTestId("helpdesk-all-tickets-page")).not.toBeInTheDocument();
  });

  it("shows the denied state for a plain member (list request 403s)", async () => {
    request.mockImplementation((url: string) => {
      if (url.endsWith("/me")) return Promise.resolve({ tier: "member" });
      return Promise.reject(new Error("403"));
    });
    await renderPage("company-a");
    await waitFor(() => expect(screen.getByTestId("helpdesk-all-tickets-denied")).toBeInTheDocument());
  });

  it("lists every ticket for an agent, without an Assign button", async () => {
    request.mockImplementation((url: string) => {
      if (url.endsWith("/me")) return Promise.resolve({ tier: "agent" });
      if (url.includes("/tickets")) return Promise.resolve([ticket()]);
      return Promise.resolve(undefined);
    });
    await renderPage("company-a");
    await waitFor(() => expect(screen.getByText("Printer on fire")).toBeInTheDocument());
    expect(screen.queryByTestId("helpdesk-assign-ticket-1")).not.toBeInTheDocument();
  });

  // The assign sheet defaults to Positions FIRST. Note the URL matching below is deliberately
  // ORDER-SENSITIVE and specific:
  // "/assignable-positions" is itself a superstring of "/assign", so the assign-to-member/
  // assign-to-position branches must be checked with a trailing "/assign" match that does NOT
  // also match "/assignable-positions".
  it("defaults to the Positions tab and assigns to a position", async () => {
    const user = userEvent.setup();
    request.mockImplementation((url: string, opts?: { method?: string }) => {
      if (url.endsWith("/me")) return Promise.resolve({ tier: "admin" });
      if (url.endsWith("/assignable-positions")) {
        return Promise.resolve([{ positionId: "position-1", title: "Support Agent", holderDisplayName: "Alice" }]);
      }
      if (url.endsWith("/assign") && opts?.method === "POST") {
        return Promise.resolve(ticket({ assigneeKind: "position", assigneePositionId: "position-1" }));
      }
      if (url.includes("/tickets") && !opts?.method) return Promise.resolve([ticket()]);
      return Promise.resolve(undefined);
    });

    await renderPage("company-a");
    await waitFor(() => expect(screen.getByText("Printer on fire")).toBeInTheDocument());

    await user.click(screen.getByTestId("helpdesk-assign-ticket-1"));
    await waitFor(() => expect(screen.getByTestId("helpdesk-assign-sheet")).toBeInTheDocument());
    expect(screen.getByTestId("helpdesk-assign-tab-positions")).toHaveAttribute("aria-selected", "true");
    await waitFor(() => expect(screen.getByTestId("helpdesk-assign-to-position-position-1")).toBeInTheDocument());
    await user.click(screen.getByTestId("helpdesk-assign-to-position-position-1"));

    await waitFor(() =>
      expect(request).toHaveBeenCalledWith("/api/helpdesk/v1/companies/company-a/tickets/ticket-1/assign", {
        method: "POST",
        body: { assigneePositionId: "position-1" },
      }),
    );
  });

  // The Groups tab is the second in tab order (Positions · Groups · Members). Same
  // order-sensitive URL-matching caution as the Positions test above ("/assignable-groups" is a
  // superstring of neither "/assign" nor "/assignable-positions", but the assign-to-group POST
  // must still be distinguished from the plain member/position assign POSTs by request body).
  it("an admin can switch to the Groups tab and assign a ticket to a group", async () => {
    const user = userEvent.setup();
    request.mockImplementation((url: string, opts?: { method?: string; body?: Record<string, unknown> }) => {
      if (url.endsWith("/me")) return Promise.resolve({ tier: "admin" });
      if (url.endsWith("/assignable-positions")) return Promise.resolve([]);
      if (url.endsWith("/assignable-groups")) {
        return Promise.resolve([{ groupId: "group-1", title: "Support Team", memberCount: 2 }]);
      }
      if (url.endsWith("/assign") && opts?.method === "POST") {
        return Promise.resolve(ticket({ assigneeKind: "group", assigneeGroupId: "group-1" }));
      }
      if (url.includes("/tickets") && !opts?.method) return Promise.resolve([ticket()]);
      return Promise.resolve(undefined);
    });

    await renderPage("company-a");
    await waitFor(() => expect(screen.getByText("Printer on fire")).toBeInTheDocument());

    await user.click(screen.getByTestId("helpdesk-assign-ticket-1"));
    await waitFor(() => expect(screen.getByTestId("helpdesk-assign-sheet")).toBeInTheDocument());
    await user.click(screen.getByTestId("helpdesk-assign-tab-groups"));
    expect(screen.getByTestId("helpdesk-assign-tab-groups")).toHaveAttribute("aria-selected", "true");
    await waitFor(() => expect(screen.getByTestId("helpdesk-assign-to-group-group-1")).toBeInTheDocument());
    await user.click(screen.getByTestId("helpdesk-assign-to-group-group-1"));

    await waitFor(() =>
      expect(request).toHaveBeenCalledWith("/api/helpdesk/v1/companies/company-a/tickets/ticket-1/assign", {
        method: "POST",
        body: { assigneeGroupId: "group-1" },
      }),
    );
  });

  it("an admin can switch to the Members tab and assign a ticket through the member-picker", async () => {
    const user = userEvent.setup();
    request.mockImplementation((url: string, opts?: { method?: string }) => {
      if (url.endsWith("/me")) return Promise.resolve({ tier: "admin" });
      if (url.endsWith("/assignable-positions")) return Promise.resolve([]);
      if (url.endsWith("/assign") && opts?.method === "POST") return Promise.resolve(ticket({ assigneeMemberId: "member-1" }));
      if (url.includes("/api/org/companies/company-a/members")) {
        return Promise.resolve({
          items: [{ id: "member-1", displayName: "Bob", email: "bob@example.com", hasLinkedUser: true }],
          total: 1,
          page: 1,
          pageSize: 20,
          totalPages: 1,
        });
      }
      if (url.includes("/tickets") && !opts?.method) return Promise.resolve([ticket()]);
      return Promise.resolve(undefined);
    });

    await renderPage("company-a");
    await waitFor(() => expect(screen.getByText("Printer on fire")).toBeInTheDocument());

    await user.click(screen.getByTestId("helpdesk-assign-ticket-1"));
    await waitFor(() => expect(screen.getByTestId("helpdesk-assign-sheet")).toBeInTheDocument());
    await user.click(screen.getByTestId("helpdesk-assign-tab-members"));
    await user.type(screen.getByTestId("helpdesk-assign-member-search"), "Bob");
    await waitFor(() => expect(screen.getByTestId("helpdesk-assign-to-member-1")).toBeInTheDocument(), { timeout: 2000 });
    await user.click(screen.getByTestId("helpdesk-assign-to-member-1"));

    await waitFor(() =>
      expect(request).toHaveBeenCalledWith("/api/helpdesk/v1/companies/company-a/tickets/ticket-1/assign", {
        method: "POST",
        body: { assigneeMemberId: "member-1" },
      }),
    );
  });

  it("shows the assignee display name on each ticket row", async () => {
    request.mockImplementation((url: string) => {
      if (url.endsWith("/me")) return Promise.resolve({ tier: "admin" });
      if (url.includes("/tickets")) return Promise.resolve([ticket({ assigneeDisplayName: "Support Agent — held by Alice" })]);
      return Promise.resolve(undefined);
    });
    await renderPage("company-a");
    await waitFor(() => expect(screen.getByTestId("helpdesk-assignee-ticket-1")).toHaveTextContent("Assigned to Support Agent — held by Alice"));
  });

  it("filters by status", async () => {
    const user = userEvent.setup();
    request.mockImplementation((url: string, opts?: { query?: Record<string, unknown> }) => {
      if (url.endsWith("/me")) return Promise.resolve({ tier: "admin" });
      if (url.includes("/tickets")) return Promise.resolve([]);
      return Promise.resolve(undefined);
    });
    await renderPage("company-a");
    await waitFor(() => expect(screen.getByTestId("helpdesk-all-tickets-page")).toBeInTheDocument());
    await user.click(screen.getByTestId("helpdesk-status-filter-resolved"));
    await waitFor(() =>
      expect(request).toHaveBeenCalledWith("/api/helpdesk/v1/companies/company-a/tickets", {
        query: { view: "all", status: "resolved" },
      }),
    );
  });

  it("a transition button fires the status API and reloads", async () => {
    const user = userEvent.setup();
    let status = "in_progress";
    request.mockImplementation((url: string, opts?: { method?: string }) => {
      if (url.endsWith("/me")) return Promise.resolve({ tier: "admin" });
      if (url.includes("/status") && opts?.method === "POST") return Promise.resolve(ticket({ status: "resolved" }));
      if (url.includes("/tickets")) return Promise.resolve([ticket({ status })]);
      return Promise.resolve(undefined);
    });
    await renderPage("company-a");
    await waitFor(() => expect(screen.getByTestId("helpdesk-transition-ticket-1-resolved")).toBeInTheDocument());
    await user.click(screen.getByTestId("helpdesk-transition-ticket-1-resolved"));
    await waitFor(() =>
      expect(request).toHaveBeenCalledWith("/api/helpdesk/v1/companies/company-a/tickets/ticket-1/status", {
        method: "POST",
        body: { status: "resolved" },
      }),
    );
  });
});
