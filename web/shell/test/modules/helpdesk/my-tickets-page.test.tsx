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

const { MyTicketsPage } = await import("../../../src/modules/helpdesk/my-tickets-page");

function context(companyId?: string): ModulePageContext {
  return { moduleKey: "helpdesk", companyId, featureKey: "helpdesk.access", params: {}, remoteExport: "MyTicketsPage" };
}

function ticket(overrides: Partial<Record<string, unknown>> = {}) {
  return {
    id: "ticket-1",
    companyId: "company-a",
    title: "Printer on fire",
    description: "help",
    status: "open",
    reporterMemberId: "member-1",
    isReporter: true,
    isAssignee: false,
    createdAt: "2026-01-01T00:00:00Z",
    updatedAt: "2026-01-01T00:00:00Z",
    ...overrides,
  };
}

async function renderPage(companyId?: string) {
  const rootRoute = createRootRoute({ component: () => <MyTicketsPage context={context(companyId)} /> });
  const routeTree = rootRoute.addChildren([]);
  const router = createRouter({ routeTree, history: createMemoryHistory({ initialEntries: ["/app"] }) });
  await act(async () => {
    render(<RouterProvider router={router} />);
    await router.load();
  });
}

function mockTierAnd(tickets: unknown[]) {
  request.mockImplementation((url: string) => {
    if (url.endsWith("/me")) return Promise.resolve({ tier: "member" });
    if (url.endsWith("/tickets")) return Promise.resolve(tickets);
    return Promise.resolve(undefined);
  });
}

describe("MyTicketsPage", () => {
  beforeEach(() => {
    request.mockReset();
  });

  it("renders nothing without a companyId", async () => {
    await renderPage(undefined);
    expect(screen.queryByTestId("helpdesk-my-tickets-page")).not.toBeInTheDocument();
  });

  it("shows an empty state with no tickets, and hides All Tickets/Agents nav for a plain member", async () => {
    mockTierAnd([]);
    await renderPage("company-a");
    await waitFor(() => expect(screen.getByText("No tickets yet")).toBeInTheDocument());
    expect(screen.getByTestId("helpdesk-nav-my-tickets")).toBeInTheDocument();
    expect(screen.queryByTestId("helpdesk-nav-all-tickets")).not.toBeInTheDocument();
    expect(screen.queryByTestId("helpdesk-nav-agents")).not.toBeInTheDocument();
  });

  it("shows the All Tickets nav for an agent, and Agents nav for an admin", async () => {
    request.mockImplementation((url: string) => {
      if (url.endsWith("/me")) return Promise.resolve({ tier: "agent" });
      if (url.endsWith("/tickets")) return Promise.resolve([]);
      return Promise.resolve(undefined);
    });
    await renderPage("company-a");
    await waitFor(() => expect(screen.getByTestId("helpdesk-nav-all-tickets")).toBeInTheDocument());
    expect(screen.queryByTestId("helpdesk-nav-agents")).not.toBeInTheDocument();

    request.mockImplementation((url: string) => {
      if (url.endsWith("/me")) return Promise.resolve({ tier: "admin" });
      if (url.endsWith("/tickets")) return Promise.resolve([]);
      return Promise.resolve(undefined);
    });
    await renderPage("company-a");
    await waitFor(() => expect(screen.getByTestId("helpdesk-nav-agents")).toBeInTheDocument());
  });

  it("lists the caller's own tickets with a status chip", async () => {
    mockTierAnd([ticket()]);
    await renderPage("company-a");
    await waitFor(() => expect(screen.getByText("Printer on fire")).toBeInTheDocument());
    expect(screen.getByTestId("helpdesk-status-chip-open")).toBeInTheDocument();
  });

  it("raises a new ticket and reloads the list", async () => {
    const user = userEvent.setup();
    let created = false;
    request.mockImplementation((url: string, opts?: { method?: string }) => {
      if (url.endsWith("/me")) return Promise.resolve({ tier: "member" });
      if (url.endsWith("/tickets") && opts?.method === "POST") {
        created = true;
        return Promise.resolve(ticket());
      }
      if (url.endsWith("/tickets")) return Promise.resolve(created ? [ticket()] : []);
      return Promise.resolve(undefined);
    });

    await renderPage("company-a");
    await waitFor(() => expect(screen.getByText("No tickets yet")).toBeInTheDocument());

    await user.type(screen.getByTestId("helpdesk-new-title"), "Printer on fire");
    await user.type(screen.getByTestId("helpdesk-new-description"), "help");
    await user.click(screen.getByTestId("helpdesk-create-button"));

    await waitFor(() =>
      expect(request).toHaveBeenCalledWith("/api/helpdesk/v1/companies/company-a/tickets", {
        method: "POST",
        body: { title: "Printer on fire", description: "help" },
      }),
    );
    await waitFor(() => expect(screen.getByText("Printer on fire")).toBeInTheDocument());
  });

  it("shows an error message when the list fetch fails", async () => {
    request.mockImplementation((url: string) => {
      if (url.endsWith("/me")) return Promise.resolve({ tier: "member" });
      return Promise.reject(new Error("boom"));
    });
    await renderPage("company-a");
    await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent("Could not load your tickets."));
  });
});
