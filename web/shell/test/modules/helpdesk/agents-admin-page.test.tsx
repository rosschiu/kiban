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

const { AgentsAdminPage } = await import("../../../src/modules/helpdesk/agents-admin-page");

function context(companyId?: string): ModulePageContext {
  return { moduleKey: "helpdesk", companyId, featureKey: "helpdesk.access", params: {}, remoteExport: "AgentsAdminPage" };
}

function agent(overrides: Partial<Record<string, unknown>> = {}) {
  return {
    id: "agent-row-1",
    companyId: "company-a",
    bindingKind: "member",
    memberId: "member-1",
    grantedBy: "carol-admin",
    createdAt: "2026-01-01T00:00:00Z",
    ...overrides,
  };
}

function positionAgent(overrides: Partial<Record<string, unknown>> = {}) {
  return {
    id: "agent-row-2",
    companyId: "company-a",
    bindingKind: "position",
    positionId: "position-1",
    positionTitle: "Support Agent",
    grantedBy: "carol-admin",
    createdAt: "2026-01-01T00:00:00Z",
    ...overrides,
  };
}

function position(overrides: Partial<Record<string, unknown>> = {}) {
  return {
    id: "position-1",
    companyId: "company-a",
    code: "support-agent",
    title: "Support Agent",
    orgUnitId: "company-a",
    assignmentId: "a1",
    memberId: "member-1",
    holderDisplayName: "Alice Demo",
    ...overrides,
  };
}

function groupAgent(overrides: Partial<Record<string, unknown>> = {}) {
  return {
    id: "agent-row-3",
    companyId: "company-a",
    bindingKind: "group",
    groupId: "group-1",
    groupTitle: "Support Team",
    grantedBy: "carol-admin",
    createdAt: "2026-01-01T00:00:00Z",
    ...overrides,
  };
}

function group(overrides: Partial<Record<string, unknown>> = {}) {
  return {
    id: "group-1",
    companyId: "company-a",
    code: "support-team",
    name: "Support Team",
    source: "kiban",
    isKibanManaged: true,
    memberCount: 2,
    ...overrides,
  };
}

async function renderPage(companyId?: string) {
  const rootRoute = createRootRoute({ component: () => <AgentsAdminPage context={context(companyId)} /> });
  const routeTree = rootRoute.addChildren([]);
  const router = createRouter({ routeTree, history: createMemoryHistory({ initialEntries: ["/app"] }) });
  await act(async () => {
    render(<RouterProvider router={router} />);
    await router.load();
  });
}

describe("AgentsAdminPage", () => {
  beforeEach(() => {
    request.mockReset();
  });

  it("renders nothing without a companyId", async () => {
    await renderPage(undefined);
    expect(screen.queryByTestId("helpdesk-agents-page")).not.toBeInTheDocument();
  });

  it("shows the admin-required denied state for a non-admin", async () => {
    request.mockImplementation((url: string) => {
      if (url.endsWith("/me")) return Promise.resolve({ tier: "agent" });
      return Promise.reject(new Error("403"));
    });
    await renderPage("company-a");
    await waitFor(() => expect(screen.getByTestId("helpdesk-agents-denied")).toBeInTheDocument());
  });

  it("lists current agents and shows an empty state with none", async () => {
    request.mockImplementation((url: string) => {
      if (url.endsWith("/me")) return Promise.resolve({ tier: "admin" });
      if (url.endsWith("/agents")) return Promise.resolve([]);
      if (url.includes("/api/org/companies/company-a/members")) {
        return Promise.resolve({ items: [], total: 0, page: 1, pageSize: 20, totalPages: 1 });
      }
      return Promise.resolve(undefined);
    });
    await renderPage("company-a");
    await waitFor(() => expect(screen.getByText("No agents yet")).toBeInTheDocument());
  });

  it("makes a member an agent through the picker", async () => {
    const user = userEvent.setup();
    let agents: unknown[] = [];
    request.mockImplementation((url: string, opts?: { method?: string }) => {
      if (url.endsWith("/me")) return Promise.resolve({ tier: "admin" });
      if (url.endsWith("/agents") && opts?.method === "POST") {
        agents = [agent()];
        return Promise.resolve(agent());
      }
      if (url.endsWith("/agents")) return Promise.resolve(agents);
      if (url.includes("/api/org/companies/company-a/members")) {
        return Promise.resolve({
          items: [{ id: "member-1", displayName: "Bob", email: "bob@example.com", hasLinkedUser: true }],
          total: 1,
          page: 1,
          pageSize: 20,
          totalPages: 1,
        });
      }
      return Promise.resolve(undefined);
    });
    await renderPage("company-a");
    await waitFor(() => expect(screen.getByTestId("helpdesk-make-agent-member-1")).toBeInTheDocument());
    await user.click(screen.getByTestId("helpdesk-make-agent-member-1"));
    await waitFor(() =>
      expect(request).toHaveBeenCalledWith("/api/helpdesk/v1/companies/company-a/agents", {
        method: "POST",
        body: { memberId: "member-1" },
      }),
    );
    await waitFor(() => expect(screen.getByTestId("helpdesk-agent-member-1")).toBeInTheDocument());
  });

  it("shows the blocked-removal message when the protection rule fires", async () => {
    const user = userEvent.setup();
    // removeAgent uses DELETE to a per-member sub-resource (.../agents/member-1), which the
    // server would 422 when the protection rule fires.
    request.mockImplementation((url: string, opts?: { method?: string }) => {
      if (url.endsWith("/me")) return Promise.resolve({ tier: "admin" });
      if (url.endsWith("/agents/member-1") && opts?.method === "DELETE") return Promise.reject(new Error("422"));
      if (url.endsWith("/agents")) return Promise.resolve([agent()]);
      if (url.includes("/api/org/companies/company-a/members")) {
        return Promise.resolve({ items: [], total: 0, page: 1, pageSize: 20, totalPages: 1 });
      }
      return Promise.resolve(undefined);
    });

    await renderPage("company-a");
    await waitFor(() => expect(screen.getByTestId("helpdesk-agent-member-1")).toBeInTheDocument());
    await user.click(screen.getByTestId("helpdesk-remove-agent-member-1"));
    await waitFor(() => expect(screen.getByTestId("helpdesk-remove-blocked-member-1")).toBeInTheDocument());
  });

  // ---- The "bind to position" variant. ----

  it("labels a member binding and a position binding differently, with the position row naming its holder", async () => {
    request.mockImplementation((url: string) => {
      if (url.endsWith("/me")) return Promise.resolve({ tier: "admin" });
      if (url.endsWith("/agents")) return Promise.resolve([agent(), positionAgent()]);
      if (url.endsWith("/assignable-positions")) {
        return Promise.resolve([{ positionId: "position-1", title: "Support Agent", holderMemberId: "member-1", holderDisplayName: "Alice Demo" }]);
      }
      if (url.includes("/api/org/admin/companies/company-a/positions")) {
        return Promise.resolve({ items: [position()], total: 1, page: 1, pageSize: 100, totalPages: 1 });
      }
      if (url.includes("/api/org/companies/company-a/members")) {
        return Promise.resolve({ items: [], total: 0, page: 1, pageSize: 20, totalPages: 1 });
      }
      return Promise.resolve(undefined);
    });

    await renderPage("company-a");
    await waitFor(() =>
      expect(screen.getByTestId("helpdesk-agent-binding-kind-member-1")).toHaveTextContent("member member-1… (member)"),
    );
    expect(screen.getByTestId("helpdesk-agent-binding-kind-position-1")).toHaveTextContent(
      "Support Agent — held by Alice Demo (position)",
    );
  });

  // A NON-superadmin helpdesk admin has no access to the superadmin-guarded
  // /api/org/admin/... position-admin route — this proves the holder NAME still
  // renders correctly for them, sourced entirely from helpdesk's own helpdesk.manage-gated
  // assignable-positions read, even while the superadmin-only route 403s.
  it("shows the real holder name for a non-superadmin admin, sourced from helpdesk's own assignable-positions read", async () => {
    request.mockImplementation((url: string) => {
      if (url.endsWith("/me")) return Promise.resolve({ tier: "admin" });
      if (url.endsWith("/agents")) return Promise.resolve([positionAgent()]);
      if (url.endsWith("/assignable-positions")) {
        return Promise.resolve([{ positionId: "position-1", title: "Support Agent", holderMemberId: "member-1", holderDisplayName: "Bob Demo" }]);
      }
      // The superadmin-only org route is unreachable for this caller — fails closed to [].
      if (url.includes("/api/org/admin/companies/company-a/positions")) return Promise.reject(new Error("403"));
      if (url.includes("/api/org/companies/company-a/members")) {
        return Promise.resolve({ items: [], total: 0, page: 1, pageSize: 20, totalPages: 1 });
      }
      return Promise.resolve(undefined);
    });

    await renderPage("company-a");
    await waitFor(() =>
      expect(screen.getByTestId("helpdesk-agent-binding-kind-position-1")).toHaveTextContent(
        "Support Agent — held by Bob Demo (position)",
      ),
    );
  });

  it("binds a position as an agent through the position picker", async () => {
    const user = userEvent.setup();
    let agents: unknown[] = [];
    request.mockImplementation((url: string, opts?: { method?: string }) => {
      if (url.endsWith("/me")) return Promise.resolve({ tier: "admin" });
      if (url.endsWith("/agents") && opts?.method === "POST") {
        agents = [positionAgent()];
        return Promise.resolve(positionAgent());
      }
      if (url.endsWith("/agents")) return Promise.resolve(agents);
      if (url.includes("/api/org/admin/companies/company-a/positions")) {
        return Promise.resolve({ items: [position()], total: 1, page: 1, pageSize: 100, totalPages: 1 });
      }
      if (url.includes("/api/org/companies/company-a/members")) {
        return Promise.resolve({ items: [], total: 0, page: 1, pageSize: 20, totalPages: 1 });
      }
      return Promise.resolve(undefined);
    });

    await renderPage("company-a");
    await waitFor(() => expect(screen.getByTestId("helpdesk-bind-position-position-1")).toBeInTheDocument());
    await user.click(screen.getByTestId("helpdesk-bind-position-position-1"));
    await waitFor(() =>
      expect(request).toHaveBeenCalledWith("/api/helpdesk/v1/companies/company-a/agents", {
        method: "POST",
        body: { positionId: "position-1" },
      }),
    );
    await waitFor(() => expect(screen.getByTestId("helpdesk-agent-position-1")).toBeInTheDocument());
  });

  it("removes a position binding via the unambiguous position-revoke route", async () => {
    const user = userEvent.setup();
    let agents: unknown[] = [positionAgent()];
    request.mockImplementation((url: string, opts?: { method?: string }) => {
      if (url.endsWith("/me")) return Promise.resolve({ tier: "admin" });
      if (url.endsWith("/agents/positions/position-1") && opts?.method === "DELETE") {
        agents = [];
        return Promise.resolve(undefined);
      }
      if (url.endsWith("/agents")) return Promise.resolve(agents);
      if (url.includes("/api/org/admin/companies/company-a/positions")) {
        return Promise.resolve({ items: [position()], total: 1, page: 1, pageSize: 100, totalPages: 1 });
      }
      if (url.includes("/api/org/companies/company-a/members")) {
        return Promise.resolve({ items: [], total: 0, page: 1, pageSize: 20, totalPages: 1 });
      }
      return Promise.resolve(undefined);
    });

    await renderPage("company-a");
    await waitFor(() => expect(screen.getByTestId("helpdesk-agent-position-1")).toBeInTheDocument());
    await user.click(screen.getByTestId("helpdesk-remove-agent-position-1"));
    await waitFor(() =>
      expect(request).toHaveBeenCalledWith("/api/helpdesk/v1/companies/company-a/agents/positions/position-1", {
        method: "DELETE",
      }),
    );
    await waitFor(() => expect(screen.queryByTestId("helpdesk-agent-position-1")).not.toBeInTheDocument());
  });

  // ---- The "bind to group" variant. ----

  it("labels a group binding distinctly from member/position bindings", async () => {
    request.mockImplementation((url: string) => {
      if (url.endsWith("/me")) return Promise.resolve({ tier: "admin" });
      if (url.endsWith("/agents")) return Promise.resolve([agent(), groupAgent()]);
      if (url.includes("/api/org/admin/companies/company-a/groups")) {
        return Promise.resolve({ items: [group()], total: 1, page: 1, pageSize: 100, totalPages: 1 });
      }
      if (url.includes("/api/org/admin/companies/company-a/positions")) {
        return Promise.resolve({ items: [], total: 0, page: 1, pageSize: 100, totalPages: 1 });
      }
      if (url.includes("/api/org/companies/company-a/members")) {
        return Promise.resolve({ items: [], total: 0, page: 1, pageSize: 20, totalPages: 1 });
      }
      return Promise.resolve(undefined);
    });

    await renderPage("company-a");
    await waitFor(() =>
      expect(screen.getByTestId("helpdesk-agent-binding-kind-group-1")).toHaveTextContent("Support Team (group)"),
    );
  });

  it("binds a group as an agent through the group picker", async () => {
    const user = userEvent.setup();
    let agents: unknown[] = [];
    request.mockImplementation((url: string, opts?: { method?: string }) => {
      if (url.endsWith("/me")) return Promise.resolve({ tier: "admin" });
      if (url.endsWith("/agents") && opts?.method === "POST") {
        agents = [groupAgent()];
        return Promise.resolve(groupAgent());
      }
      if (url.endsWith("/agents")) return Promise.resolve(agents);
      if (url.includes("/api/org/admin/companies/company-a/groups")) {
        return Promise.resolve({ items: [group()], total: 1, page: 1, pageSize: 100, totalPages: 1 });
      }
      if (url.includes("/api/org/admin/companies/company-a/positions")) {
        return Promise.resolve({ items: [], total: 0, page: 1, pageSize: 100, totalPages: 1 });
      }
      if (url.includes("/api/org/companies/company-a/members")) {
        return Promise.resolve({ items: [], total: 0, page: 1, pageSize: 20, totalPages: 1 });
      }
      return Promise.resolve(undefined);
    });

    await renderPage("company-a");
    await waitFor(() => expect(screen.getByTestId("helpdesk-bind-group-group-1")).toBeInTheDocument());
    await user.click(screen.getByTestId("helpdesk-bind-group-group-1"));
    await waitFor(() =>
      expect(request).toHaveBeenCalledWith("/api/helpdesk/v1/companies/company-a/agents", {
        method: "POST",
        body: { groupId: "group-1" },
      }),
    );
    await waitFor(() => expect(screen.getByTestId("helpdesk-agent-group-1")).toBeInTheDocument());
  });

  it("removes a group binding via the unambiguous group-revoke route", async () => {
    const user = userEvent.setup();
    let agents: unknown[] = [groupAgent()];
    request.mockImplementation((url: string, opts?: { method?: string }) => {
      if (url.endsWith("/me")) return Promise.resolve({ tier: "admin" });
      if (url.endsWith("/agents/groups/group-1") && opts?.method === "DELETE") {
        agents = [];
        return Promise.resolve(undefined);
      }
      if (url.endsWith("/agents")) return Promise.resolve(agents);
      if (url.includes("/api/org/admin/companies/company-a/groups")) {
        return Promise.resolve({ items: [group()], total: 1, page: 1, pageSize: 100, totalPages: 1 });
      }
      if (url.includes("/api/org/admin/companies/company-a/positions")) {
        return Promise.resolve({ items: [], total: 0, page: 1, pageSize: 100, totalPages: 1 });
      }
      if (url.includes("/api/org/companies/company-a/members")) {
        return Promise.resolve({ items: [], total: 0, page: 1, pageSize: 20, totalPages: 1 });
      }
      return Promise.resolve(undefined);
    });

    await renderPage("company-a");
    await waitFor(() => expect(screen.getByTestId("helpdesk-agent-group-1")).toBeInTheDocument());
    await user.click(screen.getByTestId("helpdesk-remove-agent-group-1"));
    await waitFor(() =>
      expect(request).toHaveBeenCalledWith("/api/helpdesk/v1/companies/company-a/agents/groups/group-1", {
        method: "DELETE",
      }),
    );
    await waitFor(() => expect(screen.queryByTestId("helpdesk-agent-group-1")).not.toBeInTheDocument());
  });
});
