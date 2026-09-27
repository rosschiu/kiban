// SPDX-License-Identifier: Apache-2.0

import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

const request = vi.fn();
vi.mock("../../src/auth/sdk", () => ({
  getShellSdk: () => ({ apiClient: { baseUrl: "https://gw.example", request } }),
}));

const { CompanyContextProvider, getCompanySessionContext } = await import("../../src/nav/company-context");
const { AdminGroupsPage } = await import("../../src/routes/admin-groups-page");

function group(overrides: Partial<Record<string, unknown>> = {}) {
  return {
    id: "group-1",
    companyId: "company-a",
    code: "support-team",
    name: "Support Team",
    source: "kiban",
    externalRef: null,
    isActive: true,
    isKibanManaged: true,
    memberCount: 0,
    ...overrides,
  };
}

async function renderWithCompany(companyId: string | null) {
  if (companyId) getCompanySessionContext().setActiveCompanyId(companyId);
  render(
    <CompanyContextProvider>
      <AdminGroupsPage />
    </CompanyContextProvider>,
  );
}

describe("AdminGroupsPage", () => {
  beforeEach(() => {
    request.mockReset();
    getCompanySessionContext().setActiveCompanyId(null);
  });

  it("prompts to select a company when none is active", async () => {
    await renderWithCompany(null);
    expect(screen.getByText("Select a company")).toBeInTheDocument();
    expect(request).not.toHaveBeenCalled();
  });

  it("lists groups and shows an empty state with none", async () => {
    request.mockImplementation((url: string) => {
      if (url.includes("/api/org/admin/companies/company-a/groups")) {
        return Promise.resolve({ items: [], total: 0, page: 1, pageSize: 100, totalPages: 1 });
      }
      return Promise.resolve(undefined);
    });
    await renderWithCompany("company-a");
    await waitFor(() => expect(screen.getByText("No groups yet")).toBeInTheDocument());
  });

  it("shows the member count and expands to list current members", async () => {
    request.mockImplementation((url: string) => {
      if (url.includes("/api/org/admin/companies/company-a/groups")) {
        return Promise.resolve({
          items: [group({ id: "g1", memberCount: 2 })],
          total: 1,
          page: 1,
          pageSize: 100,
          totalPages: 1,
        });
      }
      if (url.includes("/api/org/admin/groups/g1/members")) {
        return Promise.resolve([
          { groupId: "g1", memberId: "m1", addedBy: "actor", addedAt: "2026-08-18T00:00:00Z", memberDisplayName: "Alice", memberEmail: "alice@example.com" },
          { groupId: "g1", memberId: "m2", addedBy: "actor", addedAt: "2026-08-18T00:00:00Z", memberDisplayName: "Bob", memberEmail: "bob@example.com" },
        ]);
      }
      return Promise.resolve(undefined);
    });
    const user = userEvent.setup();
    await renderWithCompany("company-a");
    await waitFor(() => expect(screen.getByTestId("admin-group-expand-g1")).toHaveTextContent("2 members"));
    await user.click(screen.getByTestId("admin-group-expand-g1"));
    await waitFor(() => expect(screen.getByTestId("admin-group-members-g1")).toHaveTextContent("Alice"));
    expect(screen.getByTestId("admin-group-members-g1")).toHaveTextContent("Bob");
  });

  it("creates a group through the form and reloads the list", async () => {
    const user = userEvent.setup();
    let created = false;
    request.mockImplementation((url: string, opts?: { method?: string }) => {
      if (url.includes("/api/org/admin/companies/company-a/groups") && opts?.method === "POST") {
        created = true;
        return Promise.resolve(group());
      }
      if (url.includes("/api/org/admin/companies/company-a/groups")) {
        return Promise.resolve({
          items: created ? [group()] : [],
          total: created ? 1 : 0,
          page: 1,
          pageSize: 100,
          totalPages: 1,
        });
      }
      return Promise.resolve(undefined);
    });
    await renderWithCompany("company-a");
    await waitFor(() => expect(screen.getByText("No groups yet")).toBeInTheDocument());

    await user.type(screen.getByTestId("admin-group-code-input"), "support-team");
    await user.type(screen.getByTestId("admin-group-name-input"), "Support Team");
    await user.click(screen.getByTestId("admin-group-create-button"));

    await waitFor(() =>
      expect(request).toHaveBeenCalledWith("/api/org/admin/companies/company-a/groups", {
        method: "POST",
        body: { code: "support-team", name: "Support Team" },
      }),
    );
    await waitFor(() => expect(screen.getByTestId("admin-group-group-1")).toBeInTheDocument());
  });

  it("adds a member to a group through the picker", async () => {
    const user = userEvent.setup();
    let added = false;
    request.mockImplementation((url: string, opts?: { method?: string }) => {
      if (url.includes("/api/org/admin/groups/g1/members") && opts?.method === "POST") {
        added = true;
        return Promise.resolve({ groupId: "g1", memberId: "m1", addedBy: "actor", addedAt: "2026-08-18T00:00:00Z", memberDisplayName: "Alice", memberEmail: "alice@example.com" });
      }
      if (url.includes("/api/org/admin/groups/g1/members")) {
        return Promise.resolve(added ? [{ groupId: "g1", memberId: "m1", addedBy: "actor", addedAt: "2026-08-18T00:00:00Z", memberDisplayName: "Alice", memberEmail: "alice@example.com" }] : []);
      }
      if (url.includes("/api/org/admin/companies/company-a/groups")) {
        return Promise.resolve({
          items: [group({ id: "g1", memberCount: added ? 1 : 0 })],
          total: 1,
          page: 1,
          pageSize: 100,
          totalPages: 1,
        });
      }
      if (url.includes("/api/org/companies/company-a/members")) {
        return Promise.resolve({
          items: [{ id: "m1", displayName: "Alice", email: "alice@example.com", hasLinkedUser: true }],
          total: 1,
          page: 1,
          pageSize: 20,
          totalPages: 1,
        });
      }
      return Promise.resolve(undefined);
    });
    await renderWithCompany("company-a");
    await waitFor(() => expect(screen.getByTestId("admin-group-expand-g1")).toBeInTheDocument());
    await user.click(screen.getByTestId("admin-group-expand-g1"));
    await waitFor(() => expect(screen.getByTestId("admin-group-add-button-g1")).toBeInTheDocument());
    await user.click(screen.getByTestId("admin-group-add-button-g1"));
    await waitFor(() => expect(screen.getByTestId("admin-group-member-results-g1")).toBeInTheDocument());
    await waitFor(() => expect(screen.getByTestId("admin-group-add-member-g1-m1")).toBeInTheDocument());
    await user.click(screen.getByTestId("admin-group-add-member-g1-m1"));

    await waitFor(() =>
      expect(request).toHaveBeenCalledWith("/api/org/admin/groups/g1/members", {
        method: "POST",
        body: { memberId: "m1" },
      }),
    );
    await waitFor(() => expect(screen.getByTestId("admin-group-expand-g1")).toHaveTextContent("1 member"));
  });

  it("removes a member from a group", async () => {
    const user = userEvent.setup();
    let removed = false;
    request.mockImplementation((url: string, opts?: { method?: string }) => {
      if (url.includes("/api/org/admin/groups/g1/members/m1") && opts?.method === "DELETE") {
        removed = true;
        return Promise.resolve({ groupId: "g1", memberId: "m1" });
      }
      if (url.includes("/api/org/admin/groups/g1/members")) {
        return Promise.resolve(removed ? [] : [{ groupId: "g1", memberId: "m1", addedBy: "actor", addedAt: "2026-08-18T00:00:00Z", memberDisplayName: "Alice", memberEmail: "alice@example.com" }]);
      }
      if (url.includes("/api/org/admin/companies/company-a/groups")) {
        return Promise.resolve({
          items: [group({ id: "g1", memberCount: removed ? 0 : 1 })],
          total: 1,
          page: 1,
          pageSize: 100,
          totalPages: 1,
        });
      }
      return Promise.resolve(undefined);
    });
    await renderWithCompany("company-a");
    await waitFor(() => expect(screen.getByTestId("admin-group-expand-g1")).toBeInTheDocument());
    await user.click(screen.getByTestId("admin-group-expand-g1"));
    await waitFor(() => expect(screen.getByTestId("admin-group-remove-member-g1-m1")).toBeInTheDocument());
    await user.click(screen.getByTestId("admin-group-remove-member-g1-m1"));

    await waitFor(() =>
      expect(request).toHaveBeenCalledWith("/api/org/admin/groups/g1/members/m1", { method: "DELETE" }),
    );
    await waitFor(() => expect(screen.getByTestId("admin-group-expand-g1")).toHaveTextContent("0 members"));
  });

  it("renders an externally-sourced group read-only with a source badge, no add/remove controls", async () => {
    request.mockImplementation((url: string) => {
      if (url.includes("/api/org/admin/companies/company-a/groups")) {
        return Promise.resolve({
          items: [group({ id: "g2", code: "ad-eng", name: "AD Engineering", source: "entra:contoso", isKibanManaged: false, memberCount: 3 })],
          total: 1,
          page: 1,
          pageSize: 100,
          totalPages: 1,
        });
      }
      if (url.includes("/api/org/admin/groups/g2/members")) {
        return Promise.resolve([
          { groupId: "g2", memberId: "m9", addedBy: "sync", addedAt: "2026-08-18T00:00:00Z", memberDisplayName: "Carol", memberEmail: "carol@example.com" },
        ]);
      }
      return Promise.resolve(undefined);
    });
    const user = userEvent.setup();
    await renderWithCompany("company-a");
    await waitFor(() => expect(screen.getByTestId("admin-group-source-badge-g2")).toHaveTextContent("source: entra:contoso"));
    await user.click(screen.getByTestId("admin-group-expand-g2"));
    await waitFor(() => expect(screen.getByTestId("admin-group-readonly-g2")).toBeInTheDocument());
    expect(screen.queryByTestId("admin-group-add-button-g2")).not.toBeInTheDocument();
    expect(screen.queryByTestId("admin-group-remove-member-g2-m9")).not.toBeInTheDocument();
  });
});
