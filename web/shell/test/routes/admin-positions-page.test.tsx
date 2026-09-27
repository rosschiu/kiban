// SPDX-License-Identifier: Apache-2.0

import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

const request = vi.fn();
vi.mock("../../src/auth/sdk", () => ({
  getShellSdk: () => ({ apiClient: { baseUrl: "https://gw.example", request } }),
}));

const { CompanyContextProvider, getCompanySessionContext } = await import("../../src/nav/company-context");
const { AdminPositionsPage } = await import("../../src/routes/admin-positions-page");

function position(overrides: Partial<Record<string, unknown>> = {}) {
  return {
    id: "position-1",
    companyId: "company-a",
    code: "cfo",
    title: "CFO",
    orgUnitId: "company-a",
    assignmentId: null,
    memberId: null,
    holderDisplayName: null,
    ...overrides,
  };
}

async function renderWithCompany(companyId: string | null) {
  if (companyId) getCompanySessionContext().setActiveCompanyId(companyId);
  render(
    <CompanyContextProvider>
      <AdminPositionsPage />
    </CompanyContextProvider>,
  );
}

describe("AdminPositionsPage", () => {
  beforeEach(() => {
    request.mockReset();
    getCompanySessionContext().setActiveCompanyId(null);
  });

  it("prompts to select a company when none is active", async () => {
    await renderWithCompany(null);
    expect(screen.getByText("Select a company")).toBeInTheDocument();
    expect(request).not.toHaveBeenCalled();
  });

  it("lists positions and shows an empty state with none", async () => {
    request.mockImplementation((url: string) => {
      if (url.includes("/api/org/admin/companies/company-a/positions")) {
        return Promise.resolve({ items: [], total: 0, page: 1, pageSize: 100, totalPages: 1 });
      }
      return Promise.resolve(undefined);
    });
    await renderWithCompany("company-a");
    await waitFor(() => expect(screen.getByText("No positions yet")).toBeInTheDocument());
  });

  it("shows the current holder for an assigned position, and Vacant for an unassigned one", async () => {
    request.mockImplementation((url: string) => {
      if (url.includes("/api/org/admin/companies/company-a/positions")) {
        return Promise.resolve({
          items: [
            position({ id: "p1", holderDisplayName: "Alice", assignmentId: "a1", memberId: "m1" }),
            position({ id: "p2", code: "vacant" }),
          ],
          total: 2,
          page: 1,
          pageSize: 100,
          totalPages: 1,
        });
      }
      return Promise.resolve(undefined);
    });
    await renderWithCompany("company-a");
    await waitFor(() => expect(screen.getByTestId("admin-position-holder-p1")).toHaveTextContent("Held by Alice"));
    expect(screen.getByTestId("admin-position-vacant-p2")).toBeInTheDocument();
    expect(screen.getByTestId("admin-position-end-p1")).toBeInTheDocument();
    expect(screen.getByTestId("admin-position-assign-p2")).toBeInTheDocument();
  });

  it("creates a position through the form and reloads the list", async () => {
    const user = userEvent.setup();
    let created = false;
    request.mockImplementation((url: string, opts?: { method?: string }) => {
      if (url.includes("/api/org/admin/companies/company-a/positions") && opts?.method === "POST") {
        created = true;
        return Promise.resolve(position());
      }
      if (url.includes("/api/org/admin/companies/company-a/positions")) {
        return Promise.resolve({
          items: created ? [position()] : [],
          total: created ? 1 : 0,
          page: 1,
          pageSize: 100,
          totalPages: 1,
        });
      }
      return Promise.resolve(undefined);
    });
    await renderWithCompany("company-a");
    await waitFor(() => expect(screen.getByText("No positions yet")).toBeInTheDocument());

    await user.type(screen.getByTestId("admin-position-code-input"), "cfo");
    await user.type(screen.getByTestId("admin-position-title-input"), "CFO");
    await user.click(screen.getByTestId("admin-position-create-button"));

    await waitFor(() =>
      expect(request).toHaveBeenCalledWith("/api/org/admin/companies/company-a/positions", {
        method: "POST",
        body: { code: "cfo", title: "CFO" },
      }),
    );
    await waitFor(() => expect(screen.getByTestId("admin-position-position-1")).toBeInTheDocument());
  });

  it("assigns a member to a vacant position through the picker", async () => {
    const user = userEvent.setup();
    let assigned = false;
    request.mockImplementation((url: string, opts?: { method?: string }) => {
      if (url.includes("/api/org/admin/positions/p2/assignments") && opts?.method === "POST") {
        assigned = true;
        return Promise.resolve({ id: "a2", positionId: "p2", memberId: "m2", validFrom: "2026-08-17", validTo: null });
      }
      if (url.includes("/api/org/admin/companies/company-a/positions")) {
        return Promise.resolve({
          items: assigned
            ? [position({ id: "p2", code: "vacant", assignmentId: "a2", memberId: "m2", holderDisplayName: "Bob" })]
            : [position({ id: "p2", code: "vacant" })],
          total: 1,
          page: 1,
          pageSize: 100,
          totalPages: 1,
        });
      }
      if (url.includes("/api/org/companies/company-a/members")) {
        return Promise.resolve({
          items: [{ id: "m2", displayName: "Bob", email: "bob@example.com", hasLinkedUser: true }],
          total: 1,
          page: 1,
          pageSize: 20,
          totalPages: 1,
        });
      }
      return Promise.resolve(undefined);
    });
    await renderWithCompany("company-a");
    await waitFor(() => expect(screen.getByTestId("admin-position-assign-p2")).toBeInTheDocument());
    await user.click(screen.getByTestId("admin-position-assign-p2"));
    await waitFor(() => expect(screen.getByTestId("admin-position-member-results-p2")).toBeInTheDocument());
    await waitFor(() => expect(screen.getByTestId("admin-position-assign-member-p2-m2")).toBeInTheDocument());
    await user.click(screen.getByTestId("admin-position-assign-member-p2-m2"));

    await waitFor(() =>
      expect(request).toHaveBeenCalledWith("/api/org/admin/positions/p2/assignments", {
        method: "POST",
        body: { memberId: "m2" },
      }),
    );
    await waitFor(() => expect(screen.getByTestId("admin-position-holder-p2")).toHaveTextContent("Held by Bob"));
  });

  it("ends an assignment and reloads the list", async () => {
    const user = userEvent.setup();
    let ended = false;
    request.mockImplementation((url: string, opts?: { method?: string }) => {
      if (url.includes("/api/org/admin/assignments/a1/end") && opts?.method === "POST") {
        ended = true;
        return Promise.resolve({ id: "a1", positionId: "p1", memberId: "m1", validFrom: "2026-08-01", validTo: "2026-08-17" });
      }
      if (url.includes("/api/org/admin/companies/company-a/positions")) {
        return Promise.resolve({
          items: ended
            ? [position({ id: "p1" })]
            : [position({ id: "p1", assignmentId: "a1", memberId: "m1", holderDisplayName: "Alice" })],
          total: 1,
          page: 1,
          pageSize: 100,
          totalPages: 1,
        });
      }
      return Promise.resolve(undefined);
    });
    await renderWithCompany("company-a");
    await waitFor(() => expect(screen.getByTestId("admin-position-end-p1")).toBeInTheDocument());
    await user.click(screen.getByTestId("admin-position-end-p1"));

    await waitFor(() =>
      expect(request).toHaveBeenCalledWith("/api/org/admin/assignments/a1/end", { method: "POST" }),
    );
    await waitFor(() => expect(screen.getByTestId("admin-position-vacant-p1")).toBeInTheDocument());
  });
});
