// SPDX-License-Identifier: Apache-2.0

import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { ModulePageContext } from "../../../src/resolver/resolver";

const request = vi.fn();
vi.mock("../../../src/auth/sdk", () => ({
  getShellSdk: () => ({ apiClient: { baseUrl: "https://gw.example", request } }),
}));

const { EntriesPage } = await import("../../../src/modules/timesheet/entries-page");

function context(companyId?: string): ModulePageContext {
  return { moduleKey: "timesheet", companyId, featureKey: "timesheet.access", params: {}, remoteExport: "EntriesPage" };
}

function page(items: unknown[]) {
  return { items, total: items.length, page: 1, pageSize: 100, totalPages: 1 };
}

const project = { id: "p1", companyId: "company-a", code: "PRJ1", name: "Project One", status: "active" as const };

describe("EntriesPage", () => {
  beforeEach(() => {
    request.mockReset();
  });

  it("renders nothing without a companyId", () => {
    const { container } = render(<EntriesPage context={context(undefined)} />);
    expect(container).toBeEmptyDOMElement();
  });

  it("prompts for a project when there are none yet", async () => {
    request.mockResolvedValueOnce(page([])).mockResolvedValueOnce({ items: [] });
    render(<EntriesPage context={context("company-a")} />);
    await waitFor(() => expect(screen.getByText(/an admin must create one first/)).toBeInTheDocument());
  });

  it("renders the weekly grid with existing entries and lets the caller save an hours change", async () => {
    const user = userEvent.setup();
    request
      .mockResolvedValueOnce(page([project])) // listProjects
      .mockResolvedValueOnce({ items: [] }) // listEntries
      .mockResolvedValueOnce({ id: "e1", companyId: "company-a", memberId: "m1", projectId: "p1", entryDate: "2026-08-10", realHours: 8, billableHours: 8, status: "draft" }) // upsertEntry
      .mockResolvedValueOnce(page([project])) // reload: listProjects
      .mockResolvedValueOnce({ items: [{ id: "e1", companyId: "company-a", memberId: "m1", projectId: "p1", entryDate: "2026-08-10", realHours: 8, billableHours: 8, status: "draft" }] }); // reload: listEntries

    render(<EntriesPage context={context("company-a")} />);
    await waitFor(() => expect(screen.getByTestId("timesheet-weekly-grid")).toBeInTheDocument());
    expect(screen.getByText(/Project One/)).toBeInTheDocument();

    const inputs = screen.getAllByRole("spinbutton");
    await user.type(inputs[0]!, "8");
    await user.tab();

    await waitFor(() =>
      expect(request).toHaveBeenCalledWith("/api/timesheet/v1/companies/company-a/entries", {
        method: "POST",
        body: expect.objectContaining({ projectId: "p1", realHours: 8 }),
      }),
    );
  });

  it("enables Submit only once a draft entry exists, and submits the week", async () => {
    const user = userEvent.setup();
    request
      .mockResolvedValueOnce(page([project]))
      .mockResolvedValueOnce({
        items: [{ id: "e1", companyId: "company-a", memberId: "m1", projectId: "p1", entryDate: "2026-08-10", realHours: 8, billableHours: 8, status: "draft" }],
      })
      .mockResolvedValueOnce({ id: "s1", companyId: "company-a", memberId: "m1", weekStart: "2026-08-10", versionNumber: 1, rootId: "s1", supersedesId: null, isCurrent: true, status: "submitted", assignedApproverMemberId: "m2", rejectReason: null, permissions: { canApprove: false, canReject: false, canRevert: false } }) // submitWeek
      .mockResolvedValueOnce(page([project])) // reload
      .mockResolvedValueOnce({ items: [] });

    render(<EntriesPage context={context("company-a")} />);
    const submitButton = await screen.findByTestId("timesheet-submit-week");
    await waitFor(() => expect(submitButton).toBeEnabled());

    await user.click(submitButton);
    await waitFor(() => expect(screen.getByText("Week submitted.")).toBeInTheDocument());
  });

  it("shows an error message when the initial load fails", async () => {
    request.mockRejectedValue(new Error("boom"));
    render(<EntriesPage context={context("company-a")} />);
    await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent("Could not load the weekly timesheet."));
  });
});
