// SPDX-License-Identifier: Apache-2.0

import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { ModulePageContext } from "../../../src/resolver/resolver";

const request = vi.fn();
vi.mock("../../../src/auth/sdk", () => ({
  getShellSdk: () => ({ apiClient: { baseUrl: "https://gw.example", request } }),
}));

const { SubmissionsPage } = await import("../../../src/modules/timesheet/submissions-page");

function context(companyId?: string): ModulePageContext {
  return { moduleKey: "timesheet", companyId, featureKey: "timesheet.access", params: {}, remoteExport: "SubmissionsPage" };
}

function submission(overrides: Partial<Record<string, unknown>> = {}) {
  return {
    id: "s1",
    companyId: "company-a",
    memberId: "m1",
    weekStart: "2026-08-10",
    versionNumber: 1,
    rootId: "s1",
    supersedesId: null,
    isCurrent: true,
    status: "submitted",
    assignedApproverMemberId: "m2",
    rejectReason: null,
    permissions: { canApprove: false, canReject: false, canRevert: false },
    ...overrides,
  };
}

function pageResult(items: unknown[], totalPages = 1) {
  return { items, total: items.length, page: 1, pageSize: 25, totalPages };
}

describe("SubmissionsPage", () => {
  beforeEach(() => {
    request.mockReset();
  });

  it("renders nothing without a companyId", () => {
    const { container } = render(<SubmissionsPage context={context(undefined)} />);
    expect(container).toBeEmptyDOMElement();
  });

  it("renders the empty state when there are no submissions", async () => {
    request.mockResolvedValue(pageResult([]));
    render(<SubmissionsPage context={context("company-a")} />);
    await waitFor(() => expect(screen.getByText("No submissions yet")).toBeInTheDocument());
  });

  it("lists submissions with week/version/status/reject-reason and supports pagination", async () => {
    const user = userEvent.setup();
    request
      .mockResolvedValueOnce(
        pageResult(
          [submission(), submission({ id: "s2", weekStart: "2026-08-17", versionNumber: 2, status: "rejected", rejectReason: "wrong hours", isCurrent: false })],
          2,
        ),
      )
      .mockResolvedValueOnce(pageResult([submission({ id: "s3" })], 2)); // page 2

    render(<SubmissionsPage context={context("company-a")} />);
    await waitFor(() => expect(screen.getByTestId("timesheet-submissions-list")).toBeInTheDocument());
    expect(screen.getByText("2026-08-10")).toBeInTheDocument();
    expect(screen.getByText("2026-08-17")).toBeInTheDocument();
    expect(screen.getByText("wrong hours")).toBeInTheDocument();
    expect(screen.getByText("(superseded)")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Next" }));
    await waitFor(() =>
      expect(request).toHaveBeenCalledWith("/api/timesheet/v1/companies/company-a/submissions", {
        query: { view: "mine", page: 2, pageSize: 25 },
      }),
    );
  });

  it("shows an error message when the fetch fails", async () => {
    request.mockRejectedValue(new Error("boom"));
    render(<SubmissionsPage context={context("company-a")} />);
    await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent("Could not load your submissions."));
  });
});
