// SPDX-License-Identifier: Apache-2.0

import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { ModulePageContext } from "../../../src/resolver/resolver";

const request = vi.fn();
vi.mock("../../../src/auth/sdk", () => ({
  getShellSdk: () => ({ apiClient: { baseUrl: "https://gw.example", request } }),
}));

const { ApprovalsPage } = await import("../../../src/modules/timesheet/approvals-page");

function context(companyId?: string): ModulePageContext {
  return { moduleKey: "timesheet", companyId, featureKey: "timesheet.access", params: {}, remoteExport: "ApprovalsPage" };
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
    permissions: { canApprove: true, canReject: true, canRevert: false },
    ...overrides,
  };
}

function pageResult(items: unknown[]) {
  return { items, total: items.length, page: 1, pageSize: 25, totalPages: 1 };
}

describe("ApprovalsPage", () => {
  beforeEach(() => {
    request.mockReset();
  });
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("renders nothing without a companyId", () => {
    const { container } = render(<ApprovalsPage context={context(undefined)} />);
    expect(container).toBeEmptyDOMElement();
  });

  it("renders the empty state when there is nothing to review", async () => {
    request.mockResolvedValue(pageResult([]));
    render(<ApprovalsPage context={context("company-a")} />);
    await waitFor(() => expect(screen.getByText("Nothing to review")).toBeInTheDocument());
  });

  it("disables actions for a row the caller cannot decide, per its own permissions object", async () => {
    request.mockResolvedValueOnce(pageResult([submission({ permissions: { canApprove: false, canReject: false, canRevert: false } })]));
    render(<ApprovalsPage context={context("company-a")} />);
    await waitFor(() => expect(screen.getByText("Decided")).toBeInTheDocument());
  });

  it("approves a submission the caller can decide", async () => {
    const user = userEvent.setup();
    request
      .mockResolvedValueOnce(pageResult([submission()]))
      .mockResolvedValueOnce(submission({ status: "approved" })) // approveSubmission
      .mockResolvedValueOnce(pageResult([submission({ status: "approved", permissions: { canApprove: false, canReject: false, canRevert: false } })])); // reload

    render(<ApprovalsPage context={context("company-a")} />);
    await waitFor(() => expect(screen.getByTestId("approve-s1")).toBeEnabled());
    await user.click(screen.getByTestId("approve-s1"));

    await waitFor(() =>
      expect(request).toHaveBeenCalledWith("/api/timesheet/v1/companies/company-a/submissions/s1/approve", { method: "POST" }),
    );
  });

  it("rejects a submission with a reason from window.prompt", async () => {
    const user = userEvent.setup();
    vi.spyOn(window, "prompt").mockReturnValue("wrong hours");
    request
      .mockResolvedValueOnce(pageResult([submission()]))
      .mockResolvedValueOnce(submission({ status: "rejected", rejectReason: "wrong hours" })) // rejectSubmission
      .mockResolvedValueOnce(pageResult([submission({ status: "rejected", rejectReason: "wrong hours", permissions: { canApprove: false, canReject: false, canRevert: false } })])); // reload

    render(<ApprovalsPage context={context("company-a")} />);
    await waitFor(() => expect(screen.getByTestId("reject-s1")).toBeEnabled());
    await user.click(screen.getByTestId("reject-s1"));

    await waitFor(() =>
      expect(request).toHaveBeenCalledWith("/api/timesheet/v1/companies/company-a/submissions/s1/reject", {
        method: "POST",
        body: { reason: "wrong hours" },
      }),
    );
  });

  it("does nothing when the reject prompt is cancelled", async () => {
    const user = userEvent.setup();
    vi.spyOn(window, "prompt").mockReturnValue(null);
    request.mockResolvedValueOnce(pageResult([submission()]));

    render(<ApprovalsPage context={context("company-a")} />);
    await waitFor(() => expect(screen.getByTestId("reject-s1")).toBeEnabled());
    await user.click(screen.getByTestId("reject-s1"));

    expect(request).toHaveBeenCalledTimes(1); // only the initial load, no reject call
  });

  it("shows an error message when the fetch fails", async () => {
    request.mockRejectedValue(new Error("boom"));
    render(<ApprovalsPage context={context("company-a")} />);
    await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent("Could not load submissions awaiting your decision."));
  });
});
