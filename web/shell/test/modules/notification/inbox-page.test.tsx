// SPDX-License-Identifier: Apache-2.0

import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { ModulePageContext } from "../../../src/resolver/resolver";

const request = vi.fn();
vi.mock("../../../src/auth/sdk", () => ({
  getShellSdk: () => ({ apiClient: { baseUrl: "https://gw.example", request } }),
}));

const { InboxPage } = await import("../../../src/modules/notification/inbox-page");

function context(companyId?: string): ModulePageContext {
  return { moduleKey: "notification", companyId, featureKey: "notification.access", params: {}, remoteExport: "InboxPage" };
}

function page(items: unknown[]) {
  return { items, total: items.length, page: 1, pageSize: 50, totalPages: 1 };
}

describe("InboxPage", () => {
  beforeEach(() => {
    request.mockReset();
  });

  it("renders nothing without a companyId", () => {
    const { container } = render(<InboxPage context={context(undefined)} />);
    expect(container).toBeEmptyDOMElement();
  });

  it("renders the empty state when the inbox has no messages", async () => {
    request.mockResolvedValue(page([]));
    render(<InboxPage context={context("company-a")} />);
    await waitFor(() => expect(screen.getByText("No messages yet")).toBeInTheDocument());
  });

  it("renders messages, marking unread ones and letting the caller mark them read", async () => {
    const user = userEvent.setup();
    request
      .mockResolvedValueOnce(
        page([{ id: "msg-1", subjectLine: "Hello", body: "World", readAt: null, channelId: "c1", companyId: "company-a", createdBy: "u1", createdAt: "now" }]),
      )
      .mockResolvedValueOnce({}) // markRead
      .mockResolvedValueOnce(
        page([{ id: "msg-1", subjectLine: "Hello", body: "World", readAt: "later", channelId: "c1", companyId: "company-a", createdBy: "u1", createdAt: "now" }]),
      );

    render(<InboxPage context={context("company-a")} />);
    await waitFor(() => expect(screen.getByText("Hello")).toBeInTheDocument());
    expect(screen.getByTestId("notification-unread-msg-1")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Mark read" }));

    await waitFor(() => expect(request).toHaveBeenCalledWith("/api/notification/v1/companies/company-a/messages/msg-1/read", { method: "POST" }));
    await waitFor(() => expect(screen.queryByTestId("notification-unread-msg-1")).not.toBeInTheDocument());
  });

  it("shows an error message when the inbox fetch fails", async () => {
    request.mockRejectedValue(new Error("boom"));
    render(<InboxPage context={context("company-a")} />);
    await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent("Could not load your inbox."));
  });
});
