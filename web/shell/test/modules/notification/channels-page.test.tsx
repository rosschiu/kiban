// SPDX-License-Identifier: Apache-2.0

import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { ModulePageContext } from "../../../src/resolver/resolver";

const request = vi.fn();
vi.mock("../../../src/auth/sdk", () => ({
  getShellSdk: () => ({ apiClient: { baseUrl: "https://gw.example", request } }),
}));

const { ChannelsPage } = await import("../../../src/modules/notification/channels-page");

function context(companyId?: string): ModulePageContext {
  return { moduleKey: "notification", companyId, featureKey: "notification.access", params: {}, remoteExport: "ChannelsPage" };
}

function page(items: unknown[]) {
  return { items, total: items.length, page: 1, pageSize: 100, totalPages: 1 };
}

describe("ChannelsPage", () => {
  beforeEach(() => {
    request.mockReset();
  });

  it("renders nothing without a companyId", () => {
    const { container } = render(<ChannelsPage context={context(undefined)} />);
    expect(container).toBeEmptyDOMElement();
  });

  it("renders the empty state when there are no channels", async () => {
    request.mockResolvedValue(page([]));
    render(<ChannelsPage context={context("company-a")} />);
    await waitFor(() => expect(screen.getByText("No channels yet")).toBeInTheDocument());
  });

  it("creates a channel via the form and reloads the list", async () => {
    const user = userEvent.setup();
    request
      .mockResolvedValueOnce(page([])) // initial load
      .mockResolvedValueOnce({ id: "c1", key: "k", label: "L", kind: "in_app", target: null, companyId: "company-a", createdAt: "now" }) // create
      .mockResolvedValueOnce(page([{ id: "c1", key: "k", label: "L", kind: "in_app", target: null, companyId: "company-a", createdAt: "now" }])); // reload

    render(<ChannelsPage context={context("company-a")} />);
    await waitFor(() => expect(screen.getByText("No channels yet")).toBeInTheDocument());

    await user.type(screen.getByLabelText("Key"), "k");
    await user.type(screen.getByLabelText("Label"), "L");
    await user.click(screen.getByRole("button", { name: "Create" }));

    await waitFor(() =>
      expect(request).toHaveBeenCalledWith("/api/notification/v1/companies/company-a/channels", {
        method: "POST",
        body: { key: "k", label: "L", kind: "in_app" },
      }),
    );
    await waitFor(() => expect(screen.getByTestId("notification-channels-list")).toHaveTextContent("L (k)"));
  });

  it("subscribes to a channel and disables the button once subscribed", async () => {
    const user = userEvent.setup();
    request
      .mockResolvedValueOnce(page([{ id: "c1", key: "k", label: "L", kind: "in_app", target: null, companyId: "company-a", createdAt: "now" }]))
      .mockResolvedValueOnce(undefined); // subscribe

    render(<ChannelsPage context={context("company-a")} />);
    await waitFor(() => expect(screen.getByRole("button", { name: "Subscribe" })).toBeInTheDocument());

    await user.click(screen.getByRole("button", { name: "Subscribe" }));

    await waitFor(() =>
      expect(request).toHaveBeenCalledWith("/api/notification/v1/companies/company-a/channels/c1/subscriptions", { method: "POST" }),
    );
    await waitFor(() => expect(screen.getByRole("button", { name: "Subscribed" })).toBeDisabled());
  });

  it("shows an error message when the channel list fetch fails", async () => {
    request.mockRejectedValue(new Error("boom"));
    render(<ChannelsPage context={context("company-a")} />);
    await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent("Could not load channels."));
  });
});
