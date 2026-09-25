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

const { DocumentsListPage } = await import("../../../src/modules/docs/documents-list-page");

function context(companyId?: string): ModulePageContext {
  return { moduleKey: "docs", companyId, featureKey: "docs.access", params: {}, remoteExport: "DocumentsListPage" };
}

function doc(overrides: Partial<Record<string, unknown>> = {}) {
  return {
    id: "doc-1",
    companyId: "company-a",
    title: "Runbook",
    body: "",
    ownerKcSub: "alice",
    createdAt: "now",
    updatedAt: "now",
    ...overrides,
  };
}

// DocumentsListPage renders through @tanstack/react-router's <Link>, which requires a Router
// context ancestor — same pattern test/nav/sidebar-nav.test.tsx uses for the identical reason.
async function renderPage(companyId?: string) {
  const rootRoute = createRootRoute({ component: () => <DocumentsListPage context={context(companyId)} /> });
  const routeTree = rootRoute.addChildren([]);
  const router = createRouter({ routeTree, history: createMemoryHistory({ initialEntries: ["/app"] }) });
  await act(async () => {
    render(<RouterProvider router={router} />);
    await router.load();
  });
}

describe("DocumentsListPage", () => {
  beforeEach(() => {
    request.mockReset();
  });

  it("renders nothing without a companyId", async () => {
    await renderPage(undefined);
    expect(screen.queryByTestId("docs-documents-page")).not.toBeInTheDocument();
  });

  it("renders empty states when there are no documents", async () => {
    request.mockResolvedValue({ owned: [], sharedWithMe: [] });
    await renderPage("company-a");
    await waitFor(() => expect(screen.getByText("No documents yet")).toBeInTheDocument());
    expect(screen.getByText("Nothing shared with you yet")).toBeInTheDocument();
  });

  it("renders owned and shared-with-me documents", async () => {
    request.mockResolvedValue({
      owned: [doc({ id: "doc-1", title: "Owned Doc", myRelation: "owner" })],
      sharedWithMe: [doc({ id: "doc-2", title: "Shared Doc", myRelation: "viewer" })],
    });
    await renderPage("company-a");
    await waitFor(() => expect(screen.getByText("Owned Doc")).toBeInTheDocument());
    expect(screen.getByText("Shared Doc")).toBeInTheDocument();
  });

  it("creates a new document and reloads the list", async () => {
    const user = userEvent.setup();
    request
      .mockResolvedValueOnce({ owned: [], sharedWithMe: [] })
      .mockResolvedValueOnce(doc())
      .mockResolvedValueOnce({ owned: [doc()], sharedWithMe: [] });

    await renderPage("company-a");
    await waitFor(() => expect(screen.getByText("No documents yet")).toBeInTheDocument());

    await user.type(screen.getByTestId("docs-new-title"), "Runbook");
    await user.click(screen.getByTestId("docs-create-button"));

    await waitFor(() =>
      expect(request).toHaveBeenCalledWith("/api/docs/v1/companies/company-a/documents", {
        method: "POST",
        body: { title: "Runbook", body: "" },
      }),
    );
    await waitFor(() => expect(screen.getByText("Runbook")).toBeInTheDocument());
  });

  it("shows an error message when the list fetch fails", async () => {
    request.mockRejectedValue(new Error("boom"));
    await renderPage("company-a");
    await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent("Could not load documents."));
  });
});
