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

const { DocumentPage } = await import("../../../src/modules/docs/document-page");

function context(companyId?: string, docId?: string): ModulePageContext {
  return {
    moduleKey: "docs",
    companyId,
    featureKey: "docs.access",
    params: docId ? { docId } : {},
    remoteExport: "DocumentPage",
  };
}

function doc(overrides: Partial<Record<string, unknown>> = {}) {
  return {
    id: "doc-1",
    companyId: "company-a",
    title: "Runbook",
    body: "hello",
    ownerKcSub: "alice",
    myRelation: "owner",
    createdAt: "2026-01-01T00:00:00Z",
    updatedAt: "2026-01-01T00:00:00Z",
    ...overrides,
  };
}

async function renderPage(companyId?: string, docId?: string) {
  const rootRoute = createRootRoute({ component: () => <DocumentPage context={context(companyId, docId)} /> });
  const routeTree = rootRoute.addChildren([]);
  const router = createRouter({ routeTree, history: createMemoryHistory({ initialEntries: ["/app"] }) });
  await act(async () => {
    render(<RouterProvider router={router} />);
    await router.load();
  });
}

describe("DocumentPage", () => {
  beforeEach(() => {
    request.mockReset();
  });

  it("renders nothing without a companyId or docId", async () => {
    await renderPage(undefined, "doc-1");
    expect(screen.queryByTestId("docs-document-page")).not.toBeInTheDocument();
    await renderPage("company-a", undefined);
    expect(screen.queryByTestId("docs-document-page")).not.toBeInTheDocument();
  });

  it("shows the excludability denied state when the load fails (unshared/nonexistent doc)", async () => {
    request.mockRejectedValue(new Error("403"));
    await renderPage("company-a", "doc-1");
    await waitFor(() => expect(screen.getByTestId("docs-document-denied")).toBeInTheDocument());
  });

  it("owner sees an editable form, a Share button, and can save", async () => {
    const d = doc();
    request.mockImplementation((url: string, opts?: { method?: string; body?: unknown }) => {
      if (url.endsWith("/documents/doc-1") && (!opts || !opts.method)) return Promise.resolve(d);
      if (url.endsWith("/shares")) return Promise.resolve([]);
      if (url.endsWith("/audit")) return Promise.resolve([]);
      if (url.endsWith("/documents/doc-1") && opts?.method === "PUT") {
        return Promise.resolve({ ...d, title: (opts.body as { title: string }).title });
      }
      return Promise.resolve(undefined);
    });

    await renderPage("company-a", "doc-1");
    await waitFor(() => expect(screen.getByTestId("docs-document-page")).toBeInTheDocument());
    expect(screen.getByTestId("docs-share-button")).toBeInTheDocument();
    expect(screen.getByTestId("docs-title-input")).toHaveValue("Runbook");

    const user = userEvent.setup();
    await user.clear(screen.getByTestId("docs-title-input"));
    await user.type(screen.getByTestId("docs-title-input"), "Runbook v2");
    await user.click(screen.getByTestId("docs-save-button"));

    await waitFor(() =>
      expect(request).toHaveBeenCalledWith("/api/docs/v1/companies/company-a/documents/doc-1", {
        method: "PUT",
        body: { title: "Runbook v2", body: "hello" },
      }),
    );
  });

  it("a viewer sees read-only rendered markdown and no Share button", async () => {
    const d = doc({ myRelation: "viewer", body: "# Title\nSome **bold** text" });
    request.mockImplementation((url: string) => {
      if (url.endsWith("/documents/doc-1")) return Promise.resolve(d);
      if (url.endsWith("/shares")) return Promise.resolve([]);
      if (url.endsWith("/audit")) return Promise.resolve([]);
      return Promise.resolve(undefined);
    });

    await renderPage("company-a", "doc-1");
    await waitFor(() => expect(screen.getByTestId("docs-document-page")).toBeInTheDocument());
    expect(screen.queryByTestId("docs-share-button")).not.toBeInTheDocument();
    expect(screen.queryByTestId("docs-title-input")).not.toBeInTheDocument();
    expect(screen.getByTestId("docs-body-preview").innerHTML).toContain("<h1>Title</h1>");
  });

  it("shows the document's audit trail", async () => {
    const d = doc();
    request.mockImplementation((url: string) => {
      if (url.endsWith("/documents/doc-1")) return Promise.resolve(d);
      if (url.endsWith("/shares")) return Promise.resolve([]);
      if (url.endsWith("/audit")) {
        return Promise.resolve([
          { occurredAt: "2026-01-01T00:00:00Z", actor: "alice", action: "docs.document.create", subject: "docs_document:doc-1", payload: {} },
        ]);
      }
      return Promise.resolve(undefined);
    });

    await renderPage("company-a", "doc-1");
    await waitFor(() => expect(screen.getByText("alice created this document")).toBeInTheDocument());
  });

  it("owner can open the share sheet, search members, share, and revoke", async () => {
    const d = doc();
    let shares: unknown[] = [];
    request.mockImplementation((url: string, opts?: { method?: string; body?: unknown }) => {
      if (url.endsWith("/documents/doc-1") && (!opts || !opts.method)) return Promise.resolve(d);
      if (url.endsWith("/audit")) return Promise.resolve([]);
      if (url.includes("/documents/doc-1/shares") && opts?.method === "POST") {
        shares = [{ id: "share-1", documentId: "doc-1", memberId: "member-1", relation: "viewer", grantedBy: "alice", createdAt: "now" }];
        return Promise.resolve(shares[0]);
      }
      if (url.includes("/documents/doc-1/shares/member-1") && opts?.method === "DELETE") {
        shares = [];
        return Promise.resolve(undefined);
      }
      if (url.endsWith("/shares")) return Promise.resolve(shares);
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

    await renderPage("company-a", "doc-1");
    await waitFor(() => expect(screen.getByTestId("docs-document-page")).toBeInTheDocument());

    const user = userEvent.setup();
    await user.click(screen.getByTestId("docs-share-button"));
    await waitFor(() => expect(screen.getByTestId("docs-share-sheet")).toBeInTheDocument());
    await waitFor(() => expect(screen.getByTestId("docs-share-with-member-1")).toBeInTheDocument(), { timeout: 2000 });

    await user.click(screen.getByTestId("docs-share-with-member-1"));
    await waitFor(() => expect(screen.getByTestId("docs-share-row-member-1")).toBeInTheDocument());

    await user.click(screen.getByTestId("docs-revoke-member-1"));
    await waitFor(() => expect(screen.queryByTestId("docs-share-row-member-1")).not.toBeInTheDocument());
  });
});
