// SPDX-License-Identifier: Apache-2.0

import { render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { ModulePageContext } from "../../../src/resolver/resolver";

const request = vi.fn();
vi.mock("../../../src/auth/sdk", () => ({
  getShellSdk: () => ({ apiClient: { baseUrl: "https://gw.example", request } }),
}));

const { AdminPage } = await import("../../../src/modules/docs/admin-page");

function context(companyId?: string): ModulePageContext {
  return { moduleKey: "docs", companyId, featureKey: "docs.access", params: {}, remoteExport: "AdminPage" };
}

function page(items: unknown[]) {
  return { items, total: items.length, page: 1, pageSize: 100, totalPages: 1 };
}

describe("AdminPage", () => {
  beforeEach(() => {
    request.mockReset();
  });

  it("renders nothing without a companyId", () => {
    const { container } = render(<AdminPage context={context(undefined)} />);
    expect(container).toBeEmptyDOMElement();
  });

  it("shows the docs.manage explainer and an empty state with no events", async () => {
    request.mockResolvedValue(page([]));
    render(<AdminPage context={context("company-a")} />);
    await waitFor(() => expect(screen.getByText("No activity yet")).toBeInTheDocument());
    expect(screen.getByTestId("docs-admin-explainer")).toHaveTextContent("never the documents' own content");
  });

  it("renders module-wide audit events without leaking document content", async () => {
    request.mockResolvedValue(
      page([{ occurredAt: "2026-01-01T00:00:00Z", actor: "alice", action: "docs.share.grant", subject: "docs_document:doc-1", payload: {} }]),
    );
    render(<AdminPage context={context("company-a")} />);
    await waitFor(() => expect(screen.getByText("alice — docs.share.grant — docs_document:doc-1")).toBeInTheDocument());
  });

  it("shows an error message when the audit fetch fails", async () => {
    request.mockRejectedValue(new Error("403"));
    render(<AdminPage context={context("company-a")} />);
    await waitFor(() =>
      expect(screen.getByRole("alert")).toHaveTextContent("Could not load the module audit trail — this view requires docs.manage."),
    );
  });
});
