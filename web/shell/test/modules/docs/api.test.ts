// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it, vi } from "vitest";
import { createDocsClient } from "../../../src/modules/docs/api";

function fakeClient() {
  return { baseUrl: "https://gw.example", request: vi.fn().mockResolvedValue(undefined) };
}

describe("createDocsClient", () => {
  it("lists documents for a company", async () => {
    const client = fakeClient();
    await createDocsClient(client).listDocuments("company-a");
    expect(client.request).toHaveBeenCalledWith("/api/docs/v1/companies/company-a/documents");
  });

  it("creates a document via POST with the input as the body", async () => {
    const client = fakeClient();
    const input = { title: "T", body: "B" };
    await createDocsClient(client).createDocument("company-a", input);
    expect(client.request).toHaveBeenCalledWith("/api/docs/v1/companies/company-a/documents", {
      method: "POST",
      body: input,
    });
  });

  it("gets a single document", async () => {
    const client = fakeClient();
    await createDocsClient(client).getDocument("company-a", "doc-1");
    expect(client.request).toHaveBeenCalledWith("/api/docs/v1/companies/company-a/documents/doc-1");
  });

  it("updates a document via PUT with the input as the body", async () => {
    const client = fakeClient();
    const input = { title: "T2", body: "B2" };
    await createDocsClient(client).updateDocument("company-a", "doc-1", input);
    expect(client.request).toHaveBeenCalledWith("/api/docs/v1/companies/company-a/documents/doc-1", {
      method: "PUT",
      body: input,
    });
  });

  it("deletes a document via DELETE", async () => {
    const client = fakeClient();
    await createDocsClient(client).deleteDocument("company-a", "doc-1");
    expect(client.request).toHaveBeenCalledWith("/api/docs/v1/companies/company-a/documents/doc-1", {
      method: "DELETE",
    });
  });

  it("lists a document's shares", async () => {
    const client = fakeClient();
    await createDocsClient(client).listShares("company-a", "doc-1");
    expect(client.request).toHaveBeenCalledWith("/api/docs/v1/companies/company-a/documents/doc-1/shares");
  });

  it("creates a share via POST with memberId + relation as the body", async () => {
    const client = fakeClient();
    const input = { memberId: "member-1", relation: "viewer" as const };
    await createDocsClient(client).createShare("company-a", "doc-1", input);
    expect(client.request).toHaveBeenCalledWith("/api/docs/v1/companies/company-a/documents/doc-1/shares", {
      method: "POST",
      body: input,
    });
  });

  it("revokes a share via DELETE to the member's own sub-resource", async () => {
    const client = fakeClient();
    await createDocsClient(client).revokeShare("company-a", "doc-1", "member-1");
    expect(client.request).toHaveBeenCalledWith(
      "/api/docs/v1/companies/company-a/documents/doc-1/shares/member-1",
      { method: "DELETE" },
    );
  });

  it("gets a document's own audit trail", async () => {
    const client = fakeClient();
    await createDocsClient(client).getDocumentAudit("company-a", "doc-1");
    expect(client.request).toHaveBeenCalledWith("/api/docs/v1/companies/company-a/documents/doc-1/audit");
  });

  it("gets the module-wide audit trail with pagination query params", async () => {
    const client = fakeClient();
    await createDocsClient(client).getModuleAudit("company-a", 2, 50);
    expect(client.request).toHaveBeenCalledWith("/api/docs/v1/companies/company-a/audit", {
      query: { page: 2, pageSize: 50 },
    });
  });

  it("URI-encodes path segments", async () => {
    const client = fakeClient();
    await createDocsClient(client).getDocument("company a/b", "doc 1");
    expect(client.request).toHaveBeenCalledWith("/api/docs/v1/companies/company%20a%2Fb/documents/doc%201");
  });
});
