// SPDX-License-Identifier: Apache-2.0

// Thin, hand-written client for the docs module's own HTTP surface (modules/docs/openapi.yaml),
// built directly on the shared @rosschiu/kiban-sdk `ApiClient` — same pattern as
// web/shell/src/modules/notification/api.ts and .../timesheet/api.ts (a
// module's own API surface is the module's own concern, never added to the shared SDK package).
import type { ApiClient, Page } from "@rosschiu/kiban-sdk";

export type DocumentRelation = "owner" | "editor" | "viewer";

export interface DocsDocument {
  id: string;
  companyId: string;
  title: string;
  body: string;
  ownerKcSub: string;
  myRelation?: DocumentRelation;
  createdAt: string;
  updatedAt: string;
}

export interface DocsShare {
  id: string;
  documentId: string;
  memberId: string;
  relation: "viewer" | "editor";
  grantedBy: string;
  createdAt: string;
}

export interface DocsAuditEvent {
  occurredAt: string;
  actor: string;
  action: string;
  subject: string;
  payload: Record<string, unknown>;
}

export interface DocsClient {
  listDocuments(companyId: string): Promise<{ owned: DocsDocument[]; sharedWithMe: DocsDocument[] }>;
  createDocument(companyId: string, input: { title: string; body: string }): Promise<DocsDocument>;
  getDocument(companyId: string, docId: string): Promise<DocsDocument>;
  updateDocument(companyId: string, docId: string, input: { title: string; body: string }): Promise<DocsDocument>;
  deleteDocument(companyId: string, docId: string): Promise<void>;
  listShares(companyId: string, docId: string): Promise<DocsShare[]>;
  createShare(companyId: string, docId: string, input: { memberId: string; relation: "viewer" | "editor" }): Promise<DocsShare>;
  revokeShare(companyId: string, docId: string, memberId: string): Promise<void>;
  getDocumentAudit(companyId: string, docId: string): Promise<DocsAuditEvent[]>;
  getModuleAudit(companyId: string, page?: number, pageSize?: number): Promise<Page<DocsAuditEvent>>;
}

function base(companyId: string): string {
  return `/api/docs/v1/companies/${encodeURIComponent(companyId)}`;
}

export function createDocsClient(client: ApiClient): DocsClient {
  return {
    listDocuments: (companyId) => client.request(`${base(companyId)}/documents`),

    createDocument: (companyId, input) => client.request(`${base(companyId)}/documents`, { method: "POST", body: input }),

    getDocument: (companyId, docId) => client.request(`${base(companyId)}/documents/${encodeURIComponent(docId)}`),

    updateDocument: (companyId, docId, input) =>
      client.request(`${base(companyId)}/documents/${encodeURIComponent(docId)}`, { method: "PUT", body: input }),

    deleteDocument: (companyId, docId) =>
      client.request(`${base(companyId)}/documents/${encodeURIComponent(docId)}`, { method: "DELETE" }),

    listShares: (companyId, docId) => client.request(`${base(companyId)}/documents/${encodeURIComponent(docId)}/shares`),

    createShare: (companyId, docId, input) =>
      client.request(`${base(companyId)}/documents/${encodeURIComponent(docId)}/shares`, { method: "POST", body: input }),

    revokeShare: (companyId, docId, memberId) =>
      client.request(`${base(companyId)}/documents/${encodeURIComponent(docId)}/shares/${encodeURIComponent(memberId)}`, {
        method: "DELETE"
      }),

    getDocumentAudit: (companyId, docId) => client.request(`${base(companyId)}/documents/${encodeURIComponent(docId)}/audit`),

    getModuleAudit: (companyId, page, pageSize) => client.request(`${base(companyId)}/audit`, { query: { page, pageSize } })
  };
}
