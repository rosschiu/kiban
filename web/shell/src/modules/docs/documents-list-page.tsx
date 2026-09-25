// SPDX-License-Identifier: Apache-2.0

// The docs module's landing page (frontend.manifest.json route id "documents", path ""):
// owned + shared-with-me sections, empty states, New Document. THE first surface a human
// exercises: creating a document and seeing it become theirs to share.
import { type FormEvent, useCallback, useEffect, useState } from "react";
import { Link } from "@tanstack/react-router";
import { getShellSdk } from "../../auth/sdk";
import type { ModulePageContext } from "../../resolver/resolver";
import { Button } from "../../ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "../../ui/card";
import { EmptyState } from "../../ui/empty-state";
import { createDocsClient, type DocsDocument } from "./api";

export function DocumentsListPage({ context }: { context: ModulePageContext }) {
  const companyId = context.companyId;
  const [owned, setOwned] = useState<DocsDocument[] | null>(null);
  const [sharedWithMe, setSharedWithMe] = useState<DocsDocument[]>([]);
  const [title, setTitle] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);

  const load = useCallback(async (id: string) => {
    try {
      const client = createDocsClient(getShellSdk().apiClient);
      const result = await client.listDocuments(id);
      setOwned(result.owned);
      setSharedWithMe(result.sharedWithMe);
      setError(null);
    } catch {
      setError("Could not load documents.");
    }
  }, []);

  useEffect(() => {
    if (companyId) void load(companyId);
  }, [companyId, load]);

  async function handleCreate(event: FormEvent): Promise<void> {
    event.preventDefault();
    if (!companyId || !title.trim()) return;
    setCreating(true);
    try {
      const client = createDocsClient(getShellSdk().apiClient);
      await client.createDocument(companyId, { title: title.trim(), body: "" });
      setTitle("");
      void load(companyId);
    } catch {
      setError("Could not create the document.");
    } finally {
      setCreating(false);
    }
  }

  if (!companyId) return null;

  const documentHref = (docId: string) => `/app/c/${companyId}/docs/documents/${docId}`;

  return (
    <div className="flex flex-col gap-4" data-testid="docs-documents-page">
      <h1 className="text-lg font-semibold text-foreground">Documents</h1>

      {error ? (
        <p role="alert" className="text-sm text-destructive">
          {error}
        </p>
      ) : null}

      <Card>
        <CardHeader>
          <CardTitle>New document</CardTitle>
        </CardHeader>
        <CardContent>
          <form className="flex flex-wrap items-end gap-2" onSubmit={(event) => void handleCreate(event)}>
            <label className="flex flex-col gap-1 text-sm">
              Title
              <input
                className="rounded-md border border-input bg-background px-2 py-1 text-sm"
                data-testid="docs-new-title"
                value={title}
                onChange={(event) => setTitle(event.target.value)}
              />
            </label>
            <Button type="submit" size="sm" disabled={creating || !title.trim()} data-testid="docs-create-button">
              New Document
            </Button>
          </form>
        </CardContent>
      </Card>

      <section className="flex flex-col gap-2">
        <h2 className="text-sm font-medium text-muted-foreground">My documents</h2>
        {owned === null ? null : owned.length === 0 ? (
          <EmptyState title="No documents yet" description="Create a document to get started." />
        ) : (
          <ul className="flex flex-col gap-2" data-testid="docs-owned-list">
            {owned.map((doc) => (
              <li key={doc.id} data-testid={`docs-document-${doc.id}`}>
                <Link
                  to={documentHref(doc.id)}
                  className="flex items-center justify-between rounded-md border border-border px-3 py-2 hover:bg-accent"
                >
                  <span>{doc.title}</span>
                  <span className="text-xs text-muted-foreground">owner</span>
                </Link>
              </li>
            ))}
          </ul>
        )}
      </section>

      <section className="flex flex-col gap-2">
        <h2 className="text-sm font-medium text-muted-foreground">Shared with me</h2>
        {sharedWithMe.length === 0 ? (
          <EmptyState title="Nothing shared with you yet" description="Documents others share with you appear here." />
        ) : (
          <ul className="flex flex-col gap-2" data-testid="docs-shared-list">
            {sharedWithMe.map((doc) => (
              <li key={doc.id} data-testid={`docs-document-${doc.id}`}>
                <Link
                  to={documentHref(doc.id)}
                  className="flex items-center justify-between rounded-md border border-border px-3 py-2 hover:bg-accent"
                >
                  <span>{doc.title}</span>
                  <span className="text-xs text-muted-foreground">{doc.myRelation ?? "shared"}</span>
                </Link>
              </li>
            ))}
          </ul>
        )}
      </section>
    </div>
  );
}
