// SPDX-License-Identifier: Apache-2.0

// The docs module's document view/edit page (frontend.manifest.json route id "document", path
// "documents/:docId"). Title + markdown body (plain textarea + rendered preview, no
// WYSIWYG), Save for editors, read-only rendering for viewers. Also hosts the Share
// dialog (the demo surface: member picker fed by the org member directory, viewer/editor choice,
// current shares with revoke buttons, immediate visible state changes) and the per-document audit
// panel (human-readable event list — the visible-audit selling point).
import { type FormEvent, useCallback, useEffect, useState } from "react";
import { createOrgClient, type MemberDirectoryEntry } from "@rosschiu/kiban-sdk";
import { getShellSdk } from "../../auth/sdk";
import { describeApiError } from "../../lib/api-error";
import type { ModulePageContext } from "../../resolver/resolver";
import { Button } from "../../ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "../../ui/card";
import { Sheet, SheetContent, SheetHeader, SheetTitle, SheetDescription } from "../../ui/sheet";
import { createDocsClient, type DocsAuditEvent, type DocsDocument, type DocsShare } from "./api";
import { renderMarkdown } from "./markdown";

function describeAuditEvent(e: DocsAuditEvent): string {
  const payload = e.payload ?? {};
  switch (e.action) {
    case "docs.document.create":
      return `${e.actor} created this document`;
    case "docs.document.update":
      return `${e.actor} edited this document`;
    case "docs.document.delete":
      return `${e.actor} deleted this document`;
    case "docs.share.grant": {
      const relation = typeof payload.relation === "string" ? payload.relation : "viewer";
      return `${e.actor} shared with a member as ${relation}`;
    }
    case "docs.share.revoke":
      return `${e.actor} revoked a member's access`;
    default:
      return `${e.actor} performed ${e.action}`;
  }
}

const DOCUMENT_UNAVAILABLE =
  "This document doesn't exist, or you don't have access to it. Access is granted and revoked explicitly; there is no bypass, so even a superadmin cannot read a document nobody has shared with them.";

export function DocumentPage({ context }: { context: ModulePageContext }) {
  const companyId = context.companyId;
  const docId = context.params.docId;

  const [doc, setDoc] = useState<DocsDocument | null>(null);
  const [title, setTitle] = useState("");
  const [body, setBody] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [loadError, setLoadError] = useState<string | null>(null);

  const [shares, setShares] = useState<DocsShare[]>([]);
  const [shareOpen, setShareOpen] = useState(false);
  const [memberQuery, setMemberQuery] = useState("");
  const [memberResults, setMemberResults] = useState<MemberDirectoryEntry[]>([]);
  const [shareRelation, setShareRelation] = useState<"viewer" | "editor">("viewer");
  const [shareError, setShareError] = useState<string | null>(null);

  const [auditEvents, setAuditEvents] = useState<DocsAuditEvent[]>([]);

  const load = useCallback(async (cid: string, id: string) => {
    try {
      const client = createDocsClient(getShellSdk().apiClient);
      const [d, sh, audit] = await Promise.all([
        client.getDocument(cid, id),
        client.listShares(cid, id).catch(() => []),
        client.getDocumentAudit(cid, id).catch(() => []),
      ]);
      setDoc(d);
      setTitle(d.title);
      setBody(d.body);
      setShares(sh);
      setAuditEvents(audit);
      setLoadError(null);
      setError(null);
    } catch (err) {
      setLoadError(describeApiError(err, DOCUMENT_UNAVAILABLE));
    }
  }, []);

  useEffect(() => {
    if (companyId && docId) void load(companyId, docId);
  }, [companyId, docId, load]);

  useEffect(() => {
    if (!companyId || !shareOpen) return;
    const handle = window.setTimeout(() => {
      const orgClient = createOrgClient(getShellSdk().apiClient);
      void orgClient
        .memberDirectory(companyId, memberQuery || undefined, 1, 20)
        .then((page) => setMemberResults(page.items))
        .catch(() => setMemberResults([]));
    }, 200);
    return () => window.clearTimeout(handle);
  }, [companyId, shareOpen, memberQuery]);

  async function handleSave(event: FormEvent): Promise<void> {
    event.preventDefault();
    if (!companyId || !docId || !doc) return;
    setSaving(true);
    try {
      const client = createDocsClient(getShellSdk().apiClient);
      const updated = await client.updateDocument(companyId, docId, { title, body });
      setDoc(updated);
      setError(null);
    } catch (err) {
      setError(describeApiError(err, "Could not save changes — you may not have editor access."));
    } finally {
      setSaving(false);
    }
  }

  async function refreshShares(): Promise<void> {
    if (!companyId || !docId) return;
    const client = createDocsClient(getShellSdk().apiClient);
    const [sh, audit] = await Promise.all([client.listShares(companyId, docId), client.getDocumentAudit(companyId, docId)]);
    setShares(sh);
    setAuditEvents(audit);
  }

  async function handleShare(memberId: string): Promise<void> {
    if (!companyId || !docId) return;
    setShareError(null);
    try {
      const client = createDocsClient(getShellSdk().apiClient);
      await client.createShare(companyId, docId, { memberId, relation: shareRelation });
      await refreshShares();
    } catch (err) {
      setShareError(describeApiError(err, "Could not share this document with that member."));
    }
  }

  async function handleRevoke(memberId: string): Promise<void> {
    if (!companyId || !docId) return;
    setShareError(null);
    try {
      const client = createDocsClient(getShellSdk().apiClient);
      await client.revokeShare(companyId, docId, memberId);
      await refreshShares();
    } catch (err) {
      setShareError(describeApiError(err, "Could not revoke that member's access."));
    }
  }

  if (!companyId || !docId) return null;

  if (loadError) {
    return (
      <div className="flex flex-col gap-2" data-testid="docs-document-denied">
        <h1 className="text-lg font-semibold text-foreground">Document unavailable</h1>
        <p className="text-sm text-muted-foreground">{loadError}</p>
      </div>
    );
  }

  if (!doc) return null;

  const isOwner = doc.myRelation === "owner";
  const canEdit = doc.myRelation === "owner" || doc.myRelation === "editor";

  return (
    <div className="flex flex-col gap-4" data-testid="docs-document-page">
      <div className="flex items-center justify-between">
        <h1 className="text-lg font-semibold text-foreground" data-testid="docs-document-title">
          {doc.title}
        </h1>
        {isOwner ? (
          <Button type="button" size="sm" variant="outline" data-testid="docs-share-button" onClick={() => setShareOpen(true)}>
            Share
          </Button>
        ) : null}
      </div>

      {error ? (
        <p role="alert" className="text-sm text-destructive">
          {error}
        </p>
      ) : null}

      <Card>
        <CardHeader>
          <CardTitle>{canEdit ? "Edit" : "View"}</CardTitle>
        </CardHeader>
        <CardContent>
          {canEdit ? (
            <form className="flex flex-col gap-3" onSubmit={(event) => void handleSave(event)}>
              <label className="flex flex-col gap-1 text-sm">
                Title
                <input
                  className="rounded-md border border-input bg-background px-2 py-1 text-sm"
                  data-testid="docs-title-input"
                  value={title}
                  onChange={(event) => setTitle(event.target.value)}
                />
              </label>
              <label className="flex flex-col gap-1 text-sm">
                Body (markdown)
                <textarea
                  className="min-h-40 rounded-md border border-input bg-background px-2 py-1 text-sm font-mono"
                  data-testid="docs-body-input"
                  value={body}
                  onChange={(event) => setBody(event.target.value)}
                />
              </label>
              <div>
                <Button type="submit" size="sm" disabled={saving} data-testid="docs-save-button">
                  Save
                </Button>
              </div>
            </form>
          ) : (
            <div
              className="prose prose-sm max-w-none text-foreground"
              data-testid="docs-body-preview"
              // Safe: renderMarkdown escapes raw input before applying its own limited markup —
              // see markdown.ts's own header comment.
              dangerouslySetInnerHTML={{ __html: renderMarkdown(doc.body) }}
            />
          )}
          {canEdit ? (
            <div className="mt-3 border-t border-border pt-3">
              <p className="mb-1 text-xs font-medium text-muted-foreground">Preview</p>
              <div
                className="prose prose-sm max-w-none text-foreground"
                data-testid="docs-body-preview"
                dangerouslySetInnerHTML={{ __html: renderMarkdown(body) }}
              />
            </div>
          ) : null}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Audit trail</CardTitle>
        </CardHeader>
        <CardContent>
          {auditEvents.length === 0 ? (
            <p className="text-sm text-muted-foreground">No activity recorded yet.</p>
          ) : (
            <ul className="flex flex-col gap-1 text-sm" data-testid="docs-audit-list">
              {auditEvents.map((e, i) => (
                <li key={`${e.occurredAt}-${i}`} className="flex items-center justify-between">
                  <span>{describeAuditEvent(e)}</span>
                  <span className="text-xs text-muted-foreground">{new Date(e.occurredAt).toLocaleString()}</span>
                </li>
              ))}
            </ul>
          )}
        </CardContent>
      </Card>

      <Sheet open={shareOpen} onOpenChange={setShareOpen}>
        <SheetContent side="right" data-testid="docs-share-sheet">
          <SheetHeader>
            <SheetTitle>Share &quot;{doc.title}&quot;</SheetTitle>
            <SheetDescription>Grant a company member viewer or editor access. Changes take effect immediately.</SheetDescription>
          </SheetHeader>
          <div className="flex flex-col gap-3 px-4 pb-4">
            {shareError ? (
              <p role="alert" className="text-sm text-destructive">
                {shareError}
              </p>
            ) : null}

            <div className="flex flex-col gap-2">
              <label className="flex flex-col gap-1 text-sm">
                Search members
                <input
                  className="rounded-md border border-input bg-background px-2 py-1 text-sm"
                  data-testid="docs-member-search"
                  value={memberQuery}
                  onChange={(event) => setMemberQuery(event.target.value)}
                  placeholder="Type a name or email…"
                />
              </label>
              <div className="flex items-center gap-2 text-sm">
                <label className="flex items-center gap-1">
                  <input
                    type="radio"
                    name="docs-share-relation"
                    checked={shareRelation === "viewer"}
                    onChange={() => setShareRelation("viewer")}
                  />
                  Viewer
                </label>
                <label className="flex items-center gap-1">
                  <input
                    type="radio"
                    name="docs-share-relation"
                    checked={shareRelation === "editor"}
                    onChange={() => setShareRelation("editor")}
                  />
                  Editor
                </label>
              </div>
              <ul className="flex flex-col gap-1" data-testid="docs-member-results">
                {memberResults.map((m) => (
                  <li key={m.id} className="flex items-center justify-between rounded-md border border-border px-2 py-1 text-sm">
                    <span>
                      {m.displayName} <span className="text-xs text-muted-foreground">({m.email})</span>
                    </span>
                    <Button
                      type="button"
                      size="sm"
                      disabled={!m.hasLinkedUser}
                      data-testid={`docs-share-with-${m.id}`}
                      onClick={() => void handleShare(m.id)}
                    >
                      Share
                    </Button>
                  </li>
                ))}
              </ul>
            </div>

            <div className="flex flex-col gap-2 border-t border-border pt-3">
              <p className="text-sm font-medium text-foreground">Current shares</p>
              {shares.length === 0 ? (
                <p className="text-sm text-muted-foreground">Not shared with anyone yet.</p>
              ) : (
                <ul className="flex flex-col gap-1" data-testid="docs-current-shares">
                  {shares.map((sh) => (
                    <li
                      key={sh.id}
                      data-testid={`docs-share-row-${sh.memberId}`}
                      className="flex items-center justify-between rounded-md border border-border px-2 py-1 text-sm"
                    >
                      <span>
                        member {sh.memberId.slice(0, 8)}… <span className="text-xs text-muted-foreground">({sh.relation})</span>
                      </span>
                      <Button
                        type="button"
                        size="sm"
                        variant="outline"
                        data-testid={`docs-revoke-${sh.memberId}`}
                        onClick={() => void handleRevoke(sh.memberId)}
                      >
                        Revoke
                      </Button>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </div>
        </SheetContent>
      </Sheet>
    </div>
  );
}
