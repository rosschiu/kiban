// SPDX-License-Identifier: Apache-2.0

// The docs module's admin page (frontend.manifest.json route id "admin", path "admin", gated by
// docs.manage). Module-wide audit trail; shows the admin does NOT see document
// content, only events — the explainer line below states exactly that, and the API this page
// calls (`GET /v1/companies/{companyId}/audit`) structurally never returns body text (see
// modules/docs/service/store.go's ModuleAudit doc comment).
import { useCallback, useEffect, useState } from "react";
import { getShellSdk } from "../../auth/sdk";
import type { ModulePageContext } from "../../resolver/resolver";
import { Card, CardContent, CardHeader, CardTitle } from "../../ui/card";
import { EmptyState } from "../../ui/empty-state";
import { createDocsClient, type DocsAuditEvent } from "./api";

export function AdminPage({ context }: { context: ModulePageContext }) {
  const companyId = context.companyId;
  const [events, setEvents] = useState<DocsAuditEvent[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async (id: string) => {
    try {
      const client = createDocsClient(getShellSdk().apiClient);
      const page = await client.getModuleAudit(id, 1, 100);
      setEvents(page.items);
      setError(null);
    } catch {
      setError("Could not load the module audit trail — this view requires docs.manage.");
    }
  }, []);

  useEffect(() => {
    if (companyId) void load(companyId);
  }, [companyId, load]);

  if (!companyId) return null;

  return (
    <div className="flex flex-col gap-4" data-testid="docs-admin-page">
      <h1 className="text-lg font-semibold text-foreground">Docs — module audit trail</h1>
      <p className="text-sm text-muted-foreground" data-testid="docs-admin-explainer">
        As a docs module admin you can see who shared, edited, or revoked access to which documents and when, never
        the documents&apos; own content. Reading a document still requires an explicit per-document grant, even for
        a platform superadmin.
      </p>

      {error ? (
        <p role="alert" className="text-sm text-destructive">
          {error}
        </p>
      ) : null}

      <Card>
        <CardHeader>
          <CardTitle>Events</CardTitle>
        </CardHeader>
        <CardContent>
          {events === null ? null : events.length === 0 ? (
            <EmptyState title="No activity yet" description="Docs module events will appear here as they happen." />
          ) : (
            <ul className="flex flex-col gap-1 text-sm" data-testid="docs-admin-audit-list">
              {events.map((e, i) => (
                <li key={`${e.occurredAt}-${i}`} className="flex items-center justify-between border-b border-border py-1">
                  <span>
                    {e.actor} — {e.action} — {e.subject}
                  </span>
                  <span className="text-xs text-muted-foreground">{new Date(e.occurredAt).toLocaleString()}</span>
                </li>
              ))}
            </ul>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
