// SPDX-License-Identifier: Apache-2.0

// The helpdesk module's landing page (frontend.manifest.json route id "my-tickets", path ""):
// the caller's OWN reported tickets, list + status chips, New Ticket form, empty
// state. Every active company member reaches this page regardless of tier — the reporter-only
// "My tickets" view is what a plain member sees for the whole module.
import { type FormEvent, useCallback, useEffect, useState } from "react";
import { Link } from "@tanstack/react-router";
import { getShellSdk } from "../../auth/sdk";
import type { ModulePageContext } from "../../resolver/resolver";
import { Button } from "../../ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "../../ui/card";
import { EmptyState } from "../../ui/empty-state";
import { createHelpdeskClient, type HelpdeskTicket } from "./api";
import { HelpdeskSubNav } from "./sub-nav";
import { StatusChip } from "./status-chip";
import { useHelpdeskTier } from "./tier";

export function MyTicketsPage({ context }: { context: ModulePageContext }) {
  const companyId = context.companyId;
  const tier = useHelpdeskTier(companyId);

  const [tickets, setTickets] = useState<HelpdeskTicket[] | null>(null);
  const [title, setTitle] = useState("");
  const [description, setDescription] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);

  const load = useCallback(async (id: string) => {
    try {
      const client = createHelpdeskClient(getShellSdk().apiClient);
      const result = await client.listTickets(id, "mine");
      setTickets(result);
      setError(null);
    } catch {
      setError("Could not load your tickets.");
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
      const client = createHelpdeskClient(getShellSdk().apiClient);
      await client.createTicket(companyId, { title: title.trim(), description });
      setTitle("");
      setDescription("");
      void load(companyId);
    } catch {
      setError("Could not raise the ticket.");
    } finally {
      setCreating(false);
    }
  }

  if (!companyId) return null;

  const ticketHref = (ticketId: string) => `/app/c/${companyId}/helpdesk/tickets/${ticketId}`;

  return (
    <div className="flex flex-col gap-4" data-testid="helpdesk-my-tickets-page">
      <h1 className="text-lg font-semibold text-foreground">Helpdesk — My Tickets</h1>
      <HelpdeskSubNav companyId={companyId} tier={tier} />

      {error ? (
        <p role="alert" className="text-sm text-destructive">
          {error}
        </p>
      ) : null}

      <Card>
        <CardHeader>
          <CardTitle>Raise a ticket</CardTitle>
        </CardHeader>
        <CardContent>
          <form className="flex flex-col gap-2" onSubmit={(event) => void handleCreate(event)}>
            <label className="flex flex-col gap-1 text-sm">
              Title
              <input
                className="rounded-md border border-input bg-background px-2 py-1 text-sm"
                data-testid="helpdesk-new-title"
                value={title}
                onChange={(event) => setTitle(event.target.value)}
              />
            </label>
            <label className="flex flex-col gap-1 text-sm">
              Description
              <textarea
                className="min-h-20 rounded-md border border-input bg-background px-2 py-1 text-sm"
                data-testid="helpdesk-new-description"
                value={description}
                onChange={(event) => setDescription(event.target.value)}
              />
            </label>
            <div>
              <Button type="submit" size="sm" disabled={creating || !title.trim()} data-testid="helpdesk-create-button">
                New Ticket
              </Button>
            </div>
          </form>
        </CardContent>
      </Card>

      <section className="flex flex-col gap-2">
        {tickets === null ? null : tickets.length === 0 ? (
          <EmptyState title="No tickets yet" description="Raise a ticket above to get started." />
        ) : (
          <ul className="flex flex-col gap-2" data-testid="helpdesk-my-tickets-list">
            {tickets.map((t) => (
              <li key={t.id} data-testid={`helpdesk-ticket-${t.id}`}>
                <Link
                  to={ticketHref(t.id)}
                  className="flex flex-col gap-1 rounded-md border border-border px-3 py-2 hover:bg-accent"
                >
                  <div className="flex items-center justify-between">
                    <span>{t.title}</span>
                    <StatusChip status={t.status} />
                  </div>
                  <span className="text-xs text-muted-foreground" data-testid={`helpdesk-assignee-${t.id}`}>
                    {t.assigneeDisplayName ? `Assigned to ${t.assigneeDisplayName}` : "Unassigned"}
                  </span>
                </Link>
              </li>
            ))}
          </ul>
        )}
      </section>
    </div>
  );
}
