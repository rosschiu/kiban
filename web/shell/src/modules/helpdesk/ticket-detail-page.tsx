// SPDX-License-Identifier: Apache-2.0

// The helpdesk module's ticket detail page (frontend.manifest.json route id "ticket-detail",
// path "tickets/:ticketId"): description, status timeline (from audit events),
// comment thread, allowed actions computed from the caller's tier. THE surface where the tier
// contrast is most visible: a plain member (the reporter) sees only their own reopen/close
// buttons on a resolved ticket; an agent sees progress/resolve buttons while assigned; an admin
// sees every transition regardless of assignment.
import { type FormEvent, useCallback, useEffect, useState } from "react";
import { getShellSdk } from "../../auth/sdk";
import { describeApiError } from "../../lib/api-error";
import type { ModulePageContext } from "../../resolver/resolver";
import { Button } from "../../ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "../../ui/card";
import { EmptyState } from "../../ui/empty-state";
import { createHelpdeskClient, type HelpdeskAuditEvent, type HelpdeskComment, type HelpdeskTicket } from "./api";
import { HelpdeskSubNav } from "./sub-nav";
import { StatusChip } from "./status-chip";
import { availableTransitions } from "./transitions";
import { useHelpdeskTier } from "./tier";

function describeAuditEvent(e: HelpdeskAuditEvent): string {
  const payload = e.payload ?? {};
  switch (e.action) {
    case "helpdesk.ticket.create":
      return `${e.actor} raised this ticket`;
    case "helpdesk.ticket.assign":
      return `${e.actor} assigned this ticket`;
    case "helpdesk.ticket.status": {
      const from = typeof payload.from === "string" ? payload.from : "?";
      const to = typeof payload.to === "string" ? payload.to : "?";
      return `${e.actor} changed status: ${from} → ${to}`;
    }
    case "helpdesk.comment.create":
      return `${e.actor} commented`;
    default:
      return `${e.actor} performed ${e.action}`;
  }
}

export function TicketDetailPage({ context }: { context: ModulePageContext }) {
  const companyId = context.companyId;
  const ticketId = context.params.ticketId;
  const tier = useHelpdeskTier(companyId);

  const [ticket, setTicket] = useState<HelpdeskTicket | null>(null);
  const [auditEvents, setAuditEvents] = useState<HelpdeskAuditEvent[]>([]);
  const [comments, setComments] = useState<HelpdeskComment[]>([]);
  const [commentBody, setCommentBody] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);

  const load = useCallback(async (cid: string, tid: string) => {
    try {
      const client = createHelpdeskClient(getShellSdk().apiClient);
      const [t, audit, cs] = await Promise.all([
        client.getTicket(cid, tid),
        client.getTicketAudit(cid, tid).catch(() => []),
        client.listComments(cid, tid).catch(() => [])
      ]);
      setTicket(t);
      setAuditEvents(audit);
      setComments(cs);
      setLoadError(null);
      setError(null);
    } catch (err) {
      setLoadError(describeApiError(err, "This ticket doesn't exist, or you don't have access to it."));
    }
  }, []);

  useEffect(() => {
    if (companyId && ticketId) void load(companyId, ticketId);
  }, [companyId, ticketId, load]);

  async function handleTransition(target: HelpdeskTicket["status"]): Promise<void> {
    if (!companyId || !ticketId) return;
    try {
      const client = createHelpdeskClient(getShellSdk().apiClient);
      await client.transitionStatus(companyId, ticketId, target);
      void load(companyId, ticketId);
    } catch (err) {
      setError(describeApiError(err, "Could not change this ticket's status."));
    }
  }

  async function handleComment(event: FormEvent): Promise<void> {
    event.preventDefault();
    if (!companyId || !ticketId || !commentBody.trim()) return;
    try {
      const client = createHelpdeskClient(getShellSdk().apiClient);
      await client.createComment(companyId, ticketId, commentBody.trim());
      setCommentBody("");
      void load(companyId, ticketId);
    } catch (err) {
      setError(describeApiError(err, "Could not post that comment."));
    }
  }

  if (!companyId || !ticketId) return null;

  if (loadError) {
    return (
      <div className="flex flex-col gap-2" data-testid="helpdesk-ticket-denied">
        <h1 className="text-lg font-semibold text-foreground">Ticket unavailable</h1>
        <p className="text-sm text-muted-foreground">{loadError}</p>
      </div>
    );
  }

  if (!ticket) return null;

  const transitions = availableTransitions(ticket, tier);

  return (
    <div className="flex flex-col gap-4" data-testid="helpdesk-ticket-detail-page">
      <HelpdeskSubNav companyId={companyId} tier={tier} />
      <div className="flex items-center justify-between">
        <h1 className="text-lg font-semibold text-foreground" data-testid="helpdesk-ticket-title">
          {ticket.title}
        </h1>
        <StatusChip status={ticket.status} />
      </div>

      <p className="text-sm text-muted-foreground" data-testid="helpdesk-ticket-assignee">
        {ticket.assigneeDisplayName ? `Assigned to ${ticket.assigneeDisplayName}` : "Unassigned"}
      </p>

      {error ? (
        <p role="alert" className="text-sm text-destructive">
          {error}
        </p>
      ) : null}

      {transitions.length > 0 ? (
        <div className="flex flex-wrap gap-2" data-testid="helpdesk-ticket-actions">
          {transitions.map((tr) => (
            <Button key={tr.to} type="button" size="sm" data-testid={`helpdesk-transition-${tr.to}`} onClick={() => void handleTransition(tr.to)}>
              {tr.label}
            </Button>
          ))}
        </div>
      ) : null}

      <Card>
        <CardHeader>
          <CardTitle>Description</CardTitle>
        </CardHeader>
        <CardContent>
          <p className="whitespace-pre-wrap text-sm text-foreground" data-testid="helpdesk-ticket-description">
            {ticket.description || "No description provided."}
          </p>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Comments</CardTitle>
        </CardHeader>
        <CardContent className="flex flex-col gap-3">
          {comments.length === 0 ? (
            <EmptyState title="No comments yet" description="Be the first to add one." />
          ) : (
            <ul className="flex flex-col gap-2" data-testid="helpdesk-comment-list">
              {comments.map((c) => (
                <li key={c.id} className="rounded-md border border-border px-2 py-1 text-sm" data-testid={`helpdesk-comment-${c.id}`}>
                  <div className="flex items-center justify-between">
                    <span className="font-medium">{c.authorKcSub}</span>
                    <span className="text-xs text-muted-foreground">{new Date(c.createdAt).toLocaleString()}</span>
                  </div>
                  <p className="whitespace-pre-wrap">{c.body}</p>
                </li>
              ))}
            </ul>
          )}
          <form className="flex flex-col gap-2" onSubmit={(event) => void handleComment(event)}>
            <textarea
              className="min-h-16 rounded-md border border-input bg-background px-2 py-1 text-sm"
              data-testid="helpdesk-comment-input"
              value={commentBody}
              onChange={(event) => setCommentBody(event.target.value)}
              placeholder="Add a comment…"
            />
            <div>
              <Button type="submit" size="sm" disabled={!commentBody.trim()} data-testid="helpdesk-comment-submit">
                Comment
              </Button>
            </div>
          </form>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Status timeline</CardTitle>
        </CardHeader>
        <CardContent>
          {auditEvents.length === 0 ? (
            <p className="text-sm text-muted-foreground">No activity recorded yet.</p>
          ) : (
            <ul className="flex flex-col gap-1 text-sm" data-testid="helpdesk-audit-list">
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
    </div>
  );
}
