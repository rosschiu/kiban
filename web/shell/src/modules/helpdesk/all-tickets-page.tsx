// SPDX-License-Identifier: Apache-2.0

// The helpdesk module's "All tickets" page (frontend.manifest.json route id "all-tickets", path
// "all"): agents/admins only. Filterable by status, assign action (member picker from
// the org member directory, admin only), status transition buttons per the caller's tier. A plain
// member who navigates here directly (the nav link itself is hidden for them — sub-nav.tsx) sees
// an explicit access-denied state, never the list.
import { useCallback, useEffect, useState } from "react";
import { Link } from "@tanstack/react-router";
import { createOrgClient, type MemberDirectoryEntry } from "@rosschiu/kiban-sdk";
import { getShellSdk } from "../../auth/sdk";
import type { ModulePageContext } from "../../resolver/resolver";
import { Button } from "../../ui/button";
import { EmptyState } from "../../ui/empty-state";
import { Sheet, SheetContent, SheetHeader, SheetTitle, SheetDescription } from "../../ui/sheet";
import { createHelpdeskClient, type AssignableGroup, type AssignablePosition, type HelpdeskTicket, type TicketStatus } from "./api";
import { HelpdeskSubNav } from "./sub-nav";
import { StatusChip } from "./status-chip";
import { availableTransitions } from "./transitions";
import { useHelpdeskTier } from "./tier";

const STATUS_FILTERS: (TicketStatus | "")[] = ["", "open", "in_progress", "resolved", "closed"];

// The assign sheet defaults to "positions" — tickets are normally assigned to a role (e.g.
// "Support Agent"), not to an individual user. Tab order: Positions · Groups · Members.
type AssignTab = "positions" | "groups" | "members";

export function AllTicketsPage({ context }: { context: ModulePageContext }) {
  const companyId = context.companyId;
  const tier = useHelpdeskTier(companyId);

  const [tickets, setTickets] = useState<HelpdeskTicket[] | null>(null);
  const [status, setStatus] = useState<TicketStatus | "">("");
  const [error, setError] = useState<string | null>(null);
  const [denied, setDenied] = useState(false);

  const [assignOpen, setAssignOpen] = useState<string | null>(null);
  const [assignTab, setAssignTab] = useState<AssignTab>("positions");
  const [memberQuery, setMemberQuery] = useState("");
  const [memberResults, setMemberResults] = useState<MemberDirectoryEntry[]>([]);
  const [assignablePositions, setAssignablePositions] = useState<AssignablePosition[]>([]);
  const [assignableGroups, setAssignableGroups] = useState<AssignableGroup[]>([]);

  const load = useCallback(async (id: string, statusFilter: TicketStatus | "") => {
    try {
      const client = createHelpdeskClient(getShellSdk().apiClient);
      const result = await client.listTickets(id, "all", statusFilter || undefined);
      setTickets(result);
      setDenied(false);
      setError(null);
    } catch {
      setDenied(true);
    }
  }, []);

  useEffect(() => {
    if (companyId) void load(companyId, status);
  }, [companyId, status, load]);

  useEffect(() => {
    if (!companyId || !assignOpen || assignTab !== "members") return;
    const handle = window.setTimeout(() => {
      const orgClient = createOrgClient(getShellSdk().apiClient);
      void orgClient
        .memberDirectory(companyId, memberQuery || undefined, 1, 20)
        .then((page) => setMemberResults(page.items))
        .catch(() => setMemberResults([]));
    }, 200);
    return () => window.clearTimeout(handle);
  }, [companyId, assignOpen, assignTab, memberQuery]);

  useEffect(() => {
    if (!companyId || !assignOpen) return;
    const client = createHelpdeskClient(getShellSdk().apiClient);
    void client
      .listAssignablePositions(companyId)
      .then((rows) => setAssignablePositions(rows ?? []))
      .catch(() => setAssignablePositions([]));
  }, [companyId, assignOpen]);

  useEffect(() => {
    if (!companyId || !assignOpen) return;
    const client = createHelpdeskClient(getShellSdk().apiClient);
    void client
      .listAssignableGroups(companyId)
      .then((rows) => setAssignableGroups(rows ?? []))
      .catch(() => setAssignableGroups([]));
  }, [companyId, assignOpen]);

  function openAssignSheet(ticketId: string): void {
    setAssignTab("positions");
    setAssignOpen(ticketId);
  }

  async function handleAssignToMember(ticketId: string, memberId: string): Promise<void> {
    if (!companyId) return;
    try {
      const client = createHelpdeskClient(getShellSdk().apiClient);
      await client.assignTicket(companyId, ticketId, memberId);
      setAssignOpen(null);
      void load(companyId, status);
    } catch {
      setError("Could not assign this ticket.");
    }
  }

  async function handleAssignToPosition(ticketId: string, positionId: string): Promise<void> {
    if (!companyId) return;
    try {
      const client = createHelpdeskClient(getShellSdk().apiClient);
      await client.assignTicketToPosition(companyId, ticketId, positionId);
      setAssignOpen(null);
      void load(companyId, status);
    } catch {
      setError("Could not assign this ticket.");
    }
  }

  async function handleAssignToGroup(ticketId: string, groupId: string): Promise<void> {
    if (!companyId) return;
    try {
      const client = createHelpdeskClient(getShellSdk().apiClient);
      await client.assignTicketToGroup(companyId, ticketId, groupId);
      setAssignOpen(null);
      void load(companyId, status);
    } catch {
      setError("Could not assign this ticket.");
    }
  }

  async function handleTransition(ticketId: string, target: TicketStatus): Promise<void> {
    if (!companyId) return;
    try {
      const client = createHelpdeskClient(getShellSdk().apiClient);
      await client.transitionStatus(companyId, ticketId, target);
      void load(companyId, status);
    } catch {
      setError("Could not change this ticket's status.");
    }
  }

  if (!companyId) return null;

  if (denied) {
    return (
      <div className="flex flex-col gap-4" data-testid="helpdesk-all-tickets-page">
        <h1 className="text-lg font-semibold text-foreground">Helpdesk — All Tickets</h1>
        <HelpdeskSubNav companyId={companyId} tier={tier} />
        <div data-testid="helpdesk-all-tickets-denied">
          <EmptyState
            title="Agent or admin access required"
            description="Only helpdesk agents and admins can see every ticket. Your own reported tickets are on My Tickets."
          />
        </div>
      </div>
    );
  }

  const ticketHref = (ticketId: string) => `/app/c/${companyId}/helpdesk/tickets/${ticketId}`;

  return (
    <div className="flex flex-col gap-4" data-testid="helpdesk-all-tickets-page">
      <h1 className="text-lg font-semibold text-foreground">Helpdesk — All Tickets</h1>
      <HelpdeskSubNav companyId={companyId} tier={tier} />

      {error ? (
        <p role="alert" className="text-sm text-destructive">
          {error}
        </p>
      ) : null}

      <div className="flex items-center gap-2 text-sm">
        <span className="text-muted-foreground">Filter:</span>
        {STATUS_FILTERS.map((s) => (
          <button
            key={s || "all"}
            type="button"
            data-testid={`helpdesk-status-filter-${s || "all"}`}
            className={`rounded-md border px-2 py-1 ${status === s ? "border-primary bg-accent" : "border-border"}`}
            onClick={() => setStatus(s)}
          >
            {s === "" ? "All" : s}
          </button>
        ))}
      </div>

      {tickets === null ? null : tickets.length === 0 ? (
        <EmptyState title="No tickets" description="No tickets match this filter." />
      ) : (
        <ul className="flex flex-col gap-2" data-testid="helpdesk-all-tickets-list">
          {tickets.map((t) => {
            const transitions = availableTransitions(t, tier);
            return (
              <li key={t.id} className="flex flex-col gap-2 rounded-md border border-border px-3 py-2" data-testid={`helpdesk-ticket-${t.id}`}>
                <div className="flex items-center justify-between">
                  <Link to={ticketHref(t.id)} className="font-medium hover:underline">
                    {t.title}
                  </Link>
                  <StatusChip status={t.status} />
                </div>
                <div className="text-xs text-muted-foreground" data-testid={`helpdesk-assignee-${t.id}`}>
                  {t.assigneeDisplayName ? `Assigned to ${t.assigneeDisplayName}` : "Unassigned"}
                </div>
                <div className="flex flex-wrap items-center gap-2">
                  {tier === "admin" ? (
                    <Button type="button" size="sm" variant="outline" data-testid={`helpdesk-assign-${t.id}`} onClick={() => openAssignSheet(t.id)}>
                      {t.assigneeKind ? "Reassign" : "Assign"}
                    </Button>
                  ) : null}
                  {transitions.map((tr) => (
                    <Button
                      key={tr.to}
                      type="button"
                      size="sm"
                      data-testid={`helpdesk-transition-${t.id}-${tr.to}`}
                      onClick={() => void handleTransition(t.id, tr.to)}
                    >
                      {tr.label}
                    </Button>
                  ))}
                </div>
              </li>
            );
          })}
        </ul>
      )}

      <Sheet open={assignOpen !== null} onOpenChange={(open) => !open && setAssignOpen(null)}>
        <SheetContent side="right" data-testid="helpdesk-assign-sheet">
          <SheetHeader>
            <SheetTitle>Assign ticket</SheetTitle>
            <SheetDescription>
              Assign to a position and whoever holds it works the ticket — even after a handover.
            </SheetDescription>
          </SheetHeader>
          {/* Positions-first added a tabs row + a second results list to this sheet body,
              which can now exceed the fixed-height SheetContent's viewport — min-h-0 lets this
              flex child shrink below its content size so overflow-y-auto actually scrolls,
              instead of pushing later rows (e.g. an "Assign" button) permanently out of view. */}
          <div className="flex min-h-0 flex-1 flex-col gap-3 overflow-y-auto px-4 pb-4">
            <div className="flex gap-1 text-sm" role="tablist">
              <button
                type="button"
                role="tab"
                aria-selected={assignTab === "positions"}
                data-testid="helpdesk-assign-tab-positions"
                className={`rounded-md border px-2 py-1 ${assignTab === "positions" ? "border-primary bg-accent" : "border-border"}`}
                onClick={() => setAssignTab("positions")}
              >
                Positions
              </button>
              <button
                type="button"
                role="tab"
                aria-selected={assignTab === "groups"}
                data-testid="helpdesk-assign-tab-groups"
                className={`rounded-md border px-2 py-1 ${assignTab === "groups" ? "border-primary bg-accent" : "border-border"}`}
                onClick={() => setAssignTab("groups")}
              >
                Groups
              </button>
              <button
                type="button"
                role="tab"
                aria-selected={assignTab === "members"}
                data-testid="helpdesk-assign-tab-members"
                className={`rounded-md border px-2 py-1 ${assignTab === "members" ? "border-primary bg-accent" : "border-border"}`}
                onClick={() => setAssignTab("members")}
              >
                Members
              </button>
            </div>

            {assignTab === "positions" ? (
              assignablePositions.length === 0 ? (
                <p className="text-sm text-muted-foreground" data-testid="helpdesk-assign-positions-empty">
                  No positions are bound as helpdesk agents yet. Bind one on the Agents page, or assign to a member instead.
                </p>
              ) : (
                <ul className="flex flex-col gap-1" data-testid="helpdesk-assign-position-results">
                  {assignablePositions.map((p) => (
                    <li
                      key={p.positionId}
                      className="flex items-center justify-between rounded-md border border-border px-2 py-1 text-sm"
                    >
                      <span>
                        {p.title}{" "}
                        <span className="text-xs text-muted-foreground">
                          {p.holderDisplayName ? `— held by ${p.holderDisplayName}` : "— unassigned"}
                        </span>
                      </span>
                      <Button
                        type="button"
                        size="sm"
                        data-testid={`helpdesk-assign-to-position-${p.positionId}`}
                        onClick={() => assignOpen && void handleAssignToPosition(assignOpen, p.positionId)}
                      >
                        Assign
                      </Button>
                    </li>
                  ))}
                </ul>
              )
            ) : assignTab === "groups" ? (
              assignableGroups.length === 0 ? (
                <p className="text-sm text-muted-foreground" data-testid="helpdesk-assign-groups-empty">
                  No groups are bound as helpdesk agents yet. Bind one on the Agents page, or assign to a position or
                  member instead.
                </p>
              ) : (
                <ul className="flex flex-col gap-1" data-testid="helpdesk-assign-group-results">
                  {assignableGroups.map((g) => (
                    <li
                      key={g.groupId}
                      className="flex items-center justify-between rounded-md border border-border px-2 py-1 text-sm"
                    >
                      <span>
                        {g.title}{" "}
                        <span className="text-xs text-muted-foreground">
                          — {g.memberCount} member{g.memberCount === 1 ? "" : "s"}
                        </span>
                      </span>
                      <Button
                        type="button"
                        size="sm"
                        data-testid={`helpdesk-assign-to-group-${g.groupId}`}
                        onClick={() => assignOpen && void handleAssignToGroup(assignOpen, g.groupId)}
                      >
                        Assign
                      </Button>
                    </li>
                  ))}
                </ul>
              )
            ) : (
              <>
                <label className="flex flex-col gap-1 text-sm">
                  Search members
                  <input
                    className="rounded-md border border-input bg-background px-2 py-1 text-sm"
                    data-testid="helpdesk-assign-member-search"
                    value={memberQuery}
                    onChange={(event) => setMemberQuery(event.target.value)}
                    placeholder="Type a name or email…"
                  />
                </label>
                <ul className="flex flex-col gap-1" data-testid="helpdesk-assign-member-results">
                  {memberResults.map((m) => (
                    <li key={m.id} className="flex items-center justify-between rounded-md border border-border px-2 py-1 text-sm">
                      <span>
                        {m.displayName} <span className="text-xs text-muted-foreground">({m.email})</span>
                      </span>
                      <Button
                        type="button"
                        size="sm"
                        disabled={!m.hasLinkedUser}
                        data-testid={`helpdesk-assign-to-${m.id}`}
                        onClick={() => assignOpen && void handleAssignToMember(assignOpen, m.id)}
                      >
                        Assign
                      </Button>
                    </li>
                  ))}
                </ul>
              </>
            )}
          </div>
        </SheetContent>
      </Sheet>
    </div>
  );
}
