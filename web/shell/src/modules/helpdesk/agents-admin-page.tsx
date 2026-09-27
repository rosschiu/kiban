// SPDX-License-Identifier: Apache-2.0

// The helpdesk module's Agents admin page (frontend.manifest.json route id "agents-admin", path
// "agents"): admin only. List/add/remove agents, with an explicit blocked-removal message
// when the last-ticket-assignment protection rule fires.
import { useCallback, useEffect, useState } from "react";
import { createOrgClient, type MemberDirectoryEntry, type OrgGroupWithMemberCount, type OrgPositionWithHolder } from "@rosschiu/kiban-sdk";
import { getShellSdk } from "../../auth/sdk";
import type { ModulePageContext } from "../../resolver/resolver";
import { Button } from "../../ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "../../ui/card";
import { EmptyState } from "../../ui/empty-state";
import { createHelpdeskClient, type AssignablePosition, type HelpdeskAgent } from "./api";
import { HelpdeskSubNav } from "./sub-nav";
import { useHelpdeskTier } from "./tier";

export function AgentsAdminPage({ context }: { context: ModulePageContext }) {
  const companyId = context.companyId;
  const tier = useHelpdeskTier(companyId);

  const [agents, setAgents] = useState<HelpdeskAgent[] | null>(null);
  const [denied, setDenied] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [blockedMemberId, setBlockedMemberId] = useState<string | null>(null);

  const [memberQuery, setMemberQuery] = useState("");
  const [memberResults, setMemberResults] = useState<MemberDirectoryEntry[]>([]);

  // The "bind to position" variant (the `{positionId}` agent binding). Sourced from
  // the admin position-list route (org.adminListPositions) — superadmin-guarded at the
  // gateway, same as every other call this page never assumed access to before; a caller without
  // that access simply sees an empty position list here (fails closed to "nothing to bind",
  // never an error banner for a section they may legitimately not be able to use).
  const [positions, setPositions] = useState<OrgPositionWithHolder[]>([]);

  // Holder NAMES for the "current agents" list are sourced from helpdesk's OWN
  // assignable-positions read (helpdesk.manage-gated — reachable by any helpdesk admin, not only
  // a platform superadmin), fixing the "held by unassigned" defect the superadmin-only
  // `positions` state above has for a non-superadmin helpdesk admin. `positions` above is kept
  // ONLY for the "Bind a position" picker, which genuinely needs the full company position list
  // (including unbound ones) — a list the superadmin-guarded org route is still the sole source
  // of.
  const [assignablePositions, setAssignablePositions] = useState<AssignablePosition[]>([]);

  // The "bind to group" variant (the `{groupId}` agent binding), same posture as
  // `positions` above — sourced from org's superadmin-guarded admin group list (org has no
  // helpdesk-admin-scoped group-list read of its own, the same gap as for positions); empty for a
  // caller without superadmin access, which fails closed to "nothing
  // to bind" rather than an error banner.
  const [groups, setGroups] = useState<OrgGroupWithMemberCount[]>([]);

  const load = useCallback(async (id: string) => {
    try {
      const client = createHelpdeskClient(getShellSdk().apiClient);
      const result = await client.listAgents(id);
      setAgents(result);
      setDenied(false);
      setError(null);
    } catch {
      setDenied(true);
    }
  }, []);

  const loadPositions = useCallback(async (id: string) => {
    try {
      const orgClient = createOrgClient(getShellSdk().apiClient);
      const page = await orgClient.adminListPositions(id, 1, 100);
      setPositions(page.items);
    } catch {
      setPositions([]);
    }
  }, []);

  const loadAssignablePositions = useCallback(async (id: string) => {
    try {
      const client = createHelpdeskClient(getShellSdk().apiClient);
      setAssignablePositions((await client.listAssignablePositions(id)) ?? []);
    } catch {
      setAssignablePositions([]);
    }
  }, []);

  useEffect(() => {
    if (companyId) void load(companyId);
  }, [companyId, load]);

  const loadGroups = useCallback(async (id: string) => {
    try {
      const orgClient = createOrgClient(getShellSdk().apiClient);
      const page = await orgClient.adminListGroups(id, 1, 100);
      setGroups(page.items);
    } catch {
      setGroups([]);
    }
  }, []);

  useEffect(() => {
    if (companyId) void loadPositions(companyId);
  }, [companyId, loadPositions]);

  useEffect(() => {
    if (companyId) void loadGroups(companyId);
  }, [companyId, loadGroups]);

  useEffect(() => {
    if (companyId) void loadAssignablePositions(companyId);
  }, [companyId, loadAssignablePositions]);

  useEffect(() => {
    if (!companyId) return;
    const handle = window.setTimeout(() => {
      const orgClient = createOrgClient(getShellSdk().apiClient);
      void orgClient
        .memberDirectory(companyId, memberQuery || undefined, 1, 20)
        .then((page) => setMemberResults(page.items))
        .catch(() => setMemberResults([]));
    }, 200);
    return () => window.clearTimeout(handle);
  }, [companyId, memberQuery]);

  async function handleMakeAgent(memberId: string): Promise<void> {
    if (!companyId) return;
    setError(null);
    try {
      const client = createHelpdeskClient(getShellSdk().apiClient);
      await client.makeAgent(companyId, memberId);
      void load(companyId);
    } catch {
      setError("Could not make that member an agent.");
    }
  }

  async function handleBindPosition(positionId: string): Promise<void> {
    if (!companyId) return;
    setError(null);
    try {
      const client = createHelpdeskClient(getShellSdk().apiClient);
      await client.makeAgentForPosition(companyId, positionId);
      void load(companyId);
      void loadAssignablePositions(companyId);
    } catch {
      setError("Could not bind that position as an agent.");
    }
  }

  async function handleBindGroup(groupId: string): Promise<void> {
    if (!companyId) return;
    setError(null);
    try {
      const client = createHelpdeskClient(getShellSdk().apiClient);
      await client.makeAgentForGroup(companyId, groupId);
      void load(companyId);
    } catch {
      setError("Could not bind that group as an agent.");
    }
  }

  async function handleRemoveGroup(groupId: string): Promise<void> {
    if (!companyId) return;
    setError(null);
    try {
      const client = createHelpdeskClient(getShellSdk().apiClient);
      await client.removeAgentForGroup(companyId, groupId);
      void load(companyId);
    } catch {
      setError("Could not remove that group binding.");
    }
  }

  async function handleRemove(memberId: string): Promise<void> {
    if (!companyId) return;
    setBlockedMemberId(null);
    setError(null);
    try {
      const client = createHelpdeskClient(getShellSdk().apiClient);
      await client.removeAgent(companyId, memberId);
      void load(companyId);
    } catch {
      // The most likely cause is the protection rule: this member is still assigned an open
      // ticket. The API distinguishes this as 422 VALIDATION_FAILED, but the SDK's thin client
      // surfaces only a thrown error here — show the explicit blocked-removal message rather
      // than a generic failure, since that IS the expected/common case for this action.
      setBlockedMemberId(memberId);
    }
  }

  async function handleRemovePosition(positionId: string): Promise<void> {
    if (!companyId) return;
    setError(null);
    try {
      const client = createHelpdeskClient(getShellSdk().apiClient);
      await client.removeAgentForPosition(companyId, positionId);
      void load(companyId);
      void loadAssignablePositions(companyId);
    } catch {
      setError("Could not remove that position binding.");
    }
  }

  const boundPositionIds = new Set(agents?.filter((a) => a.bindingKind === "position").map((a) => a.positionId) ?? []);
  const holderNameByPositionId = new Map(assignablePositions.map((p) => [p.positionId, p.holderDisplayName] as const));
  const boundGroupIds = new Set(agents?.filter((a) => a.bindingKind === "group").map((a) => a.groupId) ?? []);

  if (!companyId) return null;

  if (denied) {
    return (
      <div className="flex flex-col gap-4" data-testid="helpdesk-agents-page">
        <h1 className="text-lg font-semibold text-foreground">Helpdesk — Agents</h1>
        <HelpdeskSubNav companyId={companyId} tier={tier} />
        <div data-testid="helpdesk-agents-denied">
          <EmptyState title="Admin access required" description="Only helpdesk admins can manage agents." />
        </div>
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-4" data-testid="helpdesk-agents-page">
      <h1 className="text-lg font-semibold text-foreground">Helpdesk — Agents</h1>
      <HelpdeskSubNav companyId={companyId} tier={tier} />

      {error ? (
        <p role="alert" className="text-sm text-destructive">
          {error}
        </p>
      ) : null}

      <Card>
        <CardHeader>
          <CardTitle>Make an agent</CardTitle>
        </CardHeader>
        <CardContent className="flex flex-col gap-2">
          <label className="flex flex-col gap-1 text-sm">
            Search members
            <input
              className="rounded-md border border-input bg-background px-2 py-1 text-sm"
              data-testid="helpdesk-agent-member-search"
              value={memberQuery}
              onChange={(event) => setMemberQuery(event.target.value)}
              placeholder="Type a name or email…"
            />
          </label>
          <ul className="flex flex-col gap-1" data-testid="helpdesk-agent-member-results">
            {memberResults.map((m) => (
              <li key={m.id} className="flex items-center justify-between rounded-md border border-border px-2 py-1 text-sm">
                <span>
                  {m.displayName} <span className="text-xs text-muted-foreground">({m.email})</span>
                </span>
                <Button
                  type="button"
                  size="sm"
                  disabled={!m.hasLinkedUser}
                  data-testid={`helpdesk-make-agent-${m.id}`}
                  onClick={() => void handleMakeAgent(m.id)}
                >
                  Make agent
                </Button>
              </li>
            ))}
          </ul>
        </CardContent>
      </Card>

      {/* The "bind to position" variant — successor inherits the
          position's access, zero permission edits on handover. Empty for a caller without
          superadmin access to org's position-admin surface (loadPositions fails closed to []),
          which simply renders nothing to bind rather than an error. */}
      {positions.length > 0 ? (
        <Card>
          <CardHeader>
            <CardTitle>Bind a position</CardTitle>
          </CardHeader>
          <CardContent className="flex flex-col gap-1">
            <ul className="flex flex-col gap-1" data-testid="helpdesk-agent-position-results">
              {positions.map((p) => (
                <li key={p.id} className="flex items-center justify-between rounded-md border border-border px-2 py-1 text-sm">
                  <span>
                    {p.title} <span className="text-xs text-muted-foreground">({p.code})</span>
                  </span>
                  <Button
                    type="button"
                    size="sm"
                    disabled={boundPositionIds.has(p.id)}
                    data-testid={`helpdesk-bind-position-${p.id}`}
                    onClick={() => void handleBindPosition(p.id)}
                  >
                    {boundPositionIds.has(p.id) ? "Already bound" : "Bind as agent"}
                  </Button>
                </li>
              ))}
            </ul>
          </CardContent>
        </Card>
      ) : null}

      {/* The "bind to group" variant — every CURRENT member of the group
          inherits the agent tier, zero permission edits as membership changes. Empty for a caller
          without superadmin access to org's group-admin surface (loadGroups fails closed to []),
          same posture as the position picker above. */}
      {groups.length > 0 ? (
        <Card>
          <CardHeader>
            <CardTitle>Bind a group</CardTitle>
          </CardHeader>
          <CardContent className="flex flex-col gap-1">
            <ul className="flex flex-col gap-1" data-testid="helpdesk-agent-group-results">
              {groups.map((g) => (
                <li key={g.id} className="flex items-center justify-between rounded-md border border-border px-2 py-1 text-sm">
                  <span>
                    {g.name} <span className="text-xs text-muted-foreground">({g.code})</span>
                  </span>
                  <Button
                    type="button"
                    size="sm"
                    disabled={boundGroupIds.has(g.id)}
                    data-testid={`helpdesk-bind-group-${g.id}`}
                    onClick={() => void handleBindGroup(g.id)}
                  >
                    {boundGroupIds.has(g.id) ? "Already bound" : "Bind as agent"}
                  </Button>
                </li>
              ))}
            </ul>
          </CardContent>
        </Card>
      ) : null}

      <section className="flex flex-col gap-2">
        <h2 className="text-sm font-medium text-muted-foreground">Current agents</h2>
        {agents === null ? null : agents.length === 0 ? (
          <EmptyState title="No agents yet" description="Make a member an agent above, or assign them a ticket." />
        ) : (
          <ul className="flex flex-col gap-2" data-testid="helpdesk-agents-list">
            {agents.map((a) => {
              const rowKey = a.bindingKind === "position" ? a.positionId! : a.bindingKind === "group" ? a.groupId! : a.memberId!;
              const label =
                a.bindingKind === "position"
                  ? `${a.positionTitle ?? "Position"} — held by ${holderNameByPositionId.get(a.positionId!) ?? "unassigned"} (position)`
                  : a.bindingKind === "group"
                    ? `${a.groupTitle ?? "Group"} (group)`
                    : `member ${a.memberId!.slice(0, 8)}… (member)`;
              return (
                <li key={a.id} className="flex flex-col gap-1 rounded-md border border-border px-3 py-2" data-testid={`helpdesk-agent-${rowKey}`}>
                  <div className="flex items-center justify-between">
                    <span className="text-sm" data-testid={`helpdesk-agent-binding-kind-${rowKey}`}>
                      {label}
                    </span>
                    {a.bindingKind === "position" ? (
                      <Button
                        type="button"
                        size="sm"
                        variant="outline"
                        data-testid={`helpdesk-remove-agent-${rowKey}`}
                        onClick={() => void handleRemovePosition(a.positionId!)}
                      >
                        Remove
                      </Button>
                    ) : a.bindingKind === "group" ? (
                      <Button
                        type="button"
                        size="sm"
                        variant="outline"
                        data-testid={`helpdesk-remove-agent-${rowKey}`}
                        onClick={() => void handleRemoveGroup(a.groupId!)}
                      >
                        Remove
                      </Button>
                    ) : (
                      <Button
                        type="button"
                        size="sm"
                        variant="outline"
                        data-testid={`helpdesk-remove-agent-${rowKey}`}
                        onClick={() => void handleRemove(a.memberId!)}
                      >
                        Remove
                      </Button>
                    )}
                  </div>
                  {blockedMemberId === a.memberId ? (
                    <p role="alert" className="text-xs text-destructive" data-testid={`helpdesk-remove-blocked-${rowKey}`}>
                      Can&apos;t remove — this agent is currently assigned an open ticket. Reassign it first.
                    </p>
                  ) : null}
                </li>
              );
            })}
          </ul>
        )}
      </section>
    </div>
  );
}
