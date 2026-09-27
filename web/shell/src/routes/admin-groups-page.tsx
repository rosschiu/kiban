// SPDX-License-Identifier: Apache-2.0

// The shell "Groups" admin page — the minimal admin surface for the group assignment target
// (alongside member and position), next to Positions in the superadmin nav. Superadmin-only
// (gated by the nav entry in nav/compose.ts's computeNavEntries —
// this route itself is unreachable in the UI for anyone else, and every call it makes is
// independently gateway-guarded by internal/gateway/admin_group_routes.go's RequireSuperadmin).
// Same shell-native-static-route posture as AdminPositionsPage (NOT a catalog module route —
// reads the active company from useCompanyContext()).
import { createOrgClient, type MemberDirectoryEntry, type OrgGroupMember, type OrgGroupWithMemberCount } from "@rosschiu/kiban-sdk";
import { useCallback, useEffect, useState } from "react";
import { getShellSdk } from "../auth/sdk";
import { describeApiError } from "../lib/api-error";
import { useCompanyContext } from "../nav/company-context";
import { Button } from "../ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "../ui/card";
import { EmptyState } from "../ui/empty-state";

export function AdminGroupsPage() {
  const { activeCompanyId } = useCompanyContext();

  const [groups, setGroups] = useState<OrgGroupWithMemberCount[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  const [code, setCode] = useState("");
  const [name, setName] = useState("");

  const [expandedGroupId, setExpandedGroupId] = useState<string | null>(null);
  const [members, setMembers] = useState<OrgGroupMember[]>([]);

  const [addingToGroupId, setAddingToGroupId] = useState<string | null>(null);
  const [memberQuery, setMemberQuery] = useState("");
  const [memberResults, setMemberResults] = useState<MemberDirectoryEntry[]>([]);

  const load = useCallback(async (companyId: string) => {
    try {
      const client = createOrgClient(getShellSdk().apiClient);
      const page = await client.adminListGroups(companyId, 1, 100);
      setGroups(page.items);
      setError(null);
    } catch (err) {
      setError(describeApiError(err, "Could not load groups. This page requires superadmin access."));
    }
  }, []);

  useEffect(() => {
    if (activeCompanyId) void load(activeCompanyId);
  }, [activeCompanyId, load]);

  const loadMembers = useCallback(async (groupId: string) => {
    try {
      const client = createOrgClient(getShellSdk().apiClient);
      const rows = await client.adminListGroupMembers(groupId);
      setMembers(rows);
    } catch {
      setMembers([]);
    }
  }, []);

  useEffect(() => {
    if (!activeCompanyId || !addingToGroupId) return;
    const handle = window.setTimeout(() => {
      const orgClient = createOrgClient(getShellSdk().apiClient);
      void orgClient
        .memberDirectory(activeCompanyId, memberQuery || undefined, 1, 20)
        .then((page) => setMemberResults(page.items))
        .catch(() => setMemberResults([]));
    }, 200);
    return () => window.clearTimeout(handle);
  }, [activeCompanyId, addingToGroupId, memberQuery]);

  async function handleCreate(): Promise<void> {
    if (!activeCompanyId || !code.trim() || !name.trim()) return;
    setError(null);
    try {
      const client = createOrgClient(getShellSdk().apiClient);
      await client.adminCreateGroup(activeCompanyId, { code: code.trim(), name: name.trim() });
      setCode("");
      setName("");
      void load(activeCompanyId);
    } catch (err) {
      setError(describeApiError(err, "Could not create that group."));
    }
  }

  function toggleExpanded(groupId: string): void {
    if (expandedGroupId === groupId) {
      setExpandedGroupId(null);
      setMembers([]);
      return;
    }
    setExpandedGroupId(groupId);
    setAddingToGroupId(null);
    void loadMembers(groupId);
  }

  async function handleAdd(groupId: string, memberId: string): Promise<void> {
    if (!activeCompanyId) return;
    setError(null);
    try {
      const client = createOrgClient(getShellSdk().apiClient);
      await client.adminAddGroupMember(groupId, memberId);
      setAddingToGroupId(null);
      setMemberQuery("");
      setMemberResults([]);
      void load(activeCompanyId);
      void loadMembers(groupId);
    } catch (err) {
      setError(describeApiError(err, "Could not add that member. The group may be externally managed."));
    }
  }

  async function handleRemove(groupId: string, memberId: string): Promise<void> {
    if (!activeCompanyId) return;
    setError(null);
    try {
      const client = createOrgClient(getShellSdk().apiClient);
      await client.adminRemoveGroupMember(groupId, memberId);
      void load(activeCompanyId);
      void loadMembers(groupId);
    } catch (err) {
      setError(describeApiError(err, "Could not remove that member. The group may be externally managed."));
    }
  }

  if (!activeCompanyId) {
    return (
      <div className="flex flex-col gap-4" data-testid="admin-groups-page">
        <h1 className="text-lg font-semibold text-foreground">Groups</h1>
        <EmptyState title="Select a company" description="Choose a company from the switcher to manage its groups." />
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-4" data-testid="admin-groups-page">
      <h1 className="text-lg font-semibold text-foreground">Groups</h1>
      <p className="text-sm text-muted-foreground">
        A group is a named set of members: assign a ticket to the group and any current member can work it; add or
        remove members and their access follows, live, with zero permission edits.
      </p>

      {error ? (
        <p role="alert" className="text-sm text-destructive">
          {error}
        </p>
      ) : null}

      <Card>
        <CardHeader>
          <CardTitle>Create a group</CardTitle>
        </CardHeader>
        <CardContent className="flex flex-col gap-2 sm:flex-row sm:items-end">
          <label className="flex flex-1 flex-col gap-1 text-sm">
            Code
            <input
              className="rounded-md border border-input bg-background px-2 py-1 text-sm"
              data-testid="admin-group-code-input"
              value={code}
              onChange={(event) => setCode(event.target.value)}
              placeholder="e.g. support-team"
            />
          </label>
          <label className="flex flex-1 flex-col gap-1 text-sm">
            Name
            <input
              className="rounded-md border border-input bg-background px-2 py-1 text-sm"
              data-testid="admin-group-name-input"
              value={name}
              onChange={(event) => setName(event.target.value)}
              placeholder="e.g. Support Team"
            />
          </label>
          <Button type="button" size="sm" data-testid="admin-group-create-button" onClick={() => void handleCreate()}>
            Create
          </Button>
        </CardContent>
      </Card>

      <section className="flex flex-col gap-2">
        <h2 className="text-sm font-medium text-muted-foreground">All groups</h2>
        {groups === null ? null : groups.length === 0 ? (
          <EmptyState title="No groups yet" description="Create a group above to get started." />
        ) : (
          <ul className="flex flex-col gap-2" data-testid="admin-groups-list">
            {groups.map((g) => (
              <li key={g.id} className="flex flex-col gap-2 rounded-md border border-border px-3 py-2" data-testid={`admin-group-${g.id}`}>
                <div className="flex items-center justify-between">
                  <span className="text-sm font-medium text-foreground">
                    {g.name} <span className="text-xs text-muted-foreground">({g.code})</span>
                    {!g.isKibanManaged ? (
                      <span
                        className="ml-2 rounded-full border border-border px-2 py-0.5 text-xs text-muted-foreground"
                        data-testid={`admin-group-source-badge-${g.id}`}
                      >
                        source: {g.source}
                      </span>
                    ) : null}
                  </span>
                  <Button type="button" size="sm" variant="outline" data-testid={`admin-group-expand-${g.id}`} onClick={() => toggleExpanded(g.id)}>
                    {g.memberCount} member{g.memberCount === 1 ? "" : "s"}
                  </Button>
                </div>

                {expandedGroupId === g.id ? (
                  <div className="flex flex-col gap-2 rounded-md border border-dashed border-border p-2">
                    {members.length === 0 ? (
                      <p className="text-xs text-muted-foreground">No members yet.</p>
                    ) : (
                      <ul className="flex flex-col gap-1" data-testid={`admin-group-members-${g.id}`}>
                        {members.map((m) => (
                          <li key={m.memberId} className="flex items-center justify-between rounded-md border border-border px-2 py-1 text-sm">
                            <span>
                              {m.memberDisplayName} <span className="text-xs text-muted-foreground">({m.memberEmail})</span>
                            </span>
                            {g.isKibanManaged ? (
                              <Button
                                type="button"
                                size="sm"
                                variant="ghost"
                                data-testid={`admin-group-remove-member-${g.id}-${m.memberId}`}
                                onClick={() => void handleRemove(g.id, m.memberId)}
                              >
                                Remove
                              </Button>
                            ) : null}
                          </li>
                        ))}
                      </ul>
                    )}

                    {g.isKibanManaged ? (
                      addingToGroupId === g.id ? (
                        <div className="flex flex-col gap-2">
                          <label className="flex flex-col gap-1 text-sm">
                            Search members
                            <input
                              className="rounded-md border border-input bg-background px-2 py-1 text-sm"
                              data-testid={`admin-group-member-search-${g.id}`}
                              value={memberQuery}
                              onChange={(event) => setMemberQuery(event.target.value)}
                              placeholder="Type a name or email…"
                            />
                          </label>
                          <ul className="flex flex-col gap-1" data-testid={`admin-group-member-results-${g.id}`}>
                            {memberResults.map((m) => (
                              <li key={m.id} className="flex items-center justify-between rounded-md border border-border px-2 py-1 text-sm">
                                <span>
                                  {m.displayName} <span className="text-xs text-muted-foreground">({m.email})</span>
                                </span>
                                <Button
                                  type="button"
                                  size="sm"
                                  data-testid={`admin-group-add-member-${g.id}-${m.id}`}
                                  onClick={() => void handleAdd(g.id, m.id)}
                                >
                                  Add
                                </Button>
                              </li>
                            ))}
                          </ul>
                          <Button type="button" size="sm" variant="ghost" onClick={() => setAddingToGroupId(null)}>
                            Cancel
                          </Button>
                        </div>
                      ) : (
                        <Button
                          type="button"
                          size="sm"
                          data-testid={`admin-group-add-button-${g.id}`}
                          onClick={() => {
                            setAddingToGroupId(g.id);
                            setMemberQuery("");
                            setMemberResults([]);
                          }}
                        >
                          Add a member
                        </Button>
                      )
                    ) : (
                      <p className="text-xs text-muted-foreground" data-testid={`admin-group-readonly-${g.id}`}>
                        This group is externally managed; membership is read-only here.
                      </p>
                    )}
                  </div>
                ) : null}
              </li>
            ))}
          </ul>
        )}
      </section>
    </div>
  );
}
