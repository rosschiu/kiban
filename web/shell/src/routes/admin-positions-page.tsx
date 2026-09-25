// SPDX-License-Identifier: Apache-2.0

// The shell "Positions" page — the sample shell's minimal position-based-access
// admin surface. Superadmin-only (gated by the nav entry in
// nav/compose.ts's computeNavEntries — this route itself is unreachable in the UI for anyone
// else, and every call it makes is independently gateway-guarded by
// internal/gateway/admin_position_routes.go's RequireSuperadmin). Unlike the module admin
// pages (e.g. helpdesk's AgentsAdminPage), this is NOT a catalog module route — Positions is a
// shell-native org feature, so it reads the active company from useCompanyContext() (the same
// company-switcher state module routes get via the URL's {companyId} segment) rather than a
// ModulePageContext.
import { createOrgClient, type MemberDirectoryEntry, type OrgPositionWithHolder } from "@rosschiu/kiban-sdk";
import { useCallback, useEffect, useState } from "react";
import { getShellSdk } from "../auth/sdk";
import { describeApiError } from "../lib/api-error";
import { useCompanyContext } from "../nav/company-context";
import { Button } from "../ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "../ui/card";
import { EmptyState } from "../ui/empty-state";

export function AdminPositionsPage() {
  const { activeCompanyId } = useCompanyContext();

  const [positions, setPositions] = useState<OrgPositionWithHolder[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  const [code, setCode] = useState("");
  const [title, setTitle] = useState("");

  const [assigningPositionId, setAssigningPositionId] = useState<string | null>(null);
  const [memberQuery, setMemberQuery] = useState("");
  const [memberResults, setMemberResults] = useState<MemberDirectoryEntry[]>([]);

  const load = useCallback(async (companyId: string) => {
    try {
      const client = createOrgClient(getShellSdk().apiClient);
      const page = await client.adminListPositions(companyId, 1, 100);
      setPositions(page.items);
      setError(null);
    } catch (err) {
      setError(describeApiError(err, "Could not load positions. This page requires superadmin access."));
    }
  }, []);

  useEffect(() => {
    if (activeCompanyId) void load(activeCompanyId);
  }, [activeCompanyId, load]);

  useEffect(() => {
    if (!activeCompanyId || !assigningPositionId) return;
    const handle = window.setTimeout(() => {
      const orgClient = createOrgClient(getShellSdk().apiClient);
      void orgClient
        .memberDirectory(activeCompanyId, memberQuery || undefined, 1, 20)
        .then((page) => setMemberResults(page.items))
        .catch(() => setMemberResults([]));
    }, 200);
    return () => window.clearTimeout(handle);
  }, [activeCompanyId, assigningPositionId, memberQuery]);

  async function handleCreate(): Promise<void> {
    if (!activeCompanyId || !code.trim() || !title.trim()) return;
    setError(null);
    try {
      const client = createOrgClient(getShellSdk().apiClient);
      await client.adminCreatePosition(activeCompanyId, { code: code.trim(), title: title.trim() });
      setCode("");
      setTitle("");
      void load(activeCompanyId);
    } catch (err) {
      setError(describeApiError(err, "Could not create that position."));
    }
  }

  async function handleAssign(positionId: string, memberId: string): Promise<void> {
    if (!activeCompanyId) return;
    setError(null);
    try {
      const client = createOrgClient(getShellSdk().apiClient);
      await client.adminAssignPosition(positionId, memberId);
      setAssigningPositionId(null);
      setMemberQuery("");
      setMemberResults([]);
      void load(activeCompanyId);
    } catch (err) {
      setError(describeApiError(err, "Could not assign that member."));
    }
  }

  async function handleEnd(assignmentId: string): Promise<void> {
    if (!activeCompanyId) return;
    setError(null);
    try {
      const client = createOrgClient(getShellSdk().apiClient);
      await client.adminEndAssignment(assignmentId);
      void load(activeCompanyId);
    } catch (err) {
      setError(describeApiError(err, "Could not end that assignment."));
    }
  }

  if (!activeCompanyId) {
    return (
      <div className="flex flex-col gap-4" data-testid="admin-positions-page">
        <h1 className="text-lg font-semibold text-foreground">Positions</h1>
        <EmptyState title="Select a company" description="Choose a company from the switcher to manage its positions." />
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-4" data-testid="admin-positions-page">
      <h1 className="text-lg font-semibold text-foreground">Positions</h1>
      <p className="text-sm text-muted-foreground">
        A position is a seat that carries access: assign a member to it and access flows with the chair; end the
        assignment and it flows away, with zero permission edits.
      </p>

      {error ? (
        <p role="alert" className="text-sm text-destructive">
          {error}
        </p>
      ) : null}

      <Card>
        <CardHeader>
          <CardTitle>Create a position</CardTitle>
        </CardHeader>
        <CardContent className="flex flex-col gap-2 sm:flex-row sm:items-end">
          <label className="flex flex-1 flex-col gap-1 text-sm">
            Code
            <input
              className="rounded-md border border-input bg-background px-2 py-1 text-sm"
              data-testid="admin-position-code-input"
              value={code}
              onChange={(event) => setCode(event.target.value)}
              placeholder="e.g. support-agent"
            />
          </label>
          <label className="flex flex-1 flex-col gap-1 text-sm">
            Title
            <input
              className="rounded-md border border-input bg-background px-2 py-1 text-sm"
              data-testid="admin-position-title-input"
              value={title}
              onChange={(event) => setTitle(event.target.value)}
              placeholder="e.g. Support Agent"
            />
          </label>
          <Button type="button" size="sm" data-testid="admin-position-create-button" onClick={() => void handleCreate()}>
            Create
          </Button>
        </CardContent>
      </Card>

      <section className="flex flex-col gap-2">
        <h2 className="text-sm font-medium text-muted-foreground">All positions</h2>
        {positions === null ? null : positions.length === 0 ? (
          <EmptyState title="No positions yet" description="Create a position above to get started." />
        ) : (
          <ul className="flex flex-col gap-2" data-testid="admin-positions-list">
            {positions.map((p) => (
              <li key={p.id} className="flex flex-col gap-2 rounded-md border border-border px-3 py-2" data-testid={`admin-position-${p.id}`}>
                <div className="flex items-center justify-between">
                  <span className="text-sm font-medium text-foreground">
                    {p.title} <span className="text-xs text-muted-foreground">({p.code})</span>
                  </span>
                  {p.assignmentId ? (
                    <Button
                      type="button"
                      size="sm"
                      variant="outline"
                      data-testid={`admin-position-end-${p.id}`}
                      onClick={() => void handleEnd(p.assignmentId!)}
                    >
                      End assignment
                    </Button>
                  ) : (
                    <Button
                      type="button"
                      size="sm"
                      data-testid={`admin-position-assign-${p.id}`}
                      onClick={() => {
                        setAssigningPositionId(p.id);
                        setMemberQuery("");
                        setMemberResults([]);
                      }}
                    >
                      Assign
                    </Button>
                  )}
                </div>

                {p.holderDisplayName ? (
                  <p className="text-xs text-muted-foreground" data-testid={`admin-position-holder-${p.id}`}>
                    Held by {p.holderDisplayName}
                  </p>
                ) : (
                  <p className="text-xs text-muted-foreground" data-testid={`admin-position-vacant-${p.id}`}>
                    Vacant
                  </p>
                )}

                {assigningPositionId === p.id ? (
                  <div className="flex flex-col gap-2 rounded-md border border-dashed border-border p-2">
                    <label className="flex flex-col gap-1 text-sm">
                      Search members
                      <input
                        className="rounded-md border border-input bg-background px-2 py-1 text-sm"
                        data-testid={`admin-position-member-search-${p.id}`}
                        value={memberQuery}
                        onChange={(event) => setMemberQuery(event.target.value)}
                        placeholder="Type a name or email…"
                      />
                    </label>
                    <ul className="flex flex-col gap-1" data-testid={`admin-position-member-results-${p.id}`}>
                      {memberResults.map((m) => (
                        <li key={m.id} className="flex items-center justify-between rounded-md border border-border px-2 py-1 text-sm">
                          <span>
                            {m.displayName} <span className="text-xs text-muted-foreground">({m.email})</span>
                          </span>
                          <Button
                            type="button"
                            size="sm"
                            data-testid={`admin-position-assign-member-${p.id}-${m.id}`}
                            onClick={() => void handleAssign(p.id, m.id)}
                          >
                            Assign
                          </Button>
                        </li>
                      ))}
                    </ul>
                    <Button type="button" size="sm" variant="ghost" onClick={() => setAssigningPositionId(null)}>
                      Cancel
                    </Button>
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
