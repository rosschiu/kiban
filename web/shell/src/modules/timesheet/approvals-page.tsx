// SPDX-License-Identifier: Apache-2.0

// The timesheet module's "approvals" route (view=approvals — submissions assigned to
// the caller as approver). Uses the shared list toolkit; approve/reject act on the row's
// own `permissions.canApprove`/`canReject` (the server computes these from the page-level
// authz decision already made, never a second per-row check here).
import { useCallback, useEffect, useState } from "react";
import { getShellSdk } from "../../auth/sdk";
import type { ModulePageContext } from "../../resolver/resolver";
import { Button } from "../../ui/button";
import { EmptyState } from "../../ui/empty-state";
import { ListPageFrame } from "../../ui/list-page-frame";
import { ListPaginationFooter } from "../../ui/list-pagination-footer";
import { ListTableShell } from "../../ui/list-table-shell";
import { createTimesheetClient, type TimesheetSubmission } from "./api";

export function ApprovalsPage({ context }: { context: ModulePageContext }) {
  const companyId = context.companyId;
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(25);
  const [result, setResult] = useState<{ items: TimesheetSubmission[]; total: number; totalPages: number } | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(
    async (id: string) => {
      try {
        const client = createTimesheetClient(getShellSdk().apiClient);
        const resp = await client.listSubmissions(id, "approvals", page, pageSize);
        setResult(resp);
        setError(null);
      } catch {
        setError("Could not load submissions awaiting your decision.");
      }
    },
    [page, pageSize],
  );

  useEffect(() => {
    if (companyId) void load(companyId);
  }, [companyId, load]);

  async function handleApprove(submissionId: string): Promise<void> {
    if (!companyId) return;
    try {
      const client = createTimesheetClient(getShellSdk().apiClient);
      await client.approveSubmission(companyId, submissionId);
      void load(companyId);
    } catch {
      setError("Could not approve — it may no longer be the current submitted version.");
    }
  }

  async function handleReject(submissionId: string): Promise<void> {
    if (!companyId) return;
    const reason = window.prompt("Reason for rejecting this submission:");
    if (!reason) return;
    try {
      const client = createTimesheetClient(getShellSdk().apiClient);
      await client.rejectSubmission(companyId, submissionId, reason);
      void load(companyId);
    } catch {
      setError("Could not reject the submission.");
    }
  }

  if (!companyId) return null;

  const items = result?.items ?? [];

  return (
    <ListPageFrame
      title="Approvals"
      error={
        error ? (
          <p role="alert" className="text-sm text-destructive">
            {error}
          </p>
        ) : null
      }
    >
      <ListTableShell
        isEmpty={items.length === 0}
        emptyState={<EmptyState title="Nothing to review" description="Submissions assigned to you will appear here." />}
        tableContent={
          <table className="w-full text-sm" data-testid="timesheet-approvals-list">
            <thead>
              <tr className="border-b bg-muted/50">
                <th className="p-2 text-left font-medium">Week</th>
                <th className="p-2 text-left font-medium">Version</th>
                <th className="p-2 text-left font-medium">Status</th>
                <th className="p-2 text-left font-medium">Actions</th>
              </tr>
            </thead>
            <tbody>
              {items.map((s) => (
                <tr key={s.id} className="border-b last:border-0" data-testid={`approval-${s.id}`}>
                  <td className="p-2">{s.weekStart}</td>
                  <td className="p-2">v{s.versionNumber}</td>
                  <td className="p-2 capitalize">{s.status}</td>
                  <td className="p-2">
                    {s.permissions.canApprove || s.permissions.canReject ? (
                      <div className="flex gap-2">
                        <Button
                          type="button"
                          size="sm"
                          disabled={!s.permissions.canApprove}
                          onClick={() => void handleApprove(s.id)}
                          data-testid={`approve-${s.id}`}
                        >
                          Approve
                        </Button>
                        <Button
                          type="button"
                          size="sm"
                          variant="outline"
                          disabled={!s.permissions.canReject}
                          onClick={() => void handleReject(s.id)}
                          data-testid={`reject-${s.id}`}
                        >
                          Reject
                        </Button>
                      </div>
                    ) : (
                      <span className="text-xs text-muted-foreground">Decided</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        }
        footer={
          result ? (
            <ListPaginationFooter
              currentPage={page}
              currentPageSize={pageSize}
              totalPages={Math.max(1, result.totalPages)}
              pageSizeOptions={[10, 25, 50, 100]}
              summary={`${result.total} submission${result.total === 1 ? "" : "s"}`}
              onPageChange={setPage}
              onPageSizeChange={(size) => {
                setPageSize(size);
                setPage(1);
              }}
            />
          ) : null
        }
      />
    </ListPageFrame>
  );
}
