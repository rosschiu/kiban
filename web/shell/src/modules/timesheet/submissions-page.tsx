// SPDX-License-Identifier: Apache-2.0

// The timesheet module's "submissions" route (view=mine — the caller's own
// submission history/versions). Uses the shared list toolkit (ListPageFrame/
// ListTableShell/ListPaginationFooter).
import { useCallback, useEffect, useState } from "react";
import { getShellSdk } from "../../auth/sdk";
import type { ModulePageContext } from "../../resolver/resolver";
import { EmptyState } from "../../ui/empty-state";
import { ListPageFrame } from "../../ui/list-page-frame";
import { ListPaginationFooter } from "../../ui/list-pagination-footer";
import { ListTableShell } from "../../ui/list-table-shell";
import { createTimesheetClient, type TimesheetSubmission } from "./api";

export function SubmissionsPage({ context }: { context: ModulePageContext }) {
  const companyId = context.companyId;
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(25);
  const [result, setResult] = useState<{ items: TimesheetSubmission[]; total: number; totalPages: number } | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(
    async (id: string) => {
      try {
        const client = createTimesheetClient(getShellSdk().apiClient);
        const resp = await client.listSubmissions(id, "mine", page, pageSize);
        setResult(resp);
        setError(null);
      } catch {
        setError("Could not load your submissions.");
      }
    },
    [page, pageSize],
  );

  useEffect(() => {
    if (companyId) void load(companyId);
  }, [companyId, load]);

  if (!companyId) return null;

  const items = result?.items ?? [];

  return (
    <ListPageFrame
      title="My submissions"
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
        emptyState={<EmptyState title="No submissions yet" description="Submit a week from the Timesheet page to see it here." />}
        tableContent={
          <table className="w-full text-sm" data-testid="timesheet-submissions-list">
            <thead>
              <tr className="border-b bg-muted/50">
                <th className="p-2 text-left font-medium">Week</th>
                <th className="p-2 text-left font-medium">Version</th>
                <th className="p-2 text-left font-medium">Status</th>
                <th className="p-2 text-left font-medium">Reject reason</th>
              </tr>
            </thead>
            <tbody>
              {items.map((s) => (
                <tr key={s.id} className="border-b last:border-0" data-testid={`submission-${s.id}`}>
                  <td className="p-2">{s.weekStart}</td>
                  <td className="p-2">
                    v{s.versionNumber} {s.isCurrent ? "" : <span className="text-xs text-muted-foreground">(superseded)</span>}
                  </td>
                  <td className="p-2 capitalize">{s.status}</td>
                  <td className="p-2 text-muted-foreground">{s.rejectReason ?? "—"}</td>
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
