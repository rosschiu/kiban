// SPDX-License-Identifier: Apache-2.0

// The timesheet module's "entries" route (frontend.manifest.json route id "entries",
// path "" — the module's company-scoped default landing page). Weekly entry grid: draft editing
// of hours per project/day for the current ISO week, plus Submit.
import { useCallback, useEffect, useMemo, useState } from "react";
import { getShellSdk } from "../../auth/sdk";
import type { ModulePageContext } from "../../resolver/resolver";
import { Button } from "../../ui/button";
import { ListPageFrame } from "../../ui/list-page-frame";
import { createTimesheetClient, type TimesheetEntry, type TimesheetProject } from "./api";

function isoMonday(d: Date): Date {
  const day = d.getUTCDay() || 7;
  const monday = new Date(d);
  monday.setUTCDate(d.getUTCDate() - (day - 1));
  monday.setUTCHours(0, 0, 0, 0);
  return monday;
}

function toDateInput(d: Date): string {
  return d.toISOString().slice(0, 10);
}

function weekDays(weekStart: Date): Date[] {
  return Array.from({ length: 7 }, (_, i) => {
    const d = new Date(weekStart);
    d.setUTCDate(weekStart.getUTCDate() + i);
    return d;
  });
}

export function EntriesPage({ context }: { context: ModulePageContext }) {
  const companyId = context.companyId;
  const [weekStart, setWeekStart] = useState(() => isoMonday(new Date()));
  const [projects, setProjects] = useState<TimesheetProject[] | null>(null);
  const [entries, setEntries] = useState<TimesheetEntry[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [status, setStatus] = useState<string | null>(null);

  const days = useMemo(() => weekDays(weekStart), [weekStart]);

  const load = useCallback(
    async (id: string) => {
      try {
        const client = createTimesheetClient(getShellSdk().apiClient);
        const [projPage, entriesResp] = await Promise.all([
          client.listProjects(id, 1, 100),
          client.listEntries(id, toDateInput(weekStart)),
        ]);
        setProjects(projPage.items);
        setEntries(entriesResp.items);
        setError(null);
      } catch {
        setError("Could not load the weekly timesheet.");
      }
    },
    [weekStart],
  );

  useEffect(() => {
    if (companyId) void load(companyId);
  }, [companyId, load]);

  function entryFor(projectId: string, day: Date): TimesheetEntry | undefined {
    const dateStr = toDateInput(day);
    return entries.find((e) => e.projectId === projectId && e.entryDate === dateStr);
  }

  async function handleHoursChange(projectId: string, day: Date, realHours: number): Promise<void> {
    if (!companyId) return;
    try {
      const client = createTimesheetClient(getShellSdk().apiClient);
      await client.upsertEntry(companyId, { projectId, entryDate: toDateInput(day), realHours, billableHours: realHours });
      void load(companyId);
    } catch {
      setError("Could not save the entry (check the value and the editable window).");
    }
  }

  async function handleSubmit(): Promise<void> {
    if (!companyId) return;
    setStatus(null);
    try {
      const client = createTimesheetClient(getShellSdk().apiClient);
      await client.submitWeek(companyId, toDateInput(weekStart));
      setStatus("Week submitted.");
      void load(companyId);
    } catch {
      setError("Could not submit the week (a draft entry and an assigned approver are both required).");
    }
  }

  if (!companyId) return null;

  const draftCount = entries.filter((e) => e.status === "draft").length;

  return (
    <ListPageFrame
      title="Timesheet"
      headerActions={
        <div className="flex items-center gap-2">
          <Button type="button" variant="outline" size="sm" onClick={() => setWeekStart((w) => new Date(w.getTime() - 7 * 86400000))}>
            Previous week
          </Button>
          <span className="text-sm text-muted-foreground">Week of {toDateInput(weekStart)}</span>
          <Button type="button" variant="outline" size="sm" onClick={() => setWeekStart((w) => new Date(w.getTime() + 7 * 86400000))}>
            Next week
          </Button>
          <Button type="button" size="sm" disabled={draftCount === 0} onClick={() => void handleSubmit()} data-testid="timesheet-submit-week">
            Submit week
          </Button>
        </div>
      }
      error={
        error ? (
          <p role="alert" className="text-sm text-destructive">
            {error}
          </p>
        ) : status ? (
          <p className="text-sm text-muted-foreground">{status}</p>
        ) : null
      }
    >
      {projects === null ? null : projects.length === 0 ? (
        <p className="text-sm text-muted-foreground">No projects yet — an admin must create one first.</p>
      ) : (
        <div className="overflow-auto rounded-md border">
          <table className="w-full text-sm" data-testid="timesheet-weekly-grid">
            <thead>
              <tr className="border-b bg-muted/50">
                <th className="p-2 text-left font-medium">Project</th>
                {days.map((d) => (
                  <th key={toDateInput(d)} className="p-2 text-center font-medium">
                    {d.toLocaleDateString(undefined, { weekday: "short", timeZone: "UTC" })}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {projects.map((project) => (
                <tr key={project.id} className="border-b last:border-0">
                  <td className="p-2">
                    {project.name} <span className="text-xs text-muted-foreground">({project.code})</span>
                  </td>
                  {days.map((day) => {
                    const entry = entryFor(project.id, day);
                    const locked = entry !== undefined && entry.status !== "draft";
                    return (
                      <td key={toDateInput(day)} className="p-1 text-center">
                        <input
                          type="number"
                          min={0}
                          max={24}
                          step={0.25}
                          disabled={locked}
                          defaultValue={entry?.realHours ?? ""}
                          data-testid={`entry-${project.id}-${toDateInput(day)}`}
                          className="w-16 rounded-md border border-input bg-background px-1 py-0.5 text-center text-sm disabled:opacity-50"
                          onBlur={(event) => {
                            const value = Number(event.target.value);
                            if (!Number.isNaN(value) && value !== (entry?.realHours ?? -1)) {
                              void handleHoursChange(project.id, day, value);
                            }
                          }}
                        />
                      </td>
                    );
                  })}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </ListPageFrame>
  );
}
