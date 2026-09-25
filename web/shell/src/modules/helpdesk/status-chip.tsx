// SPDX-License-Identifier: Apache-2.0

// A small status chip shared by every ticket list/detail view — status color coding is the
// cheapest "workflow" visual signal a non-developer reads at a glance.
import type { TicketStatus } from "./api";

const STYLES: Record<TicketStatus, string> = {
  open: "bg-blue-100 text-blue-800 dark:bg-blue-950 dark:text-blue-300",
  in_progress: "bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-300",
  resolved: "bg-emerald-100 text-emerald-800 dark:bg-emerald-950 dark:text-emerald-300",
  closed: "bg-muted text-muted-foreground"
};

const LABELS: Record<TicketStatus, string> = {
  open: "Open",
  in_progress: "In progress",
  resolved: "Resolved",
  closed: "Closed"
};

export function StatusChip({ status }: { status: TicketStatus }) {
  return (
    <span className={`rounded-full px-2 py-0.5 text-xs font-medium ${STYLES[status]}`} data-testid={`helpdesk-status-chip-${status}`}>
      {LABELS[status]}
    </span>
  );
}
