// SPDX-License-Identifier: Apache-2.0

// Client-side mirror of modules/helpdesk/service/http.go's validEdges/canTransition — computed
// here ONLY to decide which buttons to show; the server re-validates and enforces every one of
// these rules independently (never trust the client). Kept in one place so both the ticket list
// and detail views render identical actions.
import type { HelpdeskTicket, TicketStatus } from "./api";

export interface Transition {
  to: TicketStatus;
  label: string;
}

export function availableTransitions(ticket: HelpdeskTicket, tier: "member" | "agent" | "admin" | null): Transition[] {
  const isAdmin = tier === "admin";
  const out: Transition[] = [];
  switch (ticket.status) {
    case "open":
      if (ticket.isAssignee || isAdmin) out.push({ to: "in_progress", label: "Start progress" });
      break;
    case "in_progress":
      if (ticket.isAssignee || isAdmin) out.push({ to: "resolved", label: "Resolve" });
      break;
    case "resolved":
      if (ticket.isReporter || isAdmin) {
        out.push({ to: "closed", label: "Close" });
        out.push({ to: "open", label: "Reopen" });
      }
      break;
    case "closed":
      break;
  }
  return out;
}
