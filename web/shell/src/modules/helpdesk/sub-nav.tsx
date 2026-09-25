// SPDX-License-Identifier: Apache-2.0

// The helpdesk module's own INTERNAL sub-navigation — "My tickets" always, "All tickets" and
// "Agents" only once the tier hook resolves to agent/admin (resp. admin) — see tier.ts's header
// comment for why this lives here rather than the shell's route-level nav. Rendered at the top of
// every helpdesk page so the tier contrast is visible no matter which route a caller lands on
// directly (a plain member typing /all in the URL bar still gets the page's own access-denied
// state, never a client-side link they could have followed).
import { Link } from "@tanstack/react-router";
import type { HelpdeskTier } from "./api";

export function HelpdeskSubNav({ companyId, tier }: { companyId: string; tier: HelpdeskTier | null }) {
  const myTicketsHref = `/app/c/${companyId}/helpdesk`;
  const allTicketsHref = `/app/c/${companyId}/helpdesk/all`;
  const agentsHref = `/app/c/${companyId}/helpdesk/agents`;
  return (
    <nav className="flex items-center gap-1 border-b border-border pb-2 text-sm" data-testid="helpdesk-sub-nav">
      <Link to={myTicketsHref} className="rounded-md px-2 py-1 hover:bg-accent" data-testid="helpdesk-nav-my-tickets">
        My Tickets
      </Link>
      {tier === "agent" || tier === "admin" ? (
        <Link to={allTicketsHref} className="rounded-md px-2 py-1 hover:bg-accent" data-testid="helpdesk-nav-all-tickets">
          All Tickets
        </Link>
      ) : null}
      {tier === "admin" ? (
        <Link to={agentsHref} className="rounded-md px-2 py-1 hover:bg-accent" data-testid="helpdesk-nav-agents">
          Agents
        </Link>
      ) : null}
      {tier ? (
        <span className="ml-auto rounded-full border border-border px-2 py-0.5 text-xs text-muted-foreground" data-testid="helpdesk-my-tier">
          {tier}
        </span>
      ) : null}
    </nav>
  );
}
