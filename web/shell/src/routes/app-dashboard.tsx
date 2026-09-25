// SPDX-License-Identifier: Apache-2.0

import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "../ui/card";

/** `/app` index — a static "try this" walkthrough card that scripts the docs + helpdesk showcase
 * modules end to end. Plain static content, no new APIs, no live data — a human reads this and
 * then clicks through the real Docs/Helpdesk modules themselves using the three demo
 * credentials listed here. */
export function AppDashboardPage() {
  return (
    <div className="flex flex-col gap-4" data-testid="app-dashboard-page">
      <Card data-testid="dashboard-walkthrough-card">
        <CardHeader>
          <CardTitle>Try this</CardTitle>
          <CardDescription>
            A five-minute walkthrough of document sharing and position-based access, using the Docs and Helpdesk
            modules. Play all three roles yourself with the demo credentials below.
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-4">
          <ol className="flex flex-col gap-3 text-sm" data-testid="dashboard-walkthrough-steps">
            <li>
              <span className="font-medium text-foreground">1. Share a document.</span>{" "}
              <span className="text-muted-foreground">
                As <code className="font-mono">admin</code>, open Docs, create a document, and share it with{" "}
                <code className="font-mono">bob</code> as viewer. The audit trail records the grant.
              </span>
            </li>
            <li>
              <span className="font-medium text-foreground">2. Read it as bob.</span>{" "}
              <span className="text-muted-foreground">
                Log in as <code className="font-mono">bob</code>. He gets a share notification, can read the document,
                and cannot edit it.
              </span>
            </li>
            <li>
              <span className="font-medium text-foreground">3. Revoke, live.</span>{" "}
              <span className="text-muted-foreground">
                Back as <code className="font-mono">admin</code>, revoke bob&apos;s access. Bob can no longer open the
                document. Access is checked on every read, not cached.
              </span>
            </li>
            <li>
              <span className="font-medium text-foreground">4. Raise a ticket, assign it to a seat.</span>{" "}
              <span className="text-muted-foreground">
                As <code className="font-mono">bob</code>, raise a helpdesk ticket. As <code className="font-mono">admin</code>,
                open <code className="font-mono">Positions</code>, create &quot;Support Agent&quot;, bind it as a helpdesk agent
                in Helpdesk &rarr; Agents, then assign the ticket to the Support Agent position rather than to a named
                person, and assign <code className="font-mono">alice</code> to the seat. As{" "}
                <code className="font-mono">alice</code>, start working it (open &rarr; in progress). The work follows the
                position.
              </span>
            </li>
            <li>
              <span className="font-medium text-foreground">5. What admin cannot do.</span>{" "}
              <span className="text-muted-foreground">
                Even <code className="font-mono">admin</code>, a platform superadmin, cannot open a document nobody
                shared with them. Access comes only from explicit grants.
              </span>
            </li>
            <li>
              <span className="font-medium text-foreground">6. Change the seat holder.</span>{" "}
              <span className="text-muted-foreground">
                End <code className="font-mono">alice</code>&apos;s assignment to Support Agent and assign{" "}
                <code className="font-mono">bob</code> instead, with no permission or ticket edits.{" "}
                <code className="font-mono">bob</code> now sees All Tickets and can pick up and resolve the same open
                ticket Support Agent was already handling; <code className="font-mono">alice</code> can no longer act
                on it.
              </span>
            </li>
            <li>
              <span className="font-medium text-foreground">7. A whole team, not just one seat.</span>{" "}
              <span className="text-muted-foreground">
                As <code className="font-mono">admin</code>, open <code className="font-mono">Groups</code>, create
                &quot;Support Team&quot;, add <code className="font-mono">alice</code> and{" "}
                <code className="font-mono">bob</code> as members, bind it as a helpdesk agent in Helpdesk &rarr;
                Agents, then assign a ticket to the Support Team group. Both{" "}
                <code className="font-mono">alice</code> and <code className="font-mono">bob</code> can view and work
                the same ticket at once. Remove <code className="font-mono">bob</code> from the group and he loses
                access to it, while <code className="font-mono">alice</code> keeps hers.
              </span>
            </li>
          </ol>

          <div className="rounded-md border border-border bg-muted/40 p-3" data-testid="dashboard-walkthrough-credentials">
            <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">Demo credentials</p>
            <ul className="mt-1 flex flex-col gap-0.5 font-mono text-sm text-foreground">
              <li>admin / DemoAdmin!2026 (superadmin, module admin)</li>
              <li>alice / DemoAlice!2026 (helpdesk agent)</li>
              <li>bob / DemoBob!2026 (plain member)</li>
            </ul>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
