// SPDX-License-Identifier: Apache-2.0

import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { AppDashboardPage } from "../../src/routes/app-dashboard";

// The dashboard shows a "try this" walkthrough card. Plain static content, no APIs/data fetching —
// this test only proves the card renders the 5-step script and the three demo credentials.
describe("AppDashboardPage", () => {
  it("renders the walkthrough card with all seven steps", () => {
    render(<AppDashboardPage />);
    expect(screen.getByTestId("dashboard-walkthrough-card")).toBeInTheDocument();
    expect(screen.getByText("Try this")).toBeInTheDocument();
    expect(screen.getByText(/1\. Share a document\./)).toBeInTheDocument();
    expect(screen.getByText(/2\. Read it as bob\./)).toBeInTheDocument();
    expect(screen.getByText(/3\. Revoke, live\./)).toBeInTheDocument();
    expect(screen.getByText(/4\. Raise a ticket, assign it to a seat\./)).toBeInTheDocument();
    expect(screen.getByText(/5\. What admin cannot do\./)).toBeInTheDocument();
    expect(screen.getByText(/6\. Change the seat holder\./)).toBeInTheDocument();
    expect(screen.getByText(/7\. A whole team, not just one seat\./)).toBeInTheDocument();
  });

  it("lists the three demo credentials", () => {
    render(<AppDashboardPage />);
    const credentials = screen.getByTestId("dashboard-walkthrough-credentials");
    expect(credentials).toHaveTextContent("admin / DemoAdmin!2026 (superadmin, module admin)");
    expect(credentials).toHaveTextContent("alice / DemoAlice!2026 (helpdesk agent)");
    expect(credentials).toHaveTextContent("bob / DemoBob!2026 (plain member)");
  });
});
