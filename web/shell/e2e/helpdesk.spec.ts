// SPDX-License-Identifier: Apache-2.0

import { expect, test, type Page } from "@playwright/test";

// The full helpdesk workflow journey through the REAL browser UI, three DISTINCT
// logged-in identities (three separate browser contexts/sessions) — global-setup.ts's
// `KIBAN_E2E_HELPDESK_REPORTER_*`/`KIBAN_E2E_HELPDESK_AGENT_*` fixtures plus the seeded
// superadmin acting as admin. reporter raises -> admin assigns to a non-agent member (proving the
// live auto-agent-grant) -> agent progresses/resolves -> reporter comments + reopens -> agent
// re-resolves -> reporter closes. Tier contrast is asserted throughout: the reporter's own
// sub-nav never renders an All Tickets or Agents link. Video always-on (playwright.config.ts's
// `use.video`), retained under web/shell/e2e-artifacts/.
async function login(page: Page, username: string, password: string): Promise<void> {
  await page.goto("/");
  await page.getByRole("button", { name: "Log in" }).click();
  await page.waitForURL(/\/auth\/realms\//);
  const usernameField = page.locator("#username");
  await usernameField.waitFor({ state: "visible", timeout: 15_000 });
  await usernameField.fill(username);
  await page.locator("#password").fill(password);
  await page.locator("#kc-login").click();
  await page.waitForURL(/\/app$/, { timeout: 20_000 });
}

async function openHelpdesk(page: Page, companyId: string): Promise<void> {
  await expect(page.getByTestId("company-switcher-select")).toBeVisible({ timeout: 15_000 });
  await page.getByTestId("company-switcher-select").selectOption(companyId);
  const helpdeskLink = page.getByRole("link", { name: /Helpdesk/ });
  await expect(helpdeskLink).toBeVisible({ timeout: 15_000 });
  await helpdeskLink.click();
  await page.waitForURL(new RegExp(`/app/c/${companyId}/helpdesk$`));
  await expect(page.getByTestId("helpdesk-my-tickets-page")).toBeVisible();
}

test.describe("full helpdesk workflow journey — reporter, admin, agent, three real browser sessions", () => {
  test("reporter raises -> admin assigns (auto-agent-grant) -> agent progresses/resolves -> reporter comments+reopens -> agent re-resolves -> reporter closes; tier contrast; notifications land", async ({
    browser,
  }, testInfo) => {
    // Three browser contexts, a longer state-machine walk than any other module's own journey
    // (docs/timesheet.spec.ts's two-identity journeys fit the default 60s) — extend this test's
    // own timeout rather than the shared playwright.config.ts default (which every other spec
    // still uses unchanged).
    test.setTimeout(150_000);
    const recordVideo = { dir: testInfo.outputDir };

    const adminUsername = process.env.KIBAN_E2E_SUPERADMIN_USERNAME;
    const adminPassword = process.env.KIBAN_E2E_SUPERADMIN_PASSWORD;
    const reporterUsername = process.env.KIBAN_E2E_HELPDESK_REPORTER_USERNAME;
    const reporterPassword = process.env.KIBAN_E2E_HELPDESK_REPORTER_PASSWORD;
    const agentUsername = process.env.KIBAN_E2E_HELPDESK_AGENT_USERNAME;
    const agentPassword = process.env.KIBAN_E2E_HELPDESK_AGENT_PASSWORD;
    const agentMemberId = process.env.KIBAN_E2E_HELPDESK_AGENT_ID;
    const companyId = process.env.KIBAN_E2E_COMPANY_ID;
    if (
      !adminUsername ||
      !adminPassword ||
      !reporterUsername ||
      !reporterPassword ||
      !agentUsername ||
      !agentPassword ||
      !agentMemberId ||
      !companyId
    ) {
      throw new Error("KIBAN_E2E_SUPERADMIN_*/KIBAN_E2E_HELPDESK_*/KIBAN_E2E_COMPANY_ID not set — global-setup.ts did not run");
    }

    // --- Reporter session: log in, raise a ticket, verify the tier-contrast nav (no All
    // Tickets/Agents links for a plain member). ---
    const reporterContext = await browser.newContext({ recordVideo });
    const reporterPage = await reporterContext.newPage();
    await login(reporterPage, reporterUsername, reporterPassword);
    await openHelpdesk(reporterPage, companyId);

    await expect(reporterPage.getByTestId("helpdesk-nav-my-tickets")).toBeVisible();
    await expect(reporterPage.getByTestId("helpdesk-nav-all-tickets")).toHaveCount(0);
    await expect(reporterPage.getByTestId("helpdesk-nav-agents")).toHaveCount(0);

    const runId = `${Date.now()}`;
    const ticketTitle = `E2E Printer Fire ${runId}`;
    await reporterPage.getByTestId("helpdesk-new-title").fill(ticketTitle);
    await reporterPage.getByTestId("helpdesk-new-description").fill("Send help, quickly.");
    await reporterPage.getByTestId("helpdesk-create-button").click();

    const ticketItem = reporterPage.locator('[data-testid^="helpdesk-ticket-"]').filter({ hasText: ticketTitle });
    await expect(ticketItem).toBeVisible({ timeout: 10_000 });
    const ticketTestId = await ticketItem.getAttribute("data-testid");
    const ticketId = ticketTestId!.replace("helpdesk-ticket-", "");
    await expect(ticketItem.getByTestId("helpdesk-status-chip-open")).toBeVisible();

    // A non-agent, non-admin plain member cannot reach All Tickets by direct URL either — the
    // page itself shows the denied state (the sub-nav link is hidden, but a typed URL must be
    // denied server-side too, not just link-hidden).
    await reporterPage.goto(`/app/c/${companyId}/helpdesk/all`);
    await expect(reporterPage.getByTestId("helpdesk-all-tickets-denied")).toBeVisible({ timeout: 10_000 });

    // --- Admin (superadmin) session: assign the ticket to the (not-yet-)agent — proving the
    // live auto-agent-grant, not a pre-seeded one. ---
    const adminContext = await browser.newContext({ recordVideo });
    const adminPage = await adminContext.newPage();
    await login(adminPage, adminUsername, adminPassword);
    await openHelpdesk(adminPage, companyId);
    await adminPage.getByTestId("helpdesk-nav-all-tickets").click();
    await adminPage.waitForURL(new RegExp(`/app/c/${companyId}/helpdesk/all$`));
    await expect(adminPage.getByTestId("helpdesk-all-tickets-page")).toBeVisible();

    const adminTicketRow = adminPage.getByTestId(`helpdesk-ticket-${ticketId}`);
    await expect(adminTicketRow).toBeVisible({ timeout: 10_000 });
    // Unassigned so far — the row's own assignee display says so.
    await expect(adminTicketRow.getByTestId(`helpdesk-assignee-${ticketId}`)).toHaveText("Unassigned");
    await adminTicketRow.getByTestId(`helpdesk-assign-${ticketId}`).click();
    await expect(adminPage.getByTestId("helpdesk-assign-sheet")).toBeVisible();
    // The sheet defaults to the Positions tab — switch to Members for this member-picker
    // assignment (this journey proves the member path; walkthrough.spec.ts proves the position path).
    await adminPage.getByTestId("helpdesk-assign-tab-members").click();
    await adminPage.getByTestId("helpdesk-assign-member-search").fill("E2E Helpdesk Agent");
    const assignButton = adminPage.getByTestId(`helpdesk-assign-to-${agentMemberId}`);
    await expect(assignButton).toBeVisible({ timeout: 10_000 });
    await assignButton.click();
    await expect(adminPage.getByTestId("helpdesk-assign-sheet")).toHaveCount(0, { timeout: 10_000 });
    // The row now names the agent's own displayName (server-resolved).
    await expect(adminTicketRow.getByTestId(`helpdesk-assignee-${ticketId}`)).toContainText("E2E Helpdesk Agent", { timeout: 10_000 });

    // --- Agent session: now holds the agent tier (auto-granted by the assignment above) — sees
    // All Tickets, but never Agents (that's admin-only — the three-way tier contrast). ---
    const agentContext = await browser.newContext({ recordVideo });
    const agentPage = await agentContext.newPage();
    await login(agentPage, agentUsername, agentPassword);
    await openHelpdesk(agentPage, companyId);
    await expect(agentPage.getByTestId("helpdesk-nav-all-tickets")).toBeVisible({ timeout: 10_000 });
    await expect(agentPage.getByTestId("helpdesk-nav-agents")).toHaveCount(0);

    // Notification landed for the agent (assignment event) — the sidebar unread badge.
    await expect(agentPage.getByTestId("nav-badge-notification")).toBeVisible({ timeout: 10_000 });

    await agentPage.goto(`/app/c/${companyId}/helpdesk/tickets/${ticketId}`);
    await expect(agentPage.getByTestId("helpdesk-ticket-detail-page")).toBeVisible({ timeout: 10_000 });
    // The ticket detail page also names the assignee.
    await expect(agentPage.getByTestId("helpdesk-ticket-assignee")).toContainText("E2E Helpdesk Agent");
    await agentPage.getByTestId("helpdesk-transition-in_progress").click();
    await expect(agentPage.getByTestId("helpdesk-status-chip-in_progress")).toBeVisible({ timeout: 10_000 });
    await agentPage.getByTestId("helpdesk-transition-resolved").click();
    await expect(agentPage.getByTestId("helpdesk-status-chip-resolved")).toBeVisible({ timeout: 10_000 });

    // --- Reporter comments on the resolved ticket, then reopens it. ---
    await reporterPage.goto(`/app/c/${companyId}/helpdesk/tickets/${ticketId}`);
    await expect(reporterPage.getByTestId("helpdesk-status-chip-resolved")).toBeVisible({ timeout: 10_000 });
    await reporterPage.getByTestId("helpdesk-comment-input").fill("Still smoking a little.");
    await reporterPage.getByTestId("helpdesk-comment-submit").click();
    await expect(reporterPage.getByTestId("helpdesk-comment-list")).toContainText("Still smoking a little.", { timeout: 10_000 });
    await reporterPage.getByTestId("helpdesk-transition-open").click();
    await expect(reporterPage.getByTestId("helpdesk-status-chip-open")).toBeVisible({ timeout: 10_000 });

    // Notification landed for the agent (reporter's comment on their ticket).
    await expect(agentPage.getByTestId("nav-badge-notification")).toBeVisible({ timeout: 10_000 });

    // --- Agent re-resolves. ---
    await agentPage.goto(`/app/c/${companyId}/helpdesk/tickets/${ticketId}`);
    await expect(agentPage.getByTestId("helpdesk-status-chip-open")).toBeVisible({ timeout: 10_000 });
    await agentPage.getByTestId("helpdesk-transition-in_progress").click();
    await expect(agentPage.getByTestId("helpdesk-status-chip-in_progress")).toBeVisible({ timeout: 10_000 });
    await agentPage.getByTestId("helpdesk-transition-resolved").click();
    await expect(agentPage.getByTestId("helpdesk-status-chip-resolved")).toBeVisible({ timeout: 10_000 });

    // --- Reporter closes their own resolved ticket. ---
    await reporterPage.goto(`/app/c/${companyId}/helpdesk/tickets/${ticketId}`);
    await expect(reporterPage.getByTestId("helpdesk-status-chip-resolved")).toBeVisible({ timeout: 10_000 });
    await reporterPage.getByTestId("helpdesk-transition-closed").click();
    await expect(reporterPage.getByTestId("helpdesk-status-chip-closed")).toBeVisible({ timeout: 10_000 });

    // --- The status timeline (from audit events) shows the whole journey. ---
    await reporterPage.reload();
    const auditList = reporterPage.getByTestId("helpdesk-audit-list");
    await expect(auditList).toBeVisible({ timeout: 10_000 });
    await expect(auditList).toContainText("raised this ticket");
    await expect(auditList).toContainText("assigned this ticket");
    await expect(auditList).toContainText("open → in_progress");
    await expect(auditList).toContainText("in_progress → resolved");
    await expect(auditList).toContainText("resolved → open");
    await expect(auditList).toContainText("resolved → closed");

    // Log out all three sessions.
    for (const p of [reporterPage, adminPage, agentPage]) {
      await p.goto("/app");
      await p.getByRole("button", { name: /log out/i }).click();
      await p.waitForURL((url) => !url.searchParams.has("code"), { timeout: 15_000 });
    }
  });
});
