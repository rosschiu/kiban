// SPDX-License-Identifier: Apache-2.0

import { expect, test, type Page } from "@playwright/test";
import { expectNoCSPViolations, watchCSPViolations } from "./csp.js";

// Rehearses the dashboard's own "try this" walkthrough card (app-dashboard.tsx) end
// to end, on kiban-test, as a real browser proves it — not as an opinion. The card's script uses
// three role names (admin / alice / bob); this suite maps them onto the EXISTING e2e fixture
// identities from global-setup.ts rather than inventing new ones (the goal is to prove the
// SCRIPT, not new fixtures):
//
//   admin -> KIBAN_E2E_SUPERADMIN_*        (superadmin, module admin for all three modules)
//   bob   -> KIBAN_E2E_DOCS_MEMBER_*        (steps 1-3, the docs sharing journey)
//         -> KIBAN_E2E_HELPDESK_REPORTER_*  (step 4, the helpdesk journey — "raise a ticket")
//   alice -> KIBAN_E2E_HELPDESK_AGENT_*     (step 4, the helpdesk journey — "resolve it")
//
// "bob" is deliberately played by TWO distinct fixture accounts (one per module) because
// global-setup.ts's existing fixtures are already split that way (the docs and helpdesk specs
// each created their own second identity, independently) — both are plain,
// non-agent, non-admin members in the same fixture company, which is what the script's "bob"
// needs to demonstrate in each half. Documented here rather than adding a new fixture identity
// whose only job would be to have one shared username.
//
// Step 5 (the excludability note — "admin cannot open a doc never shared with them") is proven
// directly: the docs-member identity (playing bob) creates a SECOND document that is never
// shared with anyone, and the admin identity is denied when it navigates straight to it by URL.
//
// Step 6 (position-based access, "the seat carries access") is rehearsed through the REAL
// browser UI — the Positions admin page (`/api/org/admin/...`) and the helpdesk position-bind
// picker — so it drives create/bind/assign/end entirely through clicks, zero psql calls
// (position-access.spec.ts covers the same mechanism with direct-SQL fixture plumbing).
//
// Steps 4 and 6 work together: bob's ticket is assigned to the Support Agent position (not
// alice); alice, holding the chair, works it; step 6 hands the chair to bob — the OPEN ticket
// assigned to Support Agent is now bob's to work, and alice can no longer act on it. Step 4
// creates + binds the "Support Agent" position, assigns
// ALICE to it, and assigns bob's ticket to the POSITION (never to alice by name) through the
// Positions-first assign sheet; alice, the current holder, progresses it to in_progress (left
// deliberately OPEN — not resolved — so step 6 has something real to hand over). Step 6 ends
// alice's tenure and assigns the SAME "bob" identity (KIBAN_E2E_HELPDESK_REPORTER, the ticket's
// own reporter) to the chair instead — zero ticket edits, zero helpdesk/authz calls beyond the
// one position-assignment change — and bob, now holding the seat, resolves the SAME ticket while
// alice can no longer act on it. This spec does not use the KIBAN_E2E_POSITION_HOLDER_A/B
// fixtures (those belong to position-access.spec.ts).
//
// Video always-on (playwright.config.ts's `use.video`), retained under web/shell/e2e-artifacts/.
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

async function selectCompany(page: Page, companyId: string): Promise<void> {
  await expect(page.getByTestId("company-switcher-select")).toBeVisible({ timeout: 15_000 });
  await page.getByTestId("company-switcher-select").selectOption(companyId);
}

// Step 6's own small helpers — same shapes position-access.spec.ts
// already established for "does this identity currently see All Tickets", duplicated locally
// (not imported) since each e2e spec file is Playwright's own unit of isolation here.
async function assertSeesAllTickets(page: Page, companyId: string): Promise<void> {
  await page.goto(`/app/c/${companyId}/helpdesk`);
  await expect(page.getByTestId("helpdesk-my-tickets-page")).toBeVisible({ timeout: 10_000 });
  await expect(page.getByTestId("helpdesk-nav-all-tickets")).toBeVisible({ timeout: 10_000 });
  await page.getByTestId("helpdesk-nav-all-tickets").click();
  await page.waitForURL(new RegExp(`/app/c/${companyId}/helpdesk/all$`));
  await expect(page.getByTestId("helpdesk-all-tickets-page")).toBeVisible({ timeout: 10_000 });
  await expect(page.getByTestId("helpdesk-all-tickets-denied")).toHaveCount(0);
}

test.describe("dashboard walkthrough card, rehearsed step by step on the real UI", () => {
  test("dashboard shows the script; docs share/read/revoke; helpdesk raise/assign/resolve; superadmin excludability; position bind/assign/handover", async ({
    browser,
  }, testInfo) => {
    test.setTimeout(240_000); // step 6 (end + reassign, same-ticket resolve) needs the extra time
    const recordVideo = { dir: testInfo.outputDir };
    const cspViolations: string[] = [];

    const adminUsername = process.env.KIBAN_E2E_SUPERADMIN_USERNAME;
    const adminPassword = process.env.KIBAN_E2E_SUPERADMIN_PASSWORD;
    const docsBobUsername = process.env.KIBAN_E2E_DOCS_MEMBER_USERNAME;
    const docsBobPassword = process.env.KIBAN_E2E_DOCS_MEMBER_PASSWORD;
    const helpdeskBobUsername = process.env.KIBAN_E2E_HELPDESK_REPORTER_USERNAME;
    const helpdeskBobPassword = process.env.KIBAN_E2E_HELPDESK_REPORTER_PASSWORD;
    const helpdeskBobMemberId = process.env.KIBAN_E2E_HELPDESK_REPORTER_ID;
    const aliceUsername = process.env.KIBAN_E2E_HELPDESK_AGENT_USERNAME;
    const alicePassword = process.env.KIBAN_E2E_HELPDESK_AGENT_PASSWORD;
    const aliceMemberId = process.env.KIBAN_E2E_HELPDESK_AGENT_ID;
    const companyId = process.env.KIBAN_E2E_COMPANY_ID;
    if (
      !adminUsername ||
      !adminPassword ||
      !docsBobUsername ||
      !docsBobPassword ||
      !helpdeskBobUsername ||
      !helpdeskBobPassword ||
      !helpdeskBobMemberId ||
      !aliceUsername ||
      !alicePassword ||
      !aliceMemberId ||
      !companyId
    ) {
      throw new Error(
        "KIBAN_E2E_SUPERADMIN_*/KIBAN_E2E_DOCS_MEMBER_*/KIBAN_E2E_HELPDESK_*/KIBAN_E2E_COMPANY_ID not set — global-setup.ts did not run"
      );
    }

    // --- Dashboard: the walkthrough card itself renders the script and the three credentials. ---
    const adminContext = await browser.newContext({ recordVideo });
    const adminPage = await adminContext.newPage();
    watchCSPViolations(adminPage, cspViolations);
    await login(adminPage, adminUsername, adminPassword);
    await expect(adminPage.getByTestId("dashboard-walkthrough-card")).toBeVisible({ timeout: 15_000 });
    await expect(adminPage.getByTestId("dashboard-walkthrough-steps")).toContainText("Share a document");
    await expect(adminPage.getByTestId("dashboard-walkthrough-steps")).toContainText("Read it as bob");
    await expect(adminPage.getByTestId("dashboard-walkthrough-steps")).toContainText("Revoke, live");
    await expect(adminPage.getByTestId("dashboard-walkthrough-steps")).toContainText("Raise a ticket, assign it to a seat");
    await expect(adminPage.getByTestId("dashboard-walkthrough-steps")).toContainText("Change the seat holder");
    await expect(adminPage.getByTestId("dashboard-walkthrough-steps")).toContainText("What admin cannot do");
    await expect(adminPage.getByTestId("dashboard-walkthrough-credentials")).toContainText("admin / DemoAdmin!2026");
    await expect(adminPage.getByTestId("dashboard-walkthrough-credentials")).toContainText("alice / DemoAlice!2026");
    await expect(adminPage.getByTestId("dashboard-walkthrough-credentials")).toContainText("bob / DemoBob!2026");

    // --- Step 1: admin creates a document in Docs and shares it with bob as viewer. ---
    await selectCompany(adminPage, companyId);
    const docsLink = adminPage.getByRole("link", { name: /Docs/ });
    await expect(docsLink).toBeVisible({ timeout: 15_000 });
    await docsLink.click();
    await adminPage.waitForURL(new RegExp(`/app/c/${companyId}/docs$`));
    await expect(adminPage.getByTestId("docs-documents-page")).toBeVisible();

    const runId = `${Date.now()}`;
    const docTitle = `Walkthrough Doc ${runId}`;
    await adminPage.getByTestId("docs-new-title").fill(docTitle);
    await adminPage.getByTestId("docs-create-button").click();

    const docItem = adminPage.locator('[data-testid^="docs-document-"]').filter({ hasText: docTitle });
    await expect(docItem).toBeVisible({ timeout: 10_000 });
    const docTestId = await docItem.getAttribute("data-testid");
    const docId = docTestId!.replace("docs-document-", "");
    await docItem.click();
    await adminPage.waitForURL(new RegExp(`/app/c/${companyId}/docs/documents/${docId}$`));
    await expect(adminPage.getByTestId("docs-document-page")).toBeVisible();

    await adminPage.getByTestId("docs-share-button").click();
    await expect(adminPage.getByTestId("docs-share-sheet")).toBeVisible();
    await adminPage.getByTestId("docs-member-search").fill("E2E Docs Member");
    const shareButton = adminPage.getByTestId(/^docs-share-with-/);
    await expect(shareButton).toBeVisible({ timeout: 10_000 });
    await shareButton.click();
    await expect(adminPage.locator('[data-testid^="docs-share-row-"]')).toBeVisible({ timeout: 10_000 });

    // --- Step 2: bob logs in — gets the share notification, can read, cannot edit. ---
    const bobDocsContext = await browser.newContext({ recordVideo });
    const bobDocsPage = await bobDocsContext.newPage();
    watchCSPViolations(bobDocsPage, cspViolations);
    await login(bobDocsPage, docsBobUsername, docsBobPassword);
    await selectCompany(bobDocsPage, companyId);
    // The share notification landed in bob's inbox (nav unread badge is company-scoped —
    // useNavBadges only fires once activeCompanyId is set, hence the company selection first).
    await expect(bobDocsPage.getByTestId("nav-badge-notification")).toBeVisible({ timeout: 10_000 });
    await bobDocsPage.goto(`/app/c/${companyId}/docs/documents/${docId}`);
    await expect(bobDocsPage.getByTestId("docs-document-page")).toBeVisible({ timeout: 10_000 });
    await expect(bobDocsPage.getByTestId("docs-title-input")).toHaveCount(0); // read-only: no edit form
    await expect(bobDocsPage.getByTestId("docs-share-button")).toHaveCount(0); // viewer, not owner

    // --- Step 3: admin revokes bob — bob's access is gone, live. ---
    await adminPage.reload();
    await adminPage.getByTestId("docs-share-button").click();
    const revokeButton = adminPage.locator('[data-testid^="docs-revoke-"]');
    await expect(revokeButton).toBeVisible({ timeout: 10_000 });
    await revokeButton.click();
    await expect(adminPage.locator('[data-testid^="docs-share-row-"]')).toHaveCount(0, { timeout: 10_000 });

    await bobDocsPage.goto(`/app/c/${companyId}/docs/documents/${docId}`);
    await expect(bobDocsPage.getByTestId("docs-document-denied")).toBeVisible({ timeout: 10_000 });

    // --- Step 5 (excludability, proven now while the docs-bob session and admin session are
    // already open): bob creates a SECOND document, never shared with anyone. Admin, a platform
    // superadmin, cannot open it. ---
    await bobDocsPage.goto(`/app/c/${companyId}/docs`);
    await expect(bobDocsPage.getByTestId("docs-documents-page")).toBeVisible({ timeout: 10_000 });
    const privateTitle = `Bob's Private Doc ${runId}`;
    await bobDocsPage.getByTestId("docs-new-title").fill(privateTitle);
    await bobDocsPage.getByTestId("docs-create-button").click();
    const privateDocItem = bobDocsPage.locator('[data-testid^="docs-document-"]').filter({ hasText: privateTitle });
    await expect(privateDocItem).toBeVisible({ timeout: 10_000 });
    const privateDocTestId = await privateDocItem.getAttribute("data-testid");
    const privateDocId = privateDocTestId!.replace("docs-document-", "");

    await adminPage.goto(`/app/c/${companyId}/docs/documents/${privateDocId}`);
    await expect(adminPage.getByTestId("docs-document-denied")).toBeVisible({ timeout: 10_000 });

    // --- Step 4: bob raises a helpdesk ticket; admin creates + binds a "Support
    // Agent" position, assigns alice to it, and assigns bob's ticket to the POSITION — never to
    // alice by name — through the Positions-first assign sheet; alice, the current holder,
    // progresses it. ---
    const bobHelpdeskContext = await browser.newContext({ recordVideo });
    const bobHelpdeskPage = await bobHelpdeskContext.newPage();
    watchCSPViolations(bobHelpdeskPage, cspViolations);
    await login(bobHelpdeskPage, helpdeskBobUsername, helpdeskBobPassword);
    await selectCompany(bobHelpdeskPage, companyId);
    const helpdeskLinkBob = bobHelpdeskPage.getByRole("link", { name: /Helpdesk/ });
    await expect(helpdeskLinkBob).toBeVisible({ timeout: 15_000 });
    await helpdeskLinkBob.click();
    await bobHelpdeskPage.waitForURL(new RegExp(`/app/c/${companyId}/helpdesk$`));
    await expect(bobHelpdeskPage.getByTestId("helpdesk-my-tickets-page")).toBeVisible();

    const ticketTitle = `Walkthrough Ticket ${runId}`;
    await bobHelpdeskPage.getByTestId("helpdesk-new-title").fill(ticketTitle);
    await bobHelpdeskPage.getByTestId("helpdesk-new-description").fill("Walkthrough rehearsal ticket.");
    await bobHelpdeskPage.getByTestId("helpdesk-create-button").click();

    const ticketItem = bobHelpdeskPage.locator('[data-testid^="helpdesk-ticket-"]').filter({ hasText: ticketTitle });
    await expect(ticketItem).toBeVisible({ timeout: 10_000 });
    const ticketTestId = await ticketItem.getAttribute("data-testid");
    const ticketId = ticketTestId!.replace("helpdesk-ticket-", "");

    // Create the "Support Agent" position (admin already has companyId selected from step 1).
    const positionCode = `E2ESTEP4${runId}`;
    const positionTitle = `Support Agent ${runId}`;
    await adminPage.goto("/app/admin/positions");
    await expect(adminPage.getByTestId("admin-positions-page")).toBeVisible({ timeout: 10_000 });
    await adminPage.getByTestId("admin-position-code-input").fill(positionCode);
    await adminPage.getByTestId("admin-position-title-input").fill(positionTitle);
    await adminPage.getByTestId("admin-position-create-button").click();

    const positionRow = adminPage.locator('[data-testid^="admin-position-"]').filter({ hasText: positionTitle });
    await expect(positionRow).toBeVisible({ timeout: 10_000 });
    const positionTestId = await positionRow.getAttribute("data-testid");
    const positionId = positionTestId!.replace("admin-position-", "");

    // Bind the new position as a helpdesk agent, via the Agents admin page's position picker.
    await adminPage.goto(`/app/c/${companyId}/helpdesk/agents`);
    await expect(adminPage.getByTestId("helpdesk-agents-page")).toBeVisible({ timeout: 10_000 });
    const bindButton = adminPage.getByTestId(`helpdesk-bind-position-${positionId}`);
    await expect(bindButton).toBeVisible({ timeout: 10_000 });
    await bindButton.click();
    await expect(adminPage.getByTestId(`helpdesk-agent-${positionId}`)).toBeVisible({ timeout: 10_000 });
    await expect(adminPage.getByTestId(`helpdesk-agent-binding-kind-${positionId}`)).toContainText("(position)");

    // Assign alice to the position.
    await adminPage.goto("/app/admin/positions");
    await expect(adminPage.getByTestId("admin-positions-page")).toBeVisible({ timeout: 10_000 });
    await adminPage.getByTestId(`admin-position-assign-${positionId}`).click();
    await adminPage.getByTestId(`admin-position-member-search-${positionId}`).fill("E2E Helpdesk Agent");
    const assignAlice = adminPage.getByTestId(`admin-position-assign-member-${positionId}-${aliceMemberId}`);
    await expect(assignAlice).toBeVisible({ timeout: 10_000 });
    await assignAlice.click();
    await expect(adminPage.getByTestId(`admin-position-holder-${positionId}`)).toContainText("E2E Helpdesk Agent", {
      timeout: 10_000
    });

    // Assign bob's ticket to the SUPPORT AGENT POSITION — the Positions tab is the assign
    // sheet's default.
    await adminPage.goto(`/app/c/${companyId}/helpdesk/all`);
    await expect(adminPage.getByTestId("helpdesk-all-tickets-page")).toBeVisible({ timeout: 10_000 });
    const adminTicketRow = adminPage.getByTestId(`helpdesk-ticket-${ticketId}`);
    await expect(adminTicketRow).toBeVisible({ timeout: 10_000 });
    await adminTicketRow.getByTestId(`helpdesk-assign-${ticketId}`).click();
    await expect(adminPage.getByTestId("helpdesk-assign-sheet")).toBeVisible();
    await expect(adminPage.getByTestId("helpdesk-assign-tab-positions")).toHaveAttribute("aria-selected", "true");
    const assignToPositionButton = adminPage.getByTestId(`helpdesk-assign-to-position-${positionId}`);
    await expect(assignToPositionButton).toBeVisible({ timeout: 10_000 });
    await assignToPositionButton.click();
    await expect(adminPage.getByTestId("helpdesk-assign-sheet")).toHaveCount(0, { timeout: 10_000 });
    await expect(adminTicketRow.getByTestId(`helpdesk-assignee-${ticketId}`)).toContainText(positionTitle, { timeout: 10_000 });

    // Alice, the CURRENT holder — never named directly on the ticket — sees and progresses it.
    const aliceContext = await browser.newContext({ recordVideo });
    const alicePage = await aliceContext.newPage();
    watchCSPViolations(alicePage, cspViolations);
    await login(alicePage, aliceUsername, alicePassword);
    await selectCompany(alicePage, companyId);
    // Assignment notification landed for alice (the position's current holder, resolved at send time).
    await expect(alicePage.getByTestId("nav-badge-notification")).toBeVisible({ timeout: 10_000 });
    await alicePage.goto(`/app/c/${companyId}/helpdesk/tickets/${ticketId}`);
    await expect(alicePage.getByTestId("helpdesk-ticket-detail-page")).toBeVisible({ timeout: 10_000 });
    await expect(alicePage.getByTestId("helpdesk-ticket-assignee")).toContainText(positionTitle);
    await alicePage.getByTestId("helpdesk-transition-in_progress").click();
    await expect(alicePage.getByTestId("helpdesk-status-chip-in_progress")).toBeVisible({ timeout: 10_000 });
    // Deliberately left OPEN (in_progress, not resolved) — step 6 hands the SAME open ticket over.

    // --- Step 6: end alice's tenure and assign bob (the ticket's own reporter)
    // instead — zero ticket edits. Bob picks up and resolves the SAME open ticket; alice can no
    // longer act on it. ---
    await adminPage.goto("/app/admin/positions");
    await expect(adminPage.getByTestId("admin-positions-page")).toBeVisible({ timeout: 10_000 });
    await adminPage.getByTestId(`admin-position-end-${positionId}`).click();
    await expect(adminPage.getByTestId(`admin-position-vacant-${positionId}`)).toBeVisible({ timeout: 10_000 });
    await adminPage.getByTestId(`admin-position-assign-${positionId}`).click();
    await adminPage.getByTestId(`admin-position-member-search-${positionId}`).fill("E2E Helpdesk Reporter");
    const assignBob = adminPage.getByTestId(`admin-position-assign-member-${positionId}-${helpdeskBobMemberId}`);
    await expect(assignBob).toBeVisible({ timeout: 10_000 });
    await assignBob.click();
    await expect(adminPage.getByTestId(`admin-position-holder-${positionId}`)).toContainText("E2E Helpdesk Reporter", {
      timeout: 10_000
    });

    // Alice, the FORMER holder (same already-authenticated session, no new login), can no longer
    // act on THIS ticket — reloading re-resolves holdership at read time and the transition
    // button she used a moment ago is simply gone. (Deliberately NOT a company-wide "All Tickets"
    // nav-denial check here: this walkthrough's "alice" IS
    // the shared `KIBAN_E2E_HELPDESK_AGENT` fixture helpdesk.spec.ts's own journey directly grants
    // company_module#editor to in the SAME fixture company — a permanent, independent grant that
    // legitimately keeps her company-wide agent tier and its nav entry regardless of THIS
    // position's holdership. The walkthrough script is ticket-scoped ("alice can no longer act
    // on it") — proven above — not company-wide, so this assertion stays ticket-scoped too.)
    await alicePage.reload();
    await expect(alicePage.getByTestId("helpdesk-ticket-detail-page")).toBeVisible({ timeout: 10_000 });
    await expect(alicePage.getByTestId("helpdesk-transition-resolved")).toHaveCount(0, { timeout: 10_000 });

    // Bob (the SAME already-authenticated reporter session from step 4) now also holds the
    // chair — sees All Tickets, and picks up + resolves the SAME open ticket, no new login, zero
    // permission edits beyond the one position-assignment change above.
    await assertSeesAllTickets(bobHelpdeskPage, companyId);
    await bobHelpdeskPage.goto(`/app/c/${companyId}/helpdesk/tickets/${ticketId}`);
    await expect(bobHelpdeskPage.getByTestId("helpdesk-ticket-detail-page")).toBeVisible({ timeout: 10_000 });
    await expect(bobHelpdeskPage.getByTestId("helpdesk-ticket-assignee")).toContainText(positionTitle);
    await bobHelpdeskPage.getByTestId("helpdesk-transition-resolved").click();
    await expect(bobHelpdeskPage.getByTestId("helpdesk-status-chip-resolved")).toBeVisible({ timeout: 10_000 });

    // Cleanup: end bob's assignment to the throwaway Support Agent position. Without this, the
    // SHARED `KIBAN_E2E_HELPDESK_REPORTER` fixture would keep the agent tier (via the still-bound
    // position) for every OTHER spec's run against the same long-lived kiban-test stack —
    // helpdesk.spec.ts's own journey assumes the reporter fixture starts as a plain member (its
    // own "a non-agent, non-admin plain member cannot reach All Tickets" assertion), which this
    // walkthrough would otherwise silently break for good. Ending the assignment (vacating the
    // seat) is enough — it needs no ticket-close first (only the AGENT BINDING's own removal is
    // blocked by open tickets, per helpdesk's protection rule; ending an ASSIGNMENT is not).
    await adminPage.goto("/app/admin/positions");
    await expect(adminPage.getByTestId("admin-positions-page")).toBeVisible({ timeout: 10_000 });
    await adminPage.getByTestId(`admin-position-end-${positionId}`).click();
    await expect(adminPage.getByTestId(`admin-position-vacant-${positionId}`)).toBeVisible({ timeout: 10_000 });

    // Log out every session.
    for (const p of [adminPage, bobDocsPage, bobHelpdeskPage, alicePage]) {
      await p.goto("/app");
      await p.getByRole("button", { name: /log out/i }).click();
      await p.waitForURL((url) => !url.searchParams.has("code"), { timeout: 15_000 });
    }

    expectNoCSPViolations(cspViolations);
  });
});
