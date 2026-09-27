// SPDX-License-Identifier: Apache-2.0

import { expect, test, type Page } from "@playwright/test";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { loadTestEnv, psqlExec, psqlScalar } from "../../e2e-shared/env.js";

// The GROUP story — the third assignment/access target (member · position · group) —
// rehearsed through the REAL browser UI, end to end: superadmin creates a "Support Team" group on
// the Groups admin page -> adds two member identities via the member picker -> binds the group as
// a helpdesk agent on the Agents admin page (the "Bind a group" section, mirroring
// the "Bind a position" section) -> assigns a ticket to the group via the assign sheet's
// Groups tab -> BOTH members can see/work the ticket (assignee display names the GROUP, never a
// single member) -> superadmin removes one member from the group -> that member loses the
// ticket/agent view LIVE, the other keeps it. Also proves the read-only rendering branch for an
// externally-sourced group (fixture SQL row, source='fixture:test' — allowed as test fixture only,
// no sync code is involved).
//
// global-setup.ts's `KIBAN_E2E_GROUP_MEMBER_{A,B}_*` fixtures are two plain members, never
// directly granted the agent tier — deliberately distinct from
// `KIBAN_E2E_POSITION_HOLDER_{A,B}` (position-access.spec.ts's own fixtures) so the two specs
// never race each other's cleanup on the same shared kiban-test stack.
//
// Video always-on (playwright.config.ts's `use.video`), retained under web/shell/e2e-artifacts/.

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, "..", "..", "..");

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

async function openHelpdesk(page: Page, companyId: string): Promise<void> {
  await selectCompany(page, companyId);
  const helpdeskLink = page.getByRole("link", { name: /Helpdesk/ });
  await expect(helpdeskLink).toBeVisible({ timeout: 15_000 });
  await helpdeskLink.click();
  await page.waitForURL(new RegExp(`/app/c/${companyId}/helpdesk$`));
  await expect(page.getByTestId("helpdesk-my-tickets-page")).toBeVisible();
}

async function assertSeesAllTickets(page: Page, companyId: string): Promise<void> {
  await page.goto(`/app/c/${companyId}/helpdesk`);
  await expect(page.getByTestId("helpdesk-my-tickets-page")).toBeVisible({ timeout: 10_000 });
  await expect(page.getByTestId("helpdesk-nav-all-tickets")).toBeVisible({ timeout: 10_000 });
  await page.getByTestId("helpdesk-nav-all-tickets").click();
  await page.waitForURL(new RegExp(`/app/c/${companyId}/helpdesk/all$`));
  await expect(page.getByTestId("helpdesk-all-tickets-page")).toBeVisible({ timeout: 10_000 });
  await expect(page.getByTestId("helpdesk-all-tickets-denied")).toHaveCount(0);
}

async function assertDeniedAllTickets(page: Page, companyId: string): Promise<void> {
  await page.goto(`/app/c/${companyId}/helpdesk`);
  await expect(page.getByTestId("helpdesk-my-tickets-page")).toBeVisible({ timeout: 10_000 });
  await expect(page.getByTestId("helpdesk-nav-all-tickets")).toHaveCount(0);
  // Server-side, not just link-hidden — a direct URL must deny too.
  await page.goto(`/app/c/${companyId}/helpdesk/all`);
  await expect(page.getByTestId("helpdesk-all-tickets-denied")).toBeVisible({ timeout: 10_000 });
}

test.describe("group-based access recipe — create group, add members, bind agent, assign, live removal", () => {
  test("Support Team group: both members see/work the group-assigned ticket; removing one revokes it live, the other keeps it", async ({
    browser
  }, testInfo) => {
    test.setTimeout(180_000);
    const recordVideo = { dir: testInfo.outputDir };
    const env = loadTestEnv(repoRoot);

    const adminUsername = process.env.KIBAN_E2E_SUPERADMIN_USERNAME;
    const adminPassword = process.env.KIBAN_E2E_SUPERADMIN_PASSWORD;
    const reporterUsername = process.env.KIBAN_E2E_HELPDESK_REPORTER_USERNAME;
    const reporterPassword = process.env.KIBAN_E2E_HELPDESK_REPORTER_PASSWORD;
    const memberAUsername = process.env.KIBAN_E2E_GROUP_MEMBER_A_USERNAME;
    const memberAPassword = process.env.KIBAN_E2E_GROUP_MEMBER_A_PASSWORD;
    const memberAId = process.env.KIBAN_E2E_GROUP_MEMBER_A_ID;
    const memberBUsername = process.env.KIBAN_E2E_GROUP_MEMBER_B_USERNAME;
    const memberBPassword = process.env.KIBAN_E2E_GROUP_MEMBER_B_PASSWORD;
    const memberBId = process.env.KIBAN_E2E_GROUP_MEMBER_B_ID;
    const companyId = process.env.KIBAN_E2E_COMPANY_ID;
    const superadminMemberId = process.env.KIBAN_E2E_SUPERADMIN_MEMBER_ID;
    if (
      !adminUsername ||
      !adminPassword ||
      !reporterUsername ||
      !reporterPassword ||
      !memberAUsername ||
      !memberAPassword ||
      !memberAId ||
      !memberBUsername ||
      !memberBPassword ||
      !memberBId ||
      !companyId ||
      !superadminMemberId
    ) {
      throw new Error(
        "KIBAN_E2E_SUPERADMIN_*/KIBAN_E2E_HELPDESK_REPORTER_*/KIBAN_E2E_GROUP_MEMBER_*/KIBAN_E2E_COMPANY_ID not set — global-setup.ts did not run"
      );
    }

    const runId = `${Date.now()}`;

    // --- Admin session: create the "Support Team" group on the Groups admin page. ---
    const adminContext = await browser.newContext({ recordVideo });
    const adminPage = await adminContext.newPage();
    await login(adminPage, adminUsername, adminPassword);
    await selectCompany(adminPage, companyId);

    const groupCode = `E2EGRP${runId}`;
    const groupName = `Support Team ${runId}`;
    await adminPage.goto("/app/admin/groups");
    await expect(adminPage.getByTestId("admin-groups-page")).toBeVisible({ timeout: 10_000 });
    await adminPage.getByTestId("admin-group-code-input").fill(groupCode);
    await adminPage.getByTestId("admin-group-name-input").fill(groupName);
    await adminPage.getByTestId("admin-group-create-button").click();

    const groupRow = adminPage.locator('[data-testid^="admin-group-"]').filter({ hasText: groupName });
    await expect(groupRow).toBeVisible({ timeout: 10_000 });
    const groupTestId = await groupRow.getAttribute("data-testid");
    const groupId = groupTestId!.replace("admin-group-", "");

    // Expand the group and add BOTH members via the member picker.
    await adminPage.getByTestId(`admin-group-expand-${groupId}`).click();
    await adminPage.getByTestId(`admin-group-add-button-${groupId}`).click();
    await adminPage.getByTestId(`admin-group-member-search-${groupId}`).fill("E2E Group Member A");
    const addA = adminPage.getByTestId(`admin-group-add-member-${groupId}-${memberAId}`);
    await expect(addA).toBeVisible({ timeout: 10_000 });
    await addA.click();
    await expect(adminPage.getByTestId(`admin-group-members-${groupId}`)).toContainText("E2E Group Member A", {
      timeout: 10_000
    });

    await adminPage.getByTestId(`admin-group-add-button-${groupId}`).click();
    await adminPage.getByTestId(`admin-group-member-search-${groupId}`).fill("E2E Group Member B");
    const addB = adminPage.getByTestId(`admin-group-add-member-${groupId}-${memberBId}`);
    await expect(addB).toBeVisible({ timeout: 10_000 });
    await addB.click();
    await expect(adminPage.getByTestId(`admin-group-members-${groupId}`)).toContainText("E2E Group Member B", {
      timeout: 10_000
    });
    await expect(adminPage.getByTestId(`admin-group-expand-${groupId}`)).toContainText("2 members", { timeout: 10_000 });

    // --- Bind the group as a helpdesk agent (Agents admin page, the "Bind a group" section this
    // WP added — every CURRENT member inherits the tier). ---
    await adminPage.goto(`/app/c/${companyId}/helpdesk/agents`);
    await expect(adminPage.getByTestId("helpdesk-agents-page")).toBeVisible({ timeout: 10_000 });
    const bindGroupButton = adminPage.getByTestId(`helpdesk-bind-group-${groupId}`);
    await expect(bindGroupButton).toBeVisible({ timeout: 10_000 });
    await bindGroupButton.click();
    await expect(adminPage.getByTestId(`helpdesk-agent-${groupId}`)).toBeVisible({ timeout: 10_000 });
    await expect(adminPage.getByTestId(`helpdesk-agent-binding-kind-${groupId}`)).toContainText(`${groupName} (group)`);

    // --- Reporter raises a ticket. ---
    const reporterContext = await browser.newContext({ recordVideo });
    const reporterPage = await reporterContext.newPage();
    await login(reporterPage, reporterUsername, reporterPassword);
    await openHelpdesk(reporterPage, companyId);

    const ticketTitle = `E2E Group Ticket ${runId}`;
    await reporterPage.getByTestId("helpdesk-new-title").fill(ticketTitle);
    await reporterPage.getByTestId("helpdesk-new-description").fill("The whole team should see this.");
    await reporterPage.getByTestId("helpdesk-create-button").click();
    const ticketItem = reporterPage.locator('[data-testid^="helpdesk-ticket-"]').filter({ hasText: ticketTitle });
    await expect(ticketItem).toBeVisible({ timeout: 10_000 });
    const ticketTestId = await ticketItem.getAttribute("data-testid");
    const ticketId = ticketTestId!.replace("helpdesk-ticket-", "");

    // --- Admin assigns the ticket to the GROUP via the assign sheet's Groups tab. ---
    await adminPage.goto(`/app/c/${companyId}/helpdesk/all`);
    await expect(adminPage.getByTestId("helpdesk-all-tickets-page")).toBeVisible({ timeout: 10_000 });
    const adminTicketRow = adminPage.getByTestId(`helpdesk-ticket-${ticketId}`);
    await expect(adminTicketRow).toBeVisible({ timeout: 10_000 });
    await adminTicketRow.getByTestId(`helpdesk-assign-${ticketId}`).click();
    await expect(adminPage.getByTestId("helpdesk-assign-sheet")).toBeVisible();
    await adminPage.getByTestId("helpdesk-assign-tab-groups").click();
    const assignToGroupButton = adminPage.getByTestId(`helpdesk-assign-to-group-${groupId}`);
    await expect(assignToGroupButton).toBeVisible({ timeout: 10_000 });
    await assignToGroupButton.click();
    await expect(adminPage.getByTestId("helpdesk-assign-sheet")).toHaveCount(0, { timeout: 10_000 });
    // The assignee display names the GROUP, not any one member.
    await expect(adminTicketRow.getByTestId(`helpdesk-assignee-${ticketId}`)).toContainText(groupName, { timeout: 10_000 });

    // --- BOTH members see and can work the SAME ticket, real UI, real engine chain
    // (group#member -> member#mapped_user -> user), zero direct grant to either member. ---
    const memberAContext = await browser.newContext({ recordVideo });
    const memberAPage = await memberAContext.newPage();
    await login(memberAPage, memberAUsername, memberAPassword);
    await openHelpdesk(memberAPage, companyId);
    await assertSeesAllTickets(memberAPage, companyId);
    await memberAPage.goto(`/app/c/${companyId}/helpdesk/tickets/${ticketId}`);
    await expect(memberAPage.getByTestId("helpdesk-ticket-detail-page")).toBeVisible({ timeout: 10_000 });
    await expect(memberAPage.getByTestId("helpdesk-ticket-assignee")).toContainText(groupName);
    await memberAPage.getByTestId("helpdesk-transition-in_progress").click();
    await expect(memberAPage.getByTestId("helpdesk-status-chip-in_progress")).toBeVisible({ timeout: 10_000 });

    const memberBContext = await browser.newContext({ recordVideo });
    const memberBPage = await memberBContext.newPage();
    await login(memberBPage, memberBUsername, memberBPassword);
    await openHelpdesk(memberBPage, companyId);
    await assertSeesAllTickets(memberBPage, companyId);
    await memberBPage.goto(`/app/c/${companyId}/helpdesk/tickets/${ticketId}`);
    await expect(memberBPage.getByTestId("helpdesk-ticket-detail-page")).toBeVisible({ timeout: 10_000 });
    await expect(memberBPage.getByTestId("helpdesk-ticket-assignee")).toContainText(groupName);
    // B can act on it too — the whole group counts as assignee (not just whoever B happens to be).
    await expect(memberBPage.getByTestId("helpdesk-transition-resolved")).toBeVisible({ timeout: 10_000 });

    // --- Admin removes B from the group — live, zero ticket edits. ---
    await adminPage.goto("/app/admin/groups");
    await expect(adminPage.getByTestId("admin-groups-page")).toBeVisible({ timeout: 10_000 });
    await adminPage.getByTestId(`admin-group-expand-${groupId}`).click();
    // The member list renders one row per member (name+email) — find B's own row by text and
    // click its Remove button.
    const memberBRow = adminPage.locator(`[data-testid="admin-group-members-${groupId}"] li`).filter({ hasText: "E2E Group Member B" });
    await expect(memberBRow).toBeVisible({ timeout: 10_000 });
    await memberBRow.getByRole("button", { name: "Remove" }).click();
    await expect(memberBRow).toHaveCount(0, { timeout: 10_000 });

    // --- B (same already-authenticated session) loses the ticket AND All Tickets live: the
    // group-assignee check is a live per-request S2S authz call (no caching), so B's very next
    // GET for this ticket is a flat 403 — B is not the reporter, not admin, and no longer a group
    // member, so canSeeTicket denies outright and the shell renders the denied state, not the
    // detail page with a hidden button. ---
    await memberBPage.reload();
    await expect(memberBPage.getByTestId("helpdesk-ticket-denied")).toBeVisible({ timeout: 10_000 });
    await assertDeniedAllTickets(memberBPage, companyId);

    // --- A (same already-authenticated session) still has it — resolves the ticket. ---
    await memberAPage.reload();
    await expect(memberAPage.getByTestId("helpdesk-ticket-detail-page")).toBeVisible({ timeout: 10_000 });
    await memberAPage.getByTestId("helpdesk-transition-resolved").click();
    await expect(memberAPage.getByTestId("helpdesk-status-chip-resolved")).toBeVisible({ timeout: 10_000 });
    await assertSeesAllTickets(memberAPage, companyId);

    // --- Read-only rendering for an externally-sourced group: fixture SQL row only
    // (source='fixture:test' — allowed as test fixture, no sync code, no production code
    // changes), never through the write API (which the single-writer invariant refuses). ---
    const extGroupId = psqlScalar(
      env,
      `INSERT INTO org.group (company_id, code, name, source, external_ref)
       VALUES ('${companyId}', 'E2EEXT${runId}', 'External Team ${runId}', 'fixture:test', 'ext-${runId}')
       RETURNING id`
    );
    expect(extGroupId).toBeTruthy();
    psqlExec(
      env,
      `INSERT INTO org.group_member (group_id, member_id, added_by)
       VALUES ('${extGroupId}', '${superadminMemberId}', 'e2e-fixture')`
    );

    await adminPage.goto("/app/admin/groups");
    await expect(adminPage.getByTestId("admin-groups-page")).toBeVisible({ timeout: 10_000 });
    await expect(adminPage.getByTestId(`admin-group-source-badge-${extGroupId}`)).toContainText("fixture:test", {
      timeout: 10_000
    });
    await adminPage.getByTestId(`admin-group-expand-${extGroupId}`).click();
    await expect(adminPage.getByTestId(`admin-group-readonly-${extGroupId}`)).toBeVisible({ timeout: 10_000 });
    await expect(adminPage.getByTestId(`admin-group-add-button-${extGroupId}`)).toHaveCount(0);
    await expect(adminPage.locator(`[data-testid^="admin-group-remove-member-${extGroupId}-"]`)).toHaveCount(0);

    // Log out every session.
    for (const p of [adminPage, reporterPage, memberAPage, memberBPage]) {
      await p.goto("/app");
      await p.getByRole("button", { name: /log out/i }).click();
      await p.waitForURL((url) => !url.searchParams.has("code"), { timeout: 15_000 });
    }
  });
});
