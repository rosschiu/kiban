// SPDX-License-Identifier: Apache-2.0

import { expect, test, type Page } from "@playwright/test";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { loadTestEnv, psqlExec, psqlScalar } from "../../e2e-shared/env.js";

// The position-based access RECIPE, through the REAL browser UI — create a position
// -> bind the helpdesk agent tier to it -> assign identity A (A sees All Tickets) -> end A's
// assignment + assign identity B, ZERO permission mutations between (the "successor
// inherits the position's access") -> B sees All Tickets, A no longer does. global-setup.ts's
// `KIBAN_E2E_POSITION_HOLDER_{A,B}_*` fixtures are two plain members, never directly granted the
// agent tier — the whole point is that they gain/lose it ONLY by holding the bound position.
//
// This spec deliberately does not use the positions UI (walkthrough.spec.ts covers it). Every
// module's own e2e spec that needs an admin action with no dedicated UI form goes through the API
// directly (timesheet.spec.ts's create-project/assign-approver precedent) — but unlike every
// OTHER module in this suite, `org` is NOT gateway-mounted for position/assignment writes at all
// (infra/compose.yaml's own header: "registry/identity/org/authz run as compose services
// reachable only on the compose-internal network" — only a few NAMED org reads are proxied,
// internal/gateway/foundation_routes.go). A host-run Playwright process genuinely cannot reach
// org's `POST /internal/org/positions`/`.../assignments`/`.../assignments/{id}/end` the way it
// reaches helpdesk's real `/api/helpdesk/v1/...` through the gateway. Position/assignment
// mutations here are therefore direct-SQL TEST FIXTURE PLUMBING (same posture, and the same
// established precedent, as global-setup.ts's own company/member-row creation — see that file's
// header: "org has no gateway-mounted company/member-create route yet"), replicating EXACTLY the
// rows `internal/org.Store.CreatePosition/AssignNow/EndAssignment` would write (position row,
// position_assignment row, the `position:*#holder` tuple + its grant_ledger row) — never a
// shortcut that skips the tuple/ledger side effects those Go methods themselves are
// unit/integration-tested for (internal/org's TestPositionHolder_* and live tests). The
// AGENT-TIER BINDING step (`company_module:.../helpdesk#editor @
// position:<id>#holder`), by contrast, goes through the REAL gateway-mounted
// `POST /api/helpdesk/v1/companies/{companyId}/agents` — helpdesk IS reachable, so that part of
// the recipe exercises helpdesk's actual production code, same as timesheet's own
// create-project call exercises timesheet's real code.
//
// Video always-on (playwright.config.ts's `use.video`), retained under
// web/shell/e2e-artifacts/.

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

async function extractAccessToken(page: Page): Promise<string> {
  const accessToken = await page.evaluate(() => {
    const raw = sessionStorage.getItem("kiban.oidc.tokens");
    return raw ? (JSON.parse(raw) as { accessToken: string }).accessToken : null;
  });
  expect(accessToken).toBeTruthy();
  return accessToken as string;
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
  // Server-side, not just link-hidden — a direct URL must deny too (mirrors helpdesk.spec.ts's
  // own reporter-cannot-reach-all-tickets assertion).
  await page.goto(`/app/c/${companyId}/helpdesk/all`);
  await expect(page.getByTestId("helpdesk-all-tickets-denied")).toBeVisible({ timeout: 10_000 });
}

test.describe("position-based access recipe — create position, bind tier, handover, zero permission edits", () => {
  test("A holds the position and sees All Tickets; ending A + assigning B hands off access with no new grant/revoke call", async ({
    browser,
    request
  }, testInfo) => {
    const recordVideo = { dir: testInfo.outputDir };
    const env = loadTestEnv(repoRoot);

    const adminUsername = process.env.KIBAN_E2E_SUPERADMIN_USERNAME;
    const adminPassword = process.env.KIBAN_E2E_SUPERADMIN_PASSWORD;
    const holderAUsername = process.env.KIBAN_E2E_POSITION_HOLDER_A_USERNAME;
    const holderAPassword = process.env.KIBAN_E2E_POSITION_HOLDER_A_PASSWORD;
    const holderAId = process.env.KIBAN_E2E_POSITION_HOLDER_A_ID;
    const holderBUsername = process.env.KIBAN_E2E_POSITION_HOLDER_B_USERNAME;
    const holderBPassword = process.env.KIBAN_E2E_POSITION_HOLDER_B_PASSWORD;
    const holderBId = process.env.KIBAN_E2E_POSITION_HOLDER_B_ID;
    const companyId = process.env.KIBAN_E2E_COMPANY_ID;
    if (
      !adminUsername ||
      !adminPassword ||
      !holderAUsername ||
      !holderAPassword ||
      !holderAId ||
      !holderBUsername ||
      !holderBPassword ||
      !holderBId ||
      !companyId
    ) {
      throw new Error(
        "KIBAN_E2E_SUPERADMIN_*/KIBAN_E2E_POSITION_HOLDER_*/KIBAN_E2E_COMPANY_ID not set — global-setup.ts did not run"
      );
    }

    // --- Admin session: log in, create the position (direct-SQL fixture plumbing — org's own
    // mutation surface is unreachable, see this file's header), bind the helpdesk agent tier to
    // it via the REAL gateway-mounted API. ---
    const adminContext = await browser.newContext({ recordVideo });
    const adminPage = await adminContext.newPage();
    await login(adminPage, adminUsername, adminPassword);
    await openHelpdesk(adminPage, companyId);

    const runId = `${Date.now()}`;
    const positionCode = `E2EPOS${runId}`;
    const positionId = psqlScalar(
      env,
      `INSERT INTO org.position (company_id, code, title, org_unit_id)
       VALUES ('${companyId}', '${positionCode}', 'E2E Support Lead ${runId}', '${companyId}')
       RETURNING id`
    );
    expect(positionId).toBeTruthy();

    const adminAccessToken = await extractAccessToken(adminPage);
    const bindResp = await request.post(`/api/helpdesk/v1/companies/${companyId}/agents`, {
      headers: { authorization: `Bearer ${adminAccessToken}`, "content-type": "application/json" },
      data: { positionId }
    });
    expect(bindResp.ok()).toBe(true);
    const bound = ((await bindResp.json()) as { data: { bindingKind: string; positionId: string } }).data;
    expect(bound.bindingKind).toBe("position");
    expect(bound.positionId).toBe(positionId);

    // --- Assign A to the position (direct-SQL fixture plumbing, replicating
    // org.Store.AssignNow's exact writes: the assignment row + the position-holder tuple + its
    // grant_ledger row — see this file's header). ---
    const assignmentAId = psqlScalar(
      env,
      `INSERT INTO org.position_assignment (position_id, member_id, valid_from, valid_to)
       VALUES ('${positionId}', '${holderAId}', CURRENT_DATE, NULL) RETURNING id`
    );
    expect(assignmentAId).toBeTruthy();
    psqlExec(
      env,
      `INSERT INTO authz.tuple (object_type, object_id, relation, subject_type, subject_id, subject_relation)
       VALUES ('position', '${positionId}', 'holder', 'member', '${holderAId}', 'mapped_user')
       ON CONFLICT DO NOTHING`
    );
    psqlExec(
      env,
      `INSERT INTO authz.grant_ledger (actor, object_type, object_id, relation, subject_type, subject_id, subject_relation, op)
       VALUES ('e2e-fixture', 'position', '${positionId}', 'holder', 'member', '${holderAId}', 'mapped_user', 'grant')`
    );

    // --- Identity A: a fresh browser session sees All Tickets — real UI, real engine chain
    // (position#holder -> member#mapped_user -> user), zero direct grant to A's own user. ---
    const holderAContext = await browser.newContext({ recordVideo });
    const holderAPage = await holderAContext.newPage();
    await login(holderAPage, holderAUsername, holderAPassword);
    await openHelpdesk(holderAPage, companyId);
    await assertSeesAllTickets(holderAPage, companyId);

    // --- Same-day handover: end A's assignment + assign B — direct-SQL fixture plumbing
    // replicating org.Store.EndAssignment/AssignNow's exact writes. ZERO calls to helpdesk's
    // agent grant/revoke endpoints happen here — the property this whole recipe exists to
    // prove ("successor inherits the position's access"). ---
    psqlExec(env, `UPDATE org.position_assignment SET valid_to = CURRENT_DATE WHERE id = '${assignmentAId}'`);
    psqlExec(
      env,
      `DELETE FROM authz.tuple
       WHERE object_type = 'position' AND object_id = '${positionId}' AND relation = 'holder'
         AND subject_type = 'member' AND subject_id = '${holderAId}' AND subject_relation = 'mapped_user'`
    );
    psqlExec(
      env,
      `INSERT INTO authz.grant_ledger (actor, object_type, object_id, relation, subject_type, subject_id, subject_relation, op)
       VALUES ('e2e-fixture', 'position', '${positionId}', 'holder', 'member', '${holderAId}', 'mapped_user', 'revoke')`
    );
    const assignmentBId = psqlScalar(
      env,
      `INSERT INTO org.position_assignment (position_id, member_id, valid_from, valid_to)
       VALUES ('${positionId}', '${holderBId}', CURRENT_DATE, NULL) RETURNING id`
    );
    expect(assignmentBId).toBeTruthy();
    psqlExec(
      env,
      `INSERT INTO authz.tuple (object_type, object_id, relation, subject_type, subject_id, subject_relation)
       VALUES ('position', '${positionId}', 'holder', 'member', '${holderBId}', 'mapped_user')
       ON CONFLICT DO NOTHING`
    );
    psqlExec(
      env,
      `INSERT INTO authz.grant_ledger (actor, object_type, object_id, relation, subject_type, subject_id, subject_relation, op)
       VALUES ('e2e-fixture', 'position', '${positionId}', 'holder', 'member', '${holderBId}', 'mapped_user', 'grant')`
    );

    // --- A no longer sees All Tickets (same already-authenticated session, no new login). ---
    await assertDeniedAllTickets(holderAPage, companyId);

    // --- B, a FRESH session, now sees All Tickets — inherited with zero permission edits. ---
    const holderBContext = await browser.newContext({ recordVideo });
    const holderBPage = await holderBContext.newPage();
    await login(holderBPage, holderBUsername, holderBPassword);
    await openHelpdesk(holderBPage, companyId);
    await assertSeesAllTickets(holderBPage, companyId);

    // Log out all three sessions.
    for (const p of [adminPage, holderAPage, holderBPage]) {
      await p.goto("/app");
      await p.getByRole("button", { name: /log out/i }).click();
      await p.waitForURL((url) => !url.searchParams.has("code"), { timeout: 15_000 });
    }
  });
});
