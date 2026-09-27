// SPDX-License-Identifier: Apache-2.0

import { expect, test, type Page } from "@playwright/test";

// The full timesheet journey through the REAL browser
// UI, modeled on notification.spec.ts's own structure. Unlike notification's single-actor
// journey, this one needs TWO distinct logged-in identities — the superadmin (acting as
// admin/approver, via the default company_module#admin grant global-setup.ts's fixture
// already gives it) and a second, plain Keycloak user (global-setup.ts's new
// `KIBAN_E2E_TIMESHEET_MEMBER_*` fixture) acting as the submitter — so this test drives TWO
// separate browser contexts (two independent sessions/cookie jars), same technique a real
// two-actor demo would use. Admin actions with no dedicated UI form (create project, assign
// approver) go through the API directly, extracting the browser session's own bearer token from
// sessionStorage — the SAME precedent notification.spec.ts's own "send via API directly" step
// established. Video always-on (playwright.config.ts's `use.video`), retained under
// web/shell/e2e-artifacts/.
//
// Row identification is done by data-testid (submission id), never by version number or
// weekStart text: submissions are scoped per (company, member, ISO week) — since this fixture
// member and company are REUSED across runs (global-setup.ts's convergent fixture, never torn
// down), a rerun within the same calendar week continues the SAME version chain rather than
// starting back at v1 (submitting again after an approval simply creates the next version in the
// same chain). Identifying "the row we just acted on" by its own unique submission id, captured
// from the DOM right after each action, keeps this spec state-independent across repeat runs
// (never assume a fixed version number or an empty accumulated list).

function isoMondayUTC(d: Date): Date {
  const day = d.getUTCDay() || 7;
  const monday = new Date(d);
  monday.setUTCDate(d.getUTCDate() - (day - 1));
  monday.setUTCHours(0, 0, 0, 0);
  return monday;
}

function toDateInput(d: Date): string {
  return d.toISOString().slice(0, 10);
}

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

// firstApprovalRowId returns the submission id of the FIRST (most recently submitted — the list
// is server-ordered by submitted_at DESC, store_submissions.go's ListSubmissions) row in the
// approvals list, after navigating fresh to the page (a `goto`, never a stale in-memory locator,
// so this always reflects the server's current state).
async function firstApprovalRowId(page: Page, companyId: string): Promise<string> {
  await page.goto(`/app/c/${companyId}/timesheet/approvals`);
  await expect(page.getByTestId("timesheet-approvals-list")).toBeVisible({ timeout: 10_000 });
  const row = page.locator('[data-testid^="approval-"]').first();
  await expect(row).toBeVisible({ timeout: 10_000 });
  const testId = await row.getAttribute("data-testid");
  if (!testId) throw new Error("timesheet.spec.ts: first approval row had no data-testid");
  return testId.replace("approval-", "");
}

test.describe("full timesheet journey — admin + member, two real browser sessions", () => {
  test("admin assigns approver -> member enters+submits -> approver rejects -> member resubmits -> approver approves", async ({
    browser,
    request
  }, testInfo) => {
    // playwright.config.ts's `use.video: "on"` only auto-applies to the fixture-provided
    // default context/page (the `page` fixture notification.spec.ts/login.spec.ts use) — a
    // manually created `browser.newContext()` (needed here for TWO independent logged-in
    // sessions) does NOT inherit it automatically and records no video unless told to. Passing
    // the same `dir: testInfo.outputDir` both suites' default context resolves to keeps this
    // spec's videos retained under web/shell/e2e-artifacts/ exactly like the other two specs'.
    const recordVideo = { dir: testInfo.outputDir };

    const adminUsername = process.env.KIBAN_E2E_SUPERADMIN_USERNAME;
    const adminPassword = process.env.KIBAN_E2E_SUPERADMIN_PASSWORD;
    const memberUsername = process.env.KIBAN_E2E_TIMESHEET_MEMBER_USERNAME;
    const memberPassword = process.env.KIBAN_E2E_TIMESHEET_MEMBER_PASSWORD;
    const memberId = process.env.KIBAN_E2E_TIMESHEET_MEMBER_ID;
    const approverMemberId = process.env.KIBAN_E2E_SUPERADMIN_MEMBER_ID;
    const companyId = process.env.KIBAN_E2E_COMPANY_ID;
    if (!adminUsername || !adminPassword || !memberUsername || !memberPassword || !memberId || !approverMemberId || !companyId) {
      throw new Error(
        "KIBAN_E2E_SUPERADMIN_*/KIBAN_E2E_TIMESHEET_MEMBER_*/KIBAN_E2E_COMPANY_ID not set — global-setup.ts did not run"
      );
    }

    // --- Admin session: log in, create a project, assign the member's approver (both via API
    // directly — no dedicated admin-console UI form exists in this minimal module's frontend). ---
    const adminContext = await browser.newContext({ recordVideo });
    const adminPage = await adminContext.newPage();
    await login(adminPage, adminUsername, adminPassword);
    await expect(adminPage.getByTestId("company-switcher-select")).toBeVisible({ timeout: 15_000 });
    await adminPage.getByTestId("company-switcher-select").selectOption(companyId);
    // Nav shows Timesheet (company-scoped module, real registry entry — same proof shape as
    // notification.spec.ts's own nav assertion).
    await expect(adminPage.getByRole("link", { name: /Timesheet/ })).toBeVisible({ timeout: 15_000 });

    const adminAccessToken = await extractAccessToken(adminPage);
    const runId = `${Date.now()}`;
    const projectCode = `E2ETS${runId}`;

    const createProjectResp = await request.post(`/api/timesheet/v1/companies/${companyId}/projects`, {
      headers: { authorization: `Bearer ${adminAccessToken}`, "content-type": "application/json" },
      data: { code: projectCode, name: `E2E Timesheet Project ${runId}` }
    });
    expect(createProjectResp.ok()).toBe(true);
    const project = ((await createProjectResp.json()) as { data: { id: string } }).data;

    const assignResp = await request.post(`/api/timesheet/v1/companies/${companyId}/approvers`, {
      headers: { authorization: `Bearer ${adminAccessToken}`, "content-type": "application/json" },
      data: { memberId, approverMemberId }
    });
    expect(assignResp.ok()).toBe(true);

    // --- Member session: a SEPARATE browser context/login — enters hours through the weekly
    // grid and submits. ---
    const memberContext = await browser.newContext({ recordVideo });
    const memberPage = await memberContext.newPage();
    await login(memberPage, memberUsername, memberPassword);
    await expect(memberPage.getByTestId("company-switcher-select")).toBeVisible({ timeout: 15_000 });
    await memberPage.getByTestId("company-switcher-select").selectOption(companyId);

    const timesheetLink = memberPage.getByRole("link", { name: /Timesheet/ });
    await expect(timesheetLink).toBeVisible({ timeout: 15_000 });
    await timesheetLink.click();
    await memberPage.waitForURL(new RegExp(`/app/c/${companyId}/timesheet$`));
    await expect(memberPage.getByTestId("timesheet-weekly-grid")).toBeVisible({ timeout: 10_000 });

    const weekStart = toDateInput(isoMondayUTC(new Date()));
    const mondayInputTestId = `entry-${project.id}-${weekStart}`;
    const mondayInput = memberPage.getByTestId(mondayInputTestId);
    await expect(mondayInput).toBeVisible({ timeout: 10_000 });
    await mondayInput.fill("8");
    await mondayInput.blur();

    const submitButton = memberPage.getByTestId("timesheet-submit-week");
    await expect(submitButton).toBeEnabled({ timeout: 10_000 });
    await submitButton.click();
    await expect(memberPage.getByText("Week submitted.")).toBeVisible({ timeout: 10_000 });

    // --- Approver (admin's session, same person the fixture assigned) rejects with a reason. ---
    const v1Id = await firstApprovalRowId(adminPage, companyId);
    const v1Row = adminPage.getByTestId(`approval-${v1Id}`);
    adminPage.once("dialog", (dialog) => void dialog.accept("Please re-check the hours."));
    await v1Row.getByTestId(`reject-${v1Id}`).click();
    await expect(v1Row.getByText("rejected")).toBeVisible({ timeout: 10_000 });

    // --- Member edits (entries reverted to draft by the reject) and resubmits -> the next
    // version in the chain, superseding v1Id. ---
    await memberPage.goto(`/app/c/${companyId}/timesheet`);
    await expect(memberPage.getByTestId("timesheet-weekly-grid")).toBeVisible({ timeout: 10_000 });
    const mondayInputAgain = memberPage.getByTestId(mondayInputTestId);
    await expect(mondayInputAgain).toBeEnabled({ timeout: 10_000 });
    await mondayInputAgain.fill("7.5");
    await mondayInputAgain.blur();
    const resubmitButton = memberPage.getByTestId("timesheet-submit-week");
    await expect(resubmitButton).toBeEnabled({ timeout: 10_000 });
    await resubmitButton.click();
    await expect(memberPage.getByText("Week submitted.")).toBeVisible({ timeout: 10_000 });

    // Member's own submissions list renders (view=mine) — at least the rejected + new-current
    // rows are present; a superseded row shows the "(superseded)" marker.
    await memberPage.goto(`/app/c/${companyId}/timesheet/submissions`);
    await expect(memberPage.getByTestId("timesheet-submissions-list")).toBeVisible({ timeout: 10_000 });
    await expect(memberPage.getByText("(superseded)").first()).toBeVisible({ timeout: 10_000 });

    // --- Approver approves the new current version. The freshly-submitted row's id is
    // GUARANTEED distinct from v1Id (ListSubmissions orders submitted_at DESC and this is a
    // brand-new INSERT — store_submissions.go's SubmitWeek). ---
    const v2Id = await firstApprovalRowId(adminPage, companyId);
    expect(v2Id).not.toBe(v1Id);
    const v2Row = adminPage.getByTestId(`approval-${v2Id}`);
    await expect(v2Row.getByTestId(`approve-${v2Id}`)).toBeEnabled({ timeout: 10_000 });
    await v2Row.getByTestId(`approve-${v2Id}`).click();
    await expect(v2Row.getByText("approved")).toBeVisible({ timeout: 10_000 });

    // The superseded v1Id can never be approved — even by directly hitting the API with the
    // approver's own bearer (proves the SERVER rule, not just that the UI hides the button).
    const approverAccessToken = await extractAccessToken(adminPage);
    const reapproveV1 = await request.post(`/api/timesheet/v1/companies/${companyId}/submissions/${v1Id}/approve`, {
      headers: { authorization: `Bearer ${approverAccessToken}` }
    });
    expect(reapproveV1.status()).toBe(422);

    // Log out both sessions.
    await adminPage.goto("/app");
    await adminPage.getByRole("button", { name: /log out/i }).click();
    await adminPage.waitForURL((url) => !url.searchParams.has("code"), { timeout: 15_000 });
    await memberPage.goto("/app");
    await memberPage.getByRole("button", { name: /log out/i }).click();
    await memberPage.waitForURL((url) => !url.searchParams.has("code"), { timeout: 15_000 });
  });
});
