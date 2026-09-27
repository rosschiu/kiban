// SPDX-License-Identifier: Apache-2.0

import { expect, test, type Page } from "@playwright/test";

// Company switching as its own real-browser spec — the superadmin has an active
// membership in TWO fixture companies (KIBAN_E2E_COMPANY_ID / KIBAN_E2E_SECOND_COMPANY_ID,
// global-setup.ts). Proves (1) switching companies through the UI refetches module data (a
// document created in company A never leaks into company B's list, and vice versa — no stale
// cross-company data survives the switch), and (2) a STALE persisted `activeCompanyId`
// (localStorage `kiban.activeCompanyId`, web/sdk/src/auth/context.ts's SessionContext) for a
// company the caller no longer belongs to is reconciled to null rather than driving company-
// scoped fetches into guaranteed 403s forever (the reconciliation documented in
// web/shell/src/nav/nav-state.ts's own `useNavState` effect comment). Video always-on
// (playwright.config.ts's `use.video`), retained under web/shell/e2e-artifacts/.
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

test.describe("company switching — no stale cross-company data, stale-selection reconciliation", () => {
  test("switching companies refetches docs data (no leakage either direction)", async ({ browser }, testInfo) => {
    const username = process.env.KIBAN_E2E_SUPERADMIN_USERNAME;
    const password = process.env.KIBAN_E2E_SUPERADMIN_PASSWORD;
    const companyAId = process.env.KIBAN_E2E_COMPANY_ID;
    const companyBId = process.env.KIBAN_E2E_SECOND_COMPANY_ID;
    if (!username || !password || !companyAId || !companyBId) {
      throw new Error("KIBAN_E2E_SUPERADMIN_*/KIBAN_E2E_COMPANY_ID/KIBAN_E2E_SECOND_COMPANY_ID not set — global-setup.ts did not run");
    }

    const context = await browser.newContext({ recordVideo: { dir: testInfo.outputDir } });
    const page = await context.newPage();
    await login(page, username, password);

    const switcher = page.getByTestId("company-switcher-select");
    await expect(switcher).toBeVisible({ timeout: 15_000 });

    // --- Company A: create a document unique to this run. ---
    await switcher.selectOption(companyAId);
    await page.waitForURL(new RegExp(`/app/c/${companyAId}/`), { timeout: 10_000 }).catch(() => {
      // No company-scoped route active yet (e.g. still on /app) — navigate explicitly.
    });
    await page.goto(`/app/c/${companyAId}/docs`);
    await expect(page.getByTestId("docs-documents-page")).toBeVisible({ timeout: 15_000 });

    const runId = `${Date.now()}`;
    const docATitle = `Company A Doc ${runId}`;
    await page.getByTestId("docs-new-title").fill(docATitle);
    await page.getByTestId("docs-create-button").click();
    await expect(page.getByTestId("docs-owned-list")).toContainText(docATitle, { timeout: 10_000 });

    // --- Switch to Company B: the owned list must NOT show Company A's document — proves the
    // switch triggered a real refetch scoped to the new company, not a stale cached render. ---
    await switcher.selectOption(companyBId);
    await page.waitForURL(new RegExp(`/app/c/${companyBId}/docs$`), { timeout: 10_000 });
    await expect(page.getByTestId("docs-documents-page")).toBeVisible({ timeout: 15_000 });
    await expect(page.getByTestId("docs-owned-list").getByText(docATitle)).toHaveCount(0);

    const docBTitle = `Company B Doc ${runId}`;
    await page.getByTestId("docs-new-title").fill(docBTitle);
    await page.getByTestId("docs-create-button").click();
    await expect(page.getByTestId("docs-owned-list")).toContainText(docBTitle, { timeout: 10_000 });

    // --- Switch back to Company A: Company A's doc is back, Company B's doc is gone — proves
    // the refetch is genuinely per-company in BOTH directions, not a one-way cache bust. ---
    await switcher.selectOption(companyAId);
    await page.waitForURL(new RegExp(`/app/c/${companyAId}/docs$`), { timeout: 10_000 });
    await expect(page.getByTestId("docs-owned-list")).toContainText(docATitle, { timeout: 10_000 });
    await expect(page.getByTestId("docs-owned-list").getByText(docBTitle)).toHaveCount(0);

    await page.goto("/app");
    await page.getByRole("button", { name: /log out/i }).click();
    await page.waitForURL((url) => !url.searchParams.has("code"), { timeout: 15_000 });
  });

  test("a stale persisted activeCompanyId (company the caller no longer belongs to) is reconciled, not stuck", async ({
    browser
  }, testInfo) => {
    const username = process.env.KIBAN_E2E_SUPERADMIN_USERNAME;
    const password = process.env.KIBAN_E2E_SUPERADMIN_PASSWORD;
    const companyAId = process.env.KIBAN_E2E_COMPANY_ID;
    if (!username || !password || !companyAId) {
      throw new Error("KIBAN_E2E_SUPERADMIN_*/KIBAN_E2E_COMPANY_ID not set — global-setup.ts did not run");
    }

    const context = await browser.newContext({ recordVideo: { dir: testInfo.outputDir } });
    const page = await context.newPage();
    await login(page, username, password);

    const switcher = page.getByTestId("company-switcher-select");
    await expect(switcher).toBeVisible({ timeout: 15_000 });
    // Confirm the caller has at least one real membership to switch INTO after reconciliation.
    await expect(switcher.locator("option")).not.toHaveCount(0);

    // Plant a bogus activeCompanyId directly in the SDK's own persisted storage key
    // (web/sdk/src/auth/context.ts: `${prefix}activeCompanyId`, default prefix "kiban.") — a
    // company id the caller has no membership in, simulating a deleted company / rebuilt
    // database leaving a stale client-side selection behind.
    const bogusCompanyId = "00000000-0000-0000-0000-000000000000";
    await page.evaluate((id) => localStorage.setItem("kiban.activeCompanyId", id), bogusCompanyId);

    // Reload so the app boots with the stale selection already in place (rather than a
    // same-session setActiveCompanyId call, which would race the reconciliation effect
    // differently than a real "stale value present at load" scenario would).
    await page.reload();
    await expect(switcher).toBeVisible({ timeout: 15_000 });

    // Reconciliation (nav-state.ts's useNavState effect): once the real membership list comes
    // back and doesn't contain the stale id, setActiveCompanyId(null) fires — the persisted key
    // is cleared, never left pointing at a company the caller can't see.
    await expect
      .poll(() => page.evaluate(() => localStorage.getItem("kiban.activeCompanyId")), { timeout: 15_000 })
      .not.toBe(bogusCompanyId);

    // No broken/stuck UI: the switcher is still usable and switching to a real company still
    // works after the reconciliation (proves the app recovered into a normal state, not a
    // wedged one). Switching from the plain `/app` root (no company segment in the path yet)
    // only updates the session's activeCompanyId — getCompanySwitchDestination only rewrites the
    // URL on an already company-scoped route (company-switch-path.ts), so this asserts the
    // selection itself lands, then navigates explicitly to prove the company is now usable.
    await switcher.selectOption(companyAId);
    await expect(switcher).toHaveValue(companyAId);
    await page.goto(`/app/c/${companyAId}/docs`);
    await expect(page.getByTestId("docs-documents-page")).toBeVisible({ timeout: 15_000 });

    await page.goto("/app");
    await page.getByRole("button", { name: /log out/i }).click();
    await page.waitForURL((url) => !url.searchParams.has("code"), { timeout: 15_000 });
  });
});
