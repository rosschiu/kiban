// SPDX-License-Identifier: Apache-2.0

import { expect, test, type Page } from "@playwright/test";

// The full docs sharing journey through the REAL browser UI, modeled on
// timesheet.spec.ts's two-context structure (this module needs it too: create+share as the
// owner, then read/edit/lose-access as a SECOND, distinct logged-in member — global-setup.ts's
// `KIBAN_E2E_DOCS_MEMBER_*` fixture). Drives two separate browser contexts (two independent
// sessions/cookie jars). Video always-on (playwright.config.ts's `use.video`), retained under
// web/shell/e2e-artifacts/.
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

test.describe("full DocShare sharing journey — owner + second member, two real browser sessions", () => {
  test("create -> share viewer -> second identity reads but cannot edit -> upgrade to editor -> edits -> revoke -> second identity loses access -> audit trail shows it all", async ({
    browser,
  }, testInfo) => {
    const recordVideo = { dir: testInfo.outputDir };

    const ownerUsername = process.env.KIBAN_E2E_SUPERADMIN_USERNAME;
    const ownerPassword = process.env.KIBAN_E2E_SUPERADMIN_PASSWORD;
    const memberUsername = process.env.KIBAN_E2E_DOCS_MEMBER_USERNAME;
    const memberPassword = process.env.KIBAN_E2E_DOCS_MEMBER_PASSWORD;
    const companyId = process.env.KIBAN_E2E_COMPANY_ID;
    if (!ownerUsername || !ownerPassword || !memberUsername || !memberPassword || !companyId) {
      throw new Error("KIBAN_E2E_SUPERADMIN_*/KIBAN_E2E_DOCS_MEMBER_*/KIBAN_E2E_COMPANY_ID not set — global-setup.ts did not run");
    }

    // --- Owner session: log in, navigate to Docs, create a document. ---
    const ownerContext = await browser.newContext({ recordVideo });
    const ownerPage = await ownerContext.newPage();
    await login(ownerPage, ownerUsername, ownerPassword);
    await expect(ownerPage.getByTestId("company-switcher-select")).toBeVisible({ timeout: 15_000 });
    await ownerPage.getByTestId("company-switcher-select").selectOption(companyId);

    const docsLink = ownerPage.getByRole("link", { name: /Docs/ });
    await expect(docsLink).toBeVisible({ timeout: 15_000 });
    await docsLink.click();
    await ownerPage.waitForURL(new RegExp(`/app/c/${companyId}/docs$`));
    await expect(ownerPage.getByTestId("docs-documents-page")).toBeVisible();

    const runId = `${Date.now()}`;
    const docTitle = `E2E Runbook ${runId}`;
    await ownerPage.getByTestId("docs-new-title").fill(docTitle);
    await ownerPage.getByTestId("docs-create-button").click();

    const docItem = ownerPage.locator('[data-testid^="docs-document-"]').filter({ hasText: docTitle });
    await expect(docItem).toBeVisible({ timeout: 10_000 });
    const docTestId = await docItem.getAttribute("data-testid");
    const docId = docTestId!.replace("docs-document-", "");
    await docItem.click();
    await ownerPage.waitForURL(new RegExp(`/app/c/${companyId}/docs/documents/${docId}$`));
    await expect(ownerPage.getByTestId("docs-document-page")).toBeVisible();

    // --- Share as viewer, THROUGH THE UI's share dialog (the demo surface). ---
    await ownerPage.getByTestId("docs-share-button").click();
    await expect(ownerPage.getByTestId("docs-share-sheet")).toBeVisible();
    await ownerPage.getByTestId("docs-member-search").fill("E2E Docs Member");
    const memberResultShareButton = ownerPage.getByTestId(/^docs-share-with-/);
    await expect(memberResultShareButton).toBeVisible({ timeout: 10_000 });
    await memberResultShareButton.click();
    await expect(ownerPage.locator('[data-testid^="docs-share-row-"]')).toBeVisible({ timeout: 10_000 });

    // --- Second identity (a SEPARATE browser context/login) can now read, but not edit. ---
    const memberContext = await browser.newContext({ recordVideo });
    const memberPage = await memberContext.newPage();
    await login(memberPage, memberUsername, memberPassword);
    await expect(memberPage.getByTestId("company-switcher-select")).toBeVisible({ timeout: 15_000 });
    await memberPage.getByTestId("company-switcher-select").selectOption(companyId);

    await memberPage.goto(`/app/c/${companyId}/docs/documents/${docId}`);
    await expect(memberPage.getByTestId("docs-document-page")).toBeVisible({ timeout: 10_000 });
    await expect(memberPage.getByTestId("docs-title-input")).toHaveCount(0); // read-only: no edit form
    await expect(memberPage.getByTestId("docs-share-button")).toHaveCount(0); // viewer, not owner

    // --- Owner upgrades the member to editor — the share sheet is still open from the first
    // grant above (this IS the "immediately visible state changes" demo surface: no reopen, no
    // page reload needed to act again). ---
    await ownerPage.locator('label:has-text("Editor") input[type="radio"]').check();
    await ownerPage.getByTestId("docs-member-search").fill("E2E Docs Member");
    const upgradeShareButton = ownerPage.getByTestId(/^docs-share-with-/);
    await expect(upgradeShareButton).toBeVisible({ timeout: 10_000 });
    await upgradeShareButton.click();
    await expect(ownerPage.locator('[data-testid^="docs-share-row-"]')).toContainText("editor", { timeout: 10_000 });

    // --- Second identity can now edit and save. ---
    await memberPage.goto(`/app/c/${companyId}/docs/documents/${docId}`);
    await expect(memberPage.getByTestId("docs-title-input")).toBeVisible({ timeout: 10_000 });
    const bodyInput = memberPage.getByTestId("docs-body-input");
    await bodyInput.fill("# Edited by the second identity\n\nThis proves editor access.");
    await memberPage.getByTestId("docs-save-button").click();
    await expect(memberPage.getByTestId("docs-body-preview")).toContainText("Edited by the second identity", { timeout: 10_000 });

    // --- Owner revokes the member's access entirely. ---
    await ownerPage.reload();
    await ownerPage.getByTestId("docs-share-button").click();
    const revokeButton = ownerPage.locator('[data-testid^="docs-revoke-"]');
    await expect(revokeButton).toBeVisible({ timeout: 10_000 });
    await revokeButton.click();
    await expect(ownerPage.locator('[data-testid^="docs-share-row-"]')).toHaveCount(0, { timeout: 10_000 });

    // --- Second identity loses access — the 403 UI state, not a stale cached page. ---
    await memberPage.goto(`/app/c/${companyId}/docs/documents/${docId}`);
    await expect(memberPage.getByTestId("docs-document-denied")).toBeVisible({ timeout: 10_000 });

    // --- The document's own audit trail shows every step. ---
    await ownerPage.reload();
    const auditList = ownerPage.getByTestId("docs-audit-list");
    await expect(auditList).toBeVisible({ timeout: 10_000 });
    await expect(auditList).toContainText("created this document");
    await expect(auditList).toContainText("shared with a member as viewer");
    await expect(auditList).toContainText("shared with a member as editor");
    await expect(auditList).toContainText("edited this document");
    await expect(auditList).toContainText("revoked a member's access");

    // Log out both sessions.
    await ownerPage.goto("/app");
    await ownerPage.getByRole("button", { name: /log out/i }).click();
    await ownerPage.waitForURL((url) => !url.searchParams.has("code"), { timeout: 15_000 });
    await memberPage.goto("/app");
    await memberPage.getByRole("button", { name: /log out/i }).click();
    await memberPage.waitForURL((url) => !url.searchParams.has("code"), { timeout: 15_000 });
  });
});
