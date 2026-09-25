// SPDX-License-Identifier: Apache-2.0

import { expect, test } from "@playwright/test";

// Notification flow: login -> nav shows Notification -> create + subscribe to a
// channel (through the module's own Channels UI) -> send a message THROUGH THE API DIRECTLY
// (a companion Playwright APIRequestContext call using the
// browser session's own bearer token, extracted from sessionStorage the same way
// auth/session.ts persists it) -> the sidebar's unread badge increments -> the Inbox page
// renders the message, unread -> mark it read through the UI -> the unread marker clears.
// Video always-on (playwright.config.ts's `use.video`), retained under
// web/shell/e2e-artifacts/.
test.describe("login -> notification nav -> send via API -> badge -> inbox -> mark read", () => {
  test("full journey against the live gateway-served shell", async ({ page, request }) => {
    const username = process.env.KIBAN_E2E_SUPERADMIN_USERNAME;
    const password = process.env.KIBAN_E2E_SUPERADMIN_PASSWORD;
    const companyId = process.env.KIBAN_E2E_COMPANY_ID;
    if (!username || !password || !companyId) {
      throw new Error("KIBAN_E2E_SUPERADMIN_USERNAME/PASSWORD/KIBAN_E2E_COMPANY_ID not set — global-setup.ts did not run");
    }

    await page.goto("/");
    await page.getByRole("button", { name: "Log in" }).click();
    await page.waitForURL(/\/auth\/realms\//);
    const usernameField = page.locator("#username");
    await usernameField.waitFor({ state: "visible", timeout: 15_000 });
    await usernameField.fill(username);
    await page.locator("#password").fill(password);
    await page.locator("#kc-login").click();
    await page.waitForURL(/\/app$/, { timeout: 20_000 });

    // Notification is company-scoped (module.manifest.json scopeType "company") — its nav entry
    // only appears once a company is the ACTIVE one (compose.ts's computeNavEntries: "a
    // company-scoped module with no activeCompanyId selected yet is omitted"). The company
    // switcher only renders once org.meCompanies resolves (global-setup.ts's fixture member).
    await expect(page.getByTestId("company-switcher-select")).toBeVisible({ timeout: 15_000 });
    await page.getByTestId("company-switcher-select").selectOption(companyId);

    // Nav shows Notification (company-scoped module, real registry entry, real catalog/
    // capability composition).
    const notificationLink = page.getByRole("link", { name: /Notification/ });
    await expect(notificationLink).toBeVisible({ timeout: 15_000 });
    await notificationLink.click();
    await page.waitForURL(new RegExp(`/app/c/${companyId}/notification$`));
    await expect(page.getByTestId("notification-inbox-page")).toBeVisible();

    // Channels: create + subscribe self through the module's own UI.
    await page.getByRole("link", { name: "Manage channels" }).click();
    await page.waitForURL(new RegExp(`/app/c/${companyId}/notification/channels$`));
    // The label carries the same per-run-unique suffix the key does: this suite converges
    // rather than tearing down prior runs' rows, so a fixed label would accumulate one row per
    // run and the hasText locator below would match MULTIPLE rows, which Playwright's
    // strict-mode auto-wait treats as a failure.
    const channelKey = `e2e-${Date.now()}`;
    const channelLabel = `E2E Channel ${channelKey}`;
    await page.getByLabel("Key").fill(channelKey);
    await page.getByLabel("Label").fill(channelLabel);
    await page.getByRole("button", { name: "Create" }).click();

    const channelItem = page.locator('[data-testid^="notification-channel-"]').filter({ hasText: channelLabel });
    await expect(channelItem).toBeVisible({ timeout: 10_000 });
    const channelTestId = await channelItem.getAttribute("data-testid");
    const channelId = channelTestId!.replace("notification-channel-", "");
    await channelItem.getByRole("button", { name: "Subscribe" }).click();
    await expect(channelItem.getByRole("button", { name: "Subscribed" })).toBeDisabled();

    // Send via the API directly, reusing the real browser session's own
    // bearer token (sessionStorage — auth/session.ts's TOKENS_KEY) rather than a separate
    // service-account login: this is the SAME session already proven through the UI above.
    const accessToken = await page.evaluate(() => {
      const raw = sessionStorage.getItem("kiban.oidc.tokens");
      return raw ? (JSON.parse(raw) as { accessToken: string }).accessToken : null;
    });
    expect(accessToken).toBeTruthy();

    // Same per-run-unique suffix on the subject: the Inbox lists every message across every
    // channel this company's superadmin has EVER subscribed to (inbox-page.tsx's listInbox has no
    // per-run scoping), and convergence never unsubscribes/deletes prior runs' channels. A fixed
    // subject line would accumulate one matching, already-read <li> per prior run and the
    // `messageCard` locator below would then match multiple rows on any rerun.
    const messageSubject = `Hello from the e2e ${channelKey}`;
    const sendResponse = await request.post(`/api/notification/v1/companies/${companyId}/messages`, {
      headers: { authorization: `Bearer ${accessToken}`, "content-type": "application/json", "Idempotency-Key": `e2e-${channelId}` },
      data: { channelId, subjectLine: messageSubject, body: "Sent via the API directly." },
    });
    expect(sendResponse.ok()).toBe(true);

    // Badge increments (nav-badges.ts polls every 4s — wait it out rather than reload, proving
    // the live poll loop itself, not just a fresh-mount fetch).
    await expect(page.getByTestId("nav-badge-notification")).toBeVisible({ timeout: 10_000 });
    await expect(page.getByTestId("nav-badge-notification")).toHaveText("1");

    // Inbox renders the message, unread.
    await page.getByRole("link", { name: /Notification/ }).click();
    await page.waitForURL(new RegExp(`/app/c/${companyId}/notification$`));
    await expect(page.getByText(messageSubject)).toBeVisible();
    const messageCard = page.locator("li").filter({ hasText: messageSubject });
    await expect(messageCard.getByText("Unread")).toBeVisible();

    // Mark read through the UI; the unread marker clears and the nav badge drops back to zero.
    await messageCard.getByRole("button", { name: "Mark read" }).click();
    await expect(messageCard.getByText("Unread")).toHaveCount(0);
    await expect(page.getByTestId("nav-badge-notification")).toHaveCount(0, { timeout: 10_000 });

    await page.goto("/app");
    await page.getByRole("button", { name: /log out/i }).click();
    await page.waitForURL((url) => !url.searchParams.has("code"), { timeout: 15_000 });
  });
});
