// SPDX-License-Identifier: Apache-2.0

import { expect, test } from "@playwright/test";

// Full SDK flow: real browser login as the seeded superadmin (temp password cleared by
// global-setup.ts, e2e-login.sh's own workaround) -> OIDC/PKCE callback -> effective-access
// summary -> SDK capabilities fetch -> canI recipe -> grantObjectAccess/revokeObjectAccess recipe
// (superadmin bearer) -> superadmin module enable/disable -> logout. Video is always on for this
// run — must be top-level (Playwright forces a new worker for a per-file video override).
test.use({ video: "on" });

test.describe("login -> callback -> summary -> capabilities -> canI -> grantObjectAccess -> logout", () => {
  test("full flow against the live gateway", async ({ page }) => {
    const username = process.env.KIBAN_E2E_SUPERADMIN_USERNAME;
    const password = process.env.KIBAN_E2E_SUPERADMIN_PASSWORD;
    if (!username || !password) {
      throw new Error("KIBAN_E2E_SUPERADMIN_USERNAME/PASSWORD not set — global-setup.ts did not run");
    }

    await page.goto("/");
    await page.click("#login");

    // Keycloak's login page (proxied through the gateway's /auth/*). requiredActions were
    // cleared by global-setup.ts, so this is a plain username+password form, no interactive
    // UPDATE_PASSWORD step.
    await page.waitForURL(/\/auth\/realms\//);
    const usernameField = page.locator("#username");
    await usernameField.waitFor({ state: "visible", timeout: 15_000 });
    await usernameField.fill(username);
    await page.locator("#password").fill(password);
    await page.locator("#kc-login").click();

    // Back on the harness callback page, redirected by Keycloak.
    await page.waitForURL(/\/callback\.html/);

    const status = page.getByTestId("status");
    await expect(status).toHaveText("done", { timeout: 20_000 });
    await expect(status).not.toHaveAttribute("data-error", "true");

    // Effective-access summary — self-scoped (subjectId is whatever kcSub the
    // gateway injected from the bearer; no way for the harness to have supplied one itself).
    const summaryPayload = JSON.parse((await page.getByTestId("summary").textContent()) ?? "{}") as {
      apiVersion: number;
      subjectId: string;
      featureKeys: string[];
    };
    expect(summaryPayload.apiVersion).toBe(1);
    expect(summaryPayload.subjectId).toBeTruthy();
    // The seeded superadmin holds the superadmin feature key (re-derived by the real
    // Decider, internal/authz/summary.go's summaryFeatureKeys).
    expect(summaryPayload.featureKeys).toContain("auth.platform_administration.access");

    const capabilities = page.getByTestId("capabilities");
    const capabilitiesText = await capabilities.textContent();
    expect(capabilitiesText).toBeTruthy();
    const capabilitiesPayload = JSON.parse(capabilitiesText ?? "{}") as { count: number };
    expect(capabilitiesPayload.count).toBeGreaterThanOrEqual(0);

    // canI recipe (self-scoped effective-access/can) — the seeded superadmin holds
    // the superadmin role, so this must be allowed.
    const canIResult = JSON.parse((await page.getByTestId("can-i-result").textContent()) ?? "{}") as {
      allowed: boolean;
      reason: string;
    };
    expect(canIResult).toEqual({ allowed: true, reason: "ALLOWED" });

    // grantObjectAccess/revokeObjectAccess recipe (superadmin-guarded, company-bound
    // POST /api/auth/grants) — one tuple granted then revoked against a fixture document in the
    // fixture company global-setup.ts created (the harness anchors/un-anchors it around them).
    const grantResult = JSON.parse((await page.getByTestId("grant-result").textContent()) ?? "{}");
    expect(grantResult).toEqual({ status: "ok", count: 1 });

    const revokeResult = JSON.parse((await page.getByTestId("revoke-result").textContent()) ?? "{}");
    expect(revokeResult).toEqual({ status: "ok", count: 1 });

    const enableResult = JSON.parse((await page.getByTestId("enable-result").textContent()) ?? "{}");
    expect(enableResult).toEqual({ enabled: true });

    const disableResult = JSON.parse((await page.getByTestId("disable-result").textContent()) ?? "{}");
    expect(disableResult).toEqual({ enabled: false });

    const logoutButton = page.getByTestId("logout");
    await expect(logoutButton).toBeEnabled();
    await logoutButton.click();

    // RP-initiated logout redirects to Keycloak, then back to postLogoutRedirectUri (defaults
    // to redirectUri, i.e. this same callback page) — with no more code/state in the URL.
    await page.waitForURL((url) => !url.searchParams.has("code"), { timeout: 15_000 });
  });
});
