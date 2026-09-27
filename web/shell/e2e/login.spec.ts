// SPDX-License-Identifier: Apache-2.0

import { expect, test } from "@playwright/test";
import { expectNoCSPViolations, watchCSPViolations } from "./csp.js";

// Shell smoke flow: cold browse of the gateway-served shell ->
// real login as the seeded superadmin (global-setup.ts's throwaway-password workaround, same
// precedent as infra/e2e-login.sh) -> the sidebar nav renders -> a direct-URL module route with
// an unknown module key resolves to module-unavailable (the other three designed states —
// route-not-found/access-denied/module-error — need an installed+registered module to reach
// live and are covered by routes/states.test.tsx's unit table instead) -> logout. Video
// always-on (playwright.config.ts's `use.video`), retained under web/shell/e2e-artifacts/.
//
// The nav is never LITERALLY empty for this identity — nav/compose.ts appends a superadmin-only
// "Positions" entry (auth.platform_administration.access), and the seeded E2E superadmin holds
// that role — so this spec asserts that entry is present rather than the "sidebar-nav-empty"/
// "No modules installed" render (SidebarNav's branch for ZERO entries).
test.describe("login -> empty nav -> module-unavailable state -> logout", () => {
  test("full flow against the live gateway-served shell", async ({ page }) => {
    const cspViolations: string[] = [];
    watchCSPViolations(page, cspViolations);
    const username = process.env.KIBAN_E2E_SUPERADMIN_USERNAME;
    const password = process.env.KIBAN_E2E_SUPERADMIN_PASSWORD;
    if (!username || !password) {
      throw new Error("KIBAN_E2E_SUPERADMIN_USERNAME/PASSWORD not set — global-setup.ts did not run");
    }

    // Cold browse of the gateway-served root: unauthenticated -> redirected to /login.
    await page.goto("/");
    await expect(page.getByText("Sign in to Kiban")).toBeVisible();

    await page.getByRole("button", { name: "Log in" }).click();

    // Keycloak's login page (proxied through the gateway's own /auth/*). requiredActions
    // were cleared by global-setup.ts, so this is a plain username+password form.
    await page.waitForURL(/\/auth\/realms\//);
    const usernameField = page.locator("#username");
    await usernameField.waitFor({ state: "visible", timeout: 15_000 });
    await usernameField.fill(username);
    await page.locator("#password").fill(password);
    await page.locator("#kc-login").click();

    // Callback completes, then redirects to /app (no returnPath was carried on this run).
    await page.waitForURL(/\/app$/, { timeout: 20_000 });

    // The sidebar is NOT visually empty (the superadmin-only "Positions" entry), so this
    // asserts that entry and the absence of SidebarNav's zero-entries branch.
    await expect(page.getByTestId("sidebar-nav")).toBeVisible();
    await expect(page.getByRole("link", { name: "Positions" })).toBeVisible();
    await expect(page.getByTestId("sidebar-nav-empty")).toHaveCount(0);
    await expect(page.getByText("No modules installed")).toHaveCount(0);
    // The dashboard's "try this" walkthrough card renders unconditionally regardless of
    // catalog/nav state.
    await expect(page.getByTestId("dashboard-walkthrough-card")).toBeVisible();

    // Direct-URL module route: an unknown module key on the global host resolves to
    // module-unavailable — the resolver runs for real against the live capabilities/catalog
    // composition; nothing is installed under that key.
    await page.goto("/app/kiban-e2e-nonexistent-module/overview");
    await expect(page.getByRole("heading", { name: "Module unavailable" })).toBeVisible();
    await expect(page.getByText("kiban-e2e-nonexistent-module")).toBeVisible();

    // Company-scoped host, same proof.
    await page.goto("/app/c/kiban-e2e-nonexistent-company/kiban-e2e-nonexistent-module/overview");
    await expect(page.getByRole("heading", { name: "Module unavailable" })).toBeVisible();

    await page.goto("/app");
    const logoutButton = page.getByRole("button", { name: /log out/i });
    await expect(logoutButton).toBeEnabled();
    await logoutButton.click();

    // RP-initiated logout redirects through Keycloak, then back to postLogoutRedirectUri
    // (defaults to the SPA's own /callback) with no more code/state in the URL.
    await page.waitForURL((url) => !url.searchParams.has("code"), { timeout: 15_000 });

    // Session is really cleared: browsing back to / lands on the login page again, not /app.
    await page.goto("/");
    await expect(page.getByText("Sign in to Kiban")).toBeVisible();

    expectNoCSPViolations(cspViolations);
  });
});
