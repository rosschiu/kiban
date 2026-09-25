// SPDX-License-Identifier: Apache-2.0

import { expect, test } from "@playwright/test";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { loadTestEnv, psqlScalar } from "../../e2e-shared/env.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, "..", "..", "..");

// The first-login proof: a user that exists ONLY in Keycloak (global-setup.ts
// creates it fresh every run — no identity row, no membership) logs in and gets an honest first
// screen. The gateway provisions the identity row on the first authenticated request
// (internal/gateway/provision.go) — asserted here by reading the row back by kc_sub AFTER the
// login and never inserting it — and the shell renders "No company membership yet" (not "No
// modules installed"). A company administrator then adds the member (org has no gateway-mounted
// member-create route, so the same direct-SQL member fixture every other spec uses stands in for
// that admin action); a reload shows the company and its modules.
test.describe("first login: Keycloak user only -> no membership -> member added -> modules", () => {
  test("provisions on first request and renders the membership empty state until a member row exists", async ({ page }) => {
    const username = process.env.KIBAN_E2E_FIRST_LOGIN_USERNAME;
    const password = process.env.KIBAN_E2E_FIRST_LOGIN_PASSWORD;
    const kcSub = process.env.KIBAN_E2E_FIRST_LOGIN_KCSUB;
    const companyId = process.env.KIBAN_E2E_COMPANY_ID;
    if (!username || !password || !kcSub || !companyId) {
      throw new Error("KIBAN_E2E_FIRST_LOGIN_* / KIBAN_E2E_COMPANY_ID not set — global-setup.ts did not run");
    }
    const env = loadTestEnv(repoRoot);

    // Nothing but the Keycloak user exists yet.
    expect(psqlScalar(env, `SELECT count(*) FROM identity.user_account WHERE kc_sub = '${kcSub}'`)).toBe("0");

    await page.goto("/");
    await page.getByRole("button", { name: "Log in" }).click();
    await page.waitForURL(/\/auth\/realms\//);
    const usernameField = page.locator("#username");
    await usernameField.waitFor({ state: "visible", timeout: 15_000 });
    await usernameField.fill(username);
    await page.locator("#password").fill(password);
    await page.locator("#kc-login").click();
    await page.waitForURL(/\/app$/, { timeout: 20_000 });

    // The honest first screen: no membership, no company switcher, and NOT "No modules installed".
    await expect(page.getByTestId("sidebar-nav-no-membership")).toBeVisible({ timeout: 15_000 });
    await expect(page.getByText("No company membership yet")).toBeVisible();
    await expect(page.getByText("Ask a company administrator to add you.")).toBeVisible();
    await expect(page.getByTestId("sidebar-nav-empty")).toHaveCount(0);
    await expect(page.getByTestId("company-switcher")).toHaveCount(0);

    // The gateway provisioned the identity row on the session's first authenticated request.
    const userId = psqlScalar(env, `SELECT id FROM identity.user_account WHERE kc_sub = '${kcSub}'`);
    expect(userId).not.toBe("");

    // A company administrator adds the member.
    psqlScalar(
      env,
      `INSERT INTO org.member (company_id, code, display_name, user_id, is_active)
       VALUES ('${companyId}', 'E2EFIRSTLOGIN', 'E2E First Login', '${userId}', true)
       ON CONFLICT (company_id, code) DO UPDATE SET user_id = EXCLUDED.user_id, is_active = true
       RETURNING id`
    );

    await page.reload();
    await expect(page.getByTestId("company-switcher-select")).toBeVisible({ timeout: 15_000 });
    await page.getByTestId("company-switcher-select").selectOption(companyId);
    await expect(page.getByTestId("sidebar-nav")).toBeVisible({ timeout: 15_000 });
    await expect(page.getByRole("link", { name: /Docs/ })).toBeVisible();
    await expect(page.getByTestId("sidebar-nav-no-membership")).toHaveCount(0);
  });
});
