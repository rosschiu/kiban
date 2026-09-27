// SPDX-License-Identifier: Apache-2.0

import { expect, test, type Page } from "@playwright/test";

// A reusable per-tier allow/deny contrast sweep — the SAME set of pages/actions
// driven by four distinct logged-in identities sharing one company (KIBAN_E2E_COMPANY_ID):
// superadmin (platform), company-admin ("helpdesk admin (company_module#admin)" — company_module
// #admin for helpdesk AND docs, but NOT a platform superadmin), agent (helpdesk's own
// company_module#editor tier; a plain member for docs — docs has no equivalent agent tier), and
// plain member (no relation grants beyond the org.member row). Asserts nav entries present/
// absent, admin pages 403/denied vs rendered, and module actions available vs hidden, across TWO
// modules (helpdesk + docs). Fixtures: global-setup.ts's tier-contrast
// block. Video always-on (playwright.config.ts's `use.video`), retained under
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

async function logout(page: Page): Promise<void> {
  await page.goto("/app");
  await page.getByRole("button", { name: /log out/i }).click();
  await page.waitForURL((url) => !url.searchParams.has("code"), { timeout: 15_000 });
}

interface Tier {
  name: string;
  username: string | undefined;
  password: string | undefined;
  /** helpdesk-my-tier's own rendered value (helpdesk's tier.ts: member | agent | admin). */
  helpdeskTier: "member" | "agent" | "admin";
  /** Whether this identity holds company_module#admin for docs too (docs.manage). */
  docsAdmin: boolean;
}

test.describe("per-tier allow/deny contrast — helpdesk + docs", () => {
  const tiers: Tier[] = [
    {
      name: "superadmin",
      username: process.env.KIBAN_E2E_SUPERADMIN_USERNAME,
      password: process.env.KIBAN_E2E_SUPERADMIN_PASSWORD,
      helpdeskTier: "admin",
      docsAdmin: true
    },
    {
      name: "company-admin",
      username: process.env.KIBAN_E2E_TIER_ADMIN_USERNAME,
      password: process.env.KIBAN_E2E_TIER_ADMIN_PASSWORD,
      helpdeskTier: "admin",
      docsAdmin: true
    },
    {
      name: "agent",
      username: process.env.KIBAN_E2E_TIER_AGENT_USERNAME,
      password: process.env.KIBAN_E2E_TIER_AGENT_PASSWORD,
      helpdeskTier: "agent",
      docsAdmin: false
    },
    {
      name: "member",
      username: process.env.KIBAN_E2E_TIER_MEMBER_USERNAME,
      password: process.env.KIBAN_E2E_TIER_MEMBER_PASSWORD,
      helpdeskTier: "member",
      docsAdmin: false
    }
  ];

  const companyId = process.env.KIBAN_E2E_COMPANY_ID;

  for (const tier of tiers) {
    test(`${tier.name}: nav + helpdesk sub-nav + agents-admin + docs-admin contrast`, async ({ browser }, testInfo) => {
      if (!tier.username || !tier.password || !companyId) {
        throw new Error(`KIBAN_E2E_TIER_*/KIBAN_E2E_COMPANY_ID not set for tier '${tier.name}' — global-setup.ts did not run`);
      }

      const context = await browser.newContext({ recordVideo: { dir: testInfo.outputDir } });
      const page = await context.newPage();
      await login(page, tier.username, tier.password);

      const switcher = page.getByTestId("company-switcher-select");
      await expect(switcher).toBeVisible({ timeout: 15_000 });
      await switcher.selectOption(companyId);

      // --- Nav entries: EVERY tier is an active company member, so both module links are
      // present for all four (helpdesk.tickets.create/docs.create are membership-gated only,
      // isSidebarEntry: true, no relation leg — same for every tier here). This is the "present"
      // half of the contrast; the per-tier DENY is inside each module (sub-nav, admin pages),
      // not at the top-level nav. ---
      await expect(page.getByRole("link", { name: /Helpdesk/ })).toBeVisible({ timeout: 15_000 });
      await expect(page.getByRole("link", { name: /Docs/ })).toBeVisible();

      // --- Helpdesk sub-nav tier contrast. ---
      await page.goto(`/app/c/${companyId}/helpdesk`);
      await expect(page.getByTestId("helpdesk-sub-nav")).toBeVisible({ timeout: 15_000 });
      await expect(page.getByTestId("helpdesk-my-tier")).toHaveText(tier.helpdeskTier);

      const allTicketsLink = page.getByTestId("helpdesk-nav-all-tickets");
      const agentsLink = page.getByTestId("helpdesk-nav-agents");
      if (tier.helpdeskTier === "member") {
        await expect(allTicketsLink).toHaveCount(0);
        await expect(agentsLink).toHaveCount(0);
      } else if (tier.helpdeskTier === "agent") {
        await expect(allTicketsLink).toBeVisible();
        await expect(agentsLink).toHaveCount(0);
      } else {
        await expect(allTicketsLink).toBeVisible();
        await expect(agentsLink).toBeVisible();
      }

      // --- Helpdesk agents-admin page: direct navigation (never relying on the nav link, which
      // is itself absent for non-admins — a plain member/agent typing the URL must still get the
      // page's own client-side denied state, not a working admin surface). ---
      await page.goto(`/app/c/${companyId}/helpdesk/agents`);
      await expect(page.getByTestId("helpdesk-agents-page")).toBeVisible({ timeout: 15_000 });
      if (tier.helpdeskTier === "admin") {
        await expect(page.getByTestId("helpdesk-agents-denied")).toHaveCount(0);
        await expect(page.getByTestId("helpdesk-agent-member-search")).toBeVisible();
      } else {
        await expect(page.getByTestId("helpdesk-agents-denied")).toBeVisible();
      }

      // --- Docs admin page: direct navigation. Unlike helpdesk's agents-admin page (client-side
      // tier check -> an explicit denied testid), docs' admin ROUTE itself is only gated on
      // generic company membership (frontend.manifest.json's own featureKey comment: no
      // fragment-install path exists yet to load docs.manage into the frontend route gate) — the
      // page always renders, but its OWN API call (GET .../audit, server-side docs.manage
      // authz) fails for a non-admin, surfacing as an inline error message rather than a
      // dedicated "denied" element. Recorded here as a real, deliberate asymmetry between the
      // two modules' admin-page access patterns, not a bug. ---
      await page.goto(`/app/c/${companyId}/docs/admin`);
      await expect(page.getByTestId("docs-admin-page")).toBeVisible({ timeout: 15_000 });
      if (tier.docsAdmin) {
        await expect(page.getByText(/requires docs\.manage/)).toHaveCount(0);
      } else {
        await expect(page.getByText(/requires docs\.manage/)).toBeVisible({ timeout: 10_000 });
      }

      await logout(page);
    });
  }
});
