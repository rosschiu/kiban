// SPDX-License-Identifier: Apache-2.0

import { expect, test } from "@playwright/test";
import { loadTestEnv } from "../../e2e-shared/env.js";
import { fileURLToPath } from "node:url";
import path from "node:path";

// Session expiry + refresh mid-journey. Sets a SHORT `access.token.lifespan`
// per-client override on `kiban-frontend` (the shell's own public OIDC client, kiban-test realm
// ONLY — Keycloak admin API, restored in `afterAll` no matter how the tests finish) rather than
// touching the realm's own default lifetime, so nothing else sharing this realm (curl-proofs,
// other e2e clients) is affected. Two cases:
//   1. Login, wait past the short access-token expiry, perform an authenticated action — it must
//      succeed via SILENT refresh (a token-endpoint POST is observed on the wire; no re-login
//      page is ever shown).
//   2. The refresh token itself is revoked server-side (Keycloak admin `logout` endpoint, which
//      invalidates the user's whole session including the refresh token) before it expires —
//      the next authenticated action must end in a CLEAN redirect to `/login`, never a stuck/
//      broken page.
// Video always-on (playwright.config.ts's `use.video`), retained under web/shell/e2e-artifacts/.
const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, "..", "..", "..");
const env = loadTestEnv(repoRoot);

const kcBase = `http://127.0.0.1:${env.KEYCLOAK_HOST_PORT ?? "8081"}`;
const realm = env.KEYCLOAK_REALM ?? "kiban";
const frontendClientId = "kiban-frontend";
const shortLifespanSeconds = 8;

async function adminToken(): Promise<string> {
  const res = await fetch(`${kcBase}/realms/master/protocol/openid-connect/token`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "password",
      client_id: "admin-cli",
      username: env.KC_BOOTSTRAP_ADMIN_USERNAME!,
      password: env.KC_BOOTSTRAP_ADMIN_PASSWORD!
    })
  });
  if (!res.ok) throw new Error(`session-expiry: could not obtain a Keycloak master admin token (${res.status})`);
  const body = (await res.json()) as { access_token: string };
  return body.access_token;
}

async function adminFetch(token: string, pathname: string, init?: RequestInit): Promise<Response> {
  return fetch(`${kcBase}${pathname}`, {
    ...init,
    headers: { authorization: `Bearer ${token}`, "content-type": "application/json", ...(init?.headers ?? {}) }
  });
}

async function findClientUuid(token: string, clientId: string): Promise<string> {
  const res = await adminFetch(token, `/admin/realms/${realm}/clients?clientId=${clientId}`);
  const body = (await res.json()) as Array<{ id: string }>;
  if (!body[0]) throw new Error(`session-expiry: client '${clientId}' not found in realm '${realm}'`);
  return body[0].id;
}

async function findUserId(token: string, username: string): Promise<string> {
  const res = await adminFetch(token, `/admin/realms/${realm}/users?username=${username}&exact=true`);
  const body = (await res.json()) as Array<{ id: string }>;
  if (!body[0]) throw new Error(`session-expiry: user '${username}' not found in realm '${realm}'`);
  return body[0].id;
}

async function setFrontendAccessTokenLifespan(token: string, clientUuid: string, seconds: number | null): Promise<void> {
  const getRes = await adminFetch(token, `/admin/realms/${realm}/clients/${clientUuid}`);
  const client = (await getRes.json()) as { attributes?: Record<string, string> };
  const attributes = { ...(client.attributes ?? {}) };
  if (seconds === null) {
    delete attributes["access.token.lifespan"];
  } else {
    attributes["access.token.lifespan"] = String(seconds);
  }
  const putRes = await adminFetch(token, `/admin/realms/${realm}/clients/${clientUuid}`, {
    method: "PUT",
    body: JSON.stringify({ ...client, attributes })
  });
  if (!putRes.ok) throw new Error(`session-expiry: failed to set access.token.lifespan (${putRes.status})`);
}

test.describe("session expiry + refresh mid-journey", () => {
  let clientUuid: string;

  test.beforeAll(async () => {
    const token = await adminToken();
    clientUuid = await findClientUuid(token, frontendClientId);
    await setFrontendAccessTokenLifespan(token, clientUuid, shortLifespanSeconds);
  });

  test.afterAll(async () => {
    // Always restore, even if a test above failed — this client is shared by every OTHER shell
    // e2e spec in this suite; leaving a shortened lifespan behind would make unrelated specs
    // flaky under CPU load, and leaving it in place after the run ends would leak a test-only
    // config change into the isolated kiban-test stack indefinitely.
    const token = await adminToken();
    await setFrontendAccessTokenLifespan(token, clientUuid, null);
  });

  test("silent refresh: an authenticated action after access-token expiry succeeds with no re-login page", async ({
    browser
  }, testInfo) => {
    const username = process.env.KIBAN_E2E_SUPERADMIN_USERNAME;
    const password = process.env.KIBAN_E2E_SUPERADMIN_PASSWORD;
    const companyId = process.env.KIBAN_E2E_COMPANY_ID;
    if (!username || !password || !companyId) {
      throw new Error("KIBAN_E2E_SUPERADMIN_*/KIBAN_E2E_COMPANY_ID not set — global-setup.ts did not run");
    }

    const context = await browser.newContext({ recordVideo: { dir: testInfo.outputDir } });
    const page = await context.newPage();

    const tokenEndpointRequests: string[] = [];
    page.on("request", (req) => {
      if (req.url().includes("/protocol/openid-connect/token") && req.method() === "POST") {
        tokenEndpointRequests.push(req.url());
      }
    });

    await page.goto("/");
    await page.getByRole("button", { name: "Log in" }).click();
    await page.waitForURL(/\/auth\/realms\//);
    await page.locator("#username").fill(username);
    await page.locator("#password").fill(password);
    await page.locator("#kc-login").click();
    await page.waitForURL(/\/app$/, { timeout: 20_000 });

    // Discard the login-flow's own code-exchange token-endpoint call — only refreshes that
    // happen AFTER this point count as proof of silent mid-journey refresh.
    tokenEndpointRequests.length = 0;

    // Wait past the shortened access-token lifespan AND past the SDK's 30 s clock-skew allowance
    // (session.ts CLOCK_SKEW_MS) — no proactive refresh-before-expiry exists in this SDK
    // (web/sdk/src/auth/session.ts's own doc comment: "never triggers a refresh" outside the
    // 401-driven hook in client.ts), so the NEXT authenticated request is guaranteed to hit a
    // real 401 first, and the full page load below hydrates a persisted TokenSet whose access
    // token is unambiguously expired.
    await page.waitForTimeout((shortLifespanSeconds + 35) * 1000);

    // The authenticated action: a FULL page load (page.goto — a reload/bookmark, not an SPA
    // navigation) of a deep link into the company-scoped docs module, then create a document.
    // The reload must keep the session (the persisted set still holds a valid refresh token) and
    // stay on the deep link — never bounce to /login and lose it. A stale access token would 401
    // the underlying calls; the SDK's `ApiClient.request` (web/sdk/src/client.ts) transparently
    // refreshes and retries once (never isRetry-looped) — from the UI's perspective this must look
    // like nothing happened.
    await page.goto(`/app/c/${companyId}/docs`);
    await expect(page.getByTestId("docs-documents-page")).toBeVisible({ timeout: 15_000 });
    expect(page.url()).toContain(`/app/c/${companyId}/docs`);

    const docTitle = `Session Expiry Proof ${Date.now()}`;
    await page.getByTestId("docs-new-title").fill(docTitle);
    await page.getByTestId("docs-create-button").click();
    await expect(page.getByTestId("docs-owned-list")).toContainText(docTitle, { timeout: 15_000 });

    // No re-login page was ever shown — still on the docs route the whole time, not /login or a
    // Keycloak auth page.
    expect(page.url()).toContain(`/app/c/${companyId}/docs`);
    expect(page.url()).not.toContain("/auth/realms/");

    // Network evidence: at least one POST to the token endpoint happened after login completed
    // (the silent refresh itself — grant_type=refresh_token, though the request body isn't
    // inspected here; the endpoint hit + the action succeeding together are the proof).
    expect(tokenEndpointRequests.length).toBeGreaterThan(0);

    await page.goto("/app");
    await page.getByRole("button", { name: /log out/i }).click();
    await page.waitForURL((url) => !url.searchParams.has("code"), { timeout: 15_000 });
  });

  test("revoked refresh token: the next authenticated action ends in a clean redirect to /login, not a stuck page", async ({
    browser
  }, testInfo) => {
    const username = process.env.KIBAN_E2E_SUPERADMIN_USERNAME;
    const password = process.env.KIBAN_E2E_SUPERADMIN_PASSWORD;
    const companyId = process.env.KIBAN_E2E_COMPANY_ID;
    if (!username || !password || !companyId) {
      throw new Error("KIBAN_E2E_SUPERADMIN_*/KIBAN_E2E_COMPANY_ID not set — global-setup.ts did not run");
    }

    const context = await browser.newContext({ recordVideo: { dir: testInfo.outputDir } });
    const page = await context.newPage();

    await page.goto("/");
    await page.getByRole("button", { name: "Log in" }).click();
    await page.waitForURL(/\/auth\/realms\//);
    await page.locator("#username").fill(username);
    await page.locator("#password").fill(password);
    await page.locator("#kc-login").click();
    await page.waitForURL(/\/app$/, { timeout: 20_000 });

    // Revoke server-side: Keycloak admin `logout` invalidates every active session (and thus
    // every refresh token issued under it) for this user — simulating an admin-forced logout /
    // credential compromise response, not merely a locally-expired token.
    const token = await adminToken();
    const userId = await findUserId(token, username);
    const logoutRes = await adminFetch(token, `/admin/realms/${realm}/users/${userId}/logout`, { method: "POST" });
    if (!logoutRes.ok) throw new Error(`session-expiry: admin logout failed (${logoutRes.status})`);

    // Wait past the shortened access-token lifespan so the NEXT request is guaranteed to 401
    // and attempt a refresh — which Keycloak will now reject (the refresh token backing it no
    // longer has a live session).
    await page.waitForTimeout((shortLifespanSeconds + 5) * 1000);

    await page.goto(`/app/c/${companyId}/docs`);

    // Clean redirect to /login — never a stuck error page, a blank screen, or a page that still
    // LOOKS authenticated (stale nav/company switcher rendered from before the revoke).
    // `page.waitForURL`'s default `waitUntil: "load"` never fires for this router's
    // client-side (`<Navigate>`/history-API) redirect — no new document load occurs — so this
    // polls the URL directly instead of waiting on a load event that will never come.
    await expect.poll(() => page.url(), { timeout: 20_000 }).toMatch(/\/login$/);
    await expect(page.getByRole("heading", { name: "Sign in to Kiban" })).toBeVisible();
    await expect(page.getByTestId("company-switcher-select")).toHaveCount(0);
  });
});
