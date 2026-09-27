// SPDX-License-Identifier: Apache-2.0

import { createHmac } from "node:crypto";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { expect, test, type Page } from "@playwright/test";
import { loadTestEnv } from "../../e2e-shared/env.js";

// MFA through the real browser — the largest gap between "API says MFA works"
// (internal/identity/mfa_enforcement_live_test.go + mfa_matrix_live_test.go, the
// enforcement matrix) and "a user can actually complete it". Per-user MFA policy is the
// `kiban.login_security.required_mode` Keycloak user attribute (mfa_matrix_live_test.go's own
// header comment; values: `none` / `otp_required` / `passkey_required` /
// `otp_or_passkey_required`) — this spec sets it directly via the Keycloak admin API on
// DEDICATED, freshly-created fixture identities (never the superadmin or any shared fixture from
// global-setup.ts — MFA policy is never weakened on the superadmin or shared fixtures).
//
// TOTP code generation: Node's `crypto.createHmac` (stdlib, HMAC-SHA1, RFC 6238), not an
// otplib/otpauth devDependency. Justification: this is a ~15-line, pinned algorithm (6 digits,
// 30s step, HMAC-SHA1 — Keycloak's own default OTPPolicy, matching
// mfa_matrix_live_test.go's own `mfaEnforcementOtpCredentialSeed`'s
// `{"subType":"totp","digits":6,"period":30,"algorithm":"HmacSHA1"}`), needs zero maintenance,
// and avoids a new third-party dependency for logic this short and this stable — a genuine
// judgment call, but RFC 6238 has not changed since 2011 and Keycloak's default OTPPolicy is a
// project decision, not something upstream churn would silently break this
// test against. One non-obvious wrinkle, confirmed empirically (not assumed from any RFC or
// otplib source): Keycloak's `#totpSecret` hidden field carries the RAW secret bytes used
// directly as the HMAC key server-side (`HmacOTP`) — NOT base32-decoded. The base32 form (RFC
// 4648) is only a separate re-encoding of those same raw bytes for the QR code / "manual entry
// key" shown to external authenticator apps, which DO require base32 input. Feeding the raw
// `#totpSecret` string's own bytes to HMAC (skipping any base32 step) is what matches the
// server; base32-decoding it first (the natural first guess) produces a DIFFERENT key and every
// code is silently wrong — this was discovered by hand against the real kiban-test Keycloak
// (a first draft base32-decoded the secret and every enrollment attempt failed with "Invalid
// authenticator code."), not from documentation.
//
// Passkey feasibility: tried first, with Playwright's CDP
// WebAuthn virtual authenticator (`WebAuthn.enable` + `addVirtualAuthenticator`, resident key +
// user verification, `internal` transport). The authenticator itself worked — Chrome's own
// `navigator.credentials.create()` ceremony completed and POSTed back to Keycloak's
// `webauthn-register-passwordless` required action — but Keycloak's OWN server-side response
// was: "Passkey registration result is invalid. SecurityError: This is an invalid domain."
// Root cause, confirmed by direct inspection of the real failure page (not assumed): the WebAuthn
// spec requires an RP ID to be a registrable DOMAIN — an IP-literal origin (this stack's own
// `https://127.0.0.1:<port>`) is NOT a valid RP ID, so
// EVERY WebAuthn ceremony against kiban-test fails this exact way regardless of automation
// technique (headless, headed, virtual authenticator, or a human with a real security key) — a
// structural property of this stack's own origin, not a Kiban bug, not a Playwright/CDP
// limitation, and not fixable by trying harder at the automation. A real deployment behind a DNS
// hostname would not hit this. Confirmed live against a throwaway `passkey_required` fixture
// user (created, exercised, and deleted directly via the Keycloak admin API). Passkey
// coverage is therefore NOT attempted as a passing test here (it cannot pass against this
// stack's own IP-literal origin, and a test asserting the SecurityError itself would be padding,
// not a passkey proof) — TOTP (below) and `otp_or_passkey_required` (which
// deterministically defaults to
// the SAME TOTP setup page when neither credential exists yet, since Keycloak's authenticator has
// no chooser UI) are both covered instead.
const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, "..", "..", "..");
const env = loadTestEnv(repoRoot);

const kcBase = `http://127.0.0.1:${env.KEYCLOAK_HOST_PORT ?? "8081"}`;
const realm = env.KEYCLOAK_REALM ?? "kiban";

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
  if (!res.ok) throw new Error(`mfa.spec: could not obtain a Keycloak master admin token (${res.status})`);
  return ((await res.json()) as { access_token: string }).access_token;
}

async function adminFetch(token: string, pathname: string, init?: RequestInit): Promise<Response> {
  return fetch(`${kcBase}${pathname}`, {
    ...init,
    headers: { authorization: `Bearer ${token}`, "content-type": "application/json", ...(init?.headers ?? {}) }
  });
}

/** Create-or-replace a DEDICATED fixture identity (deletes any prior user of the same name
 * first, so repeated runs never accumulate stale credentials) with the given required_mode.
 * Mirrors mfa_matrix_live_test.go's own mfaEnforcementSeedUser (Go side) — this is the same
 * fixture shape from Playwright/TypeScript, never touching global-setup.ts's shared fixtures. */
async function seedMfaFixtureUser(token: string, username: string, requiredMode: string): Promise<{ password: string }> {
  const findRes = await adminFetch(token, `/admin/realms/${realm}/users?username=${username}&exact=true`);
  const existing = (await findRes.json()) as Array<{ id: string }>;
  if (existing[0]) {
    await adminFetch(token, `/admin/realms/${realm}/users/${existing[0].id}`, { method: "DELETE" });
  }
  const createRes = await adminFetch(token, `/admin/realms/${realm}/users`, {
    method: "POST",
    body: JSON.stringify({
      username,
      enabled: true,
      emailVerified: true,
      firstName: "E2E",
      lastName: "Mfa",
      email: `${username}@kiban.local`,
      requiredActions: [],
      attributes: { "kiban.login_security.required_mode": [requiredMode] }
    })
  });
  if (!createRes.ok) throw new Error(`mfa.spec: create fixture user ${username} -> ${createRes.status}`);
  const found = (await (
    await adminFetch(token, `/admin/realms/${realm}/users?username=${username}&exact=true`)
  ).json()) as Array<{ id: string }>;
  const userId = found[0]!.id;
  const password = `e2e-${username}-pw`;
  const resetRes = await adminFetch(token, `/admin/realms/${realm}/users/${userId}/reset-password`, {
    method: "PUT",
    body: JSON.stringify({ type: "password", value: password, temporary: false })
  });
  if (!resetRes.ok) throw new Error(`mfa.spec: reset-password for ${username} -> ${resetRes.status}`);
  return { password };
}

async function deleteMfaFixtureUser(token: string, username: string): Promise<void> {
  const findRes = await adminFetch(token, `/admin/realms/${realm}/users?username=${username}&exact=true`);
  const existing = (await findRes.json()) as Array<{ id: string }>;
  if (existing[0]) {
    await adminFetch(token, `/admin/realms/${realm}/users/${existing[0].id}`, { method: "DELETE" });
  }
}

/** RFC 6238 TOTP, HMAC-SHA1, 6 digits, 30s step — Keycloak's default OTPPolicy. `secretRaw` is
 * used as the HMAC key VERBATIM (its own UTF-8 bytes), matching Keycloak's `#totpSecret` hidden
 * field / server-side `HmacOTP` — see this file's header comment for why this is NOT base32. */
function totp(secretRaw: string, when: number = Date.now(), timeStep = 30, digits = 6): string {
  const key = Buffer.from(secretRaw, "utf8");
  const counter = Math.floor(when / 1000 / timeStep);
  const counterBuf = Buffer.alloc(8);
  counterBuf.writeBigUInt64BE(BigInt(counter));
  const hmac = createHmac("sha1", key).update(counterBuf).digest();
  const offset = hmac[hmac.length - 1]! & 0xf;
  const code =
    ((hmac[offset]! & 0x7f) << 24) | ((hmac[offset + 1]! & 0xff) << 16) | ((hmac[offset + 2]! & 0xff) << 8) | (hmac[offset + 3]! & 0xff);
  return String(code % 10 ** digits).padStart(digits, "0");
}

async function login(page: Page, username: string, password: string): Promise<void> {
  await page.goto("/");
  await page.getByRole("button", { name: "Log in" }).click();
  await page.waitForURL(/\/auth\/realms\//);
  await page.locator("#username").fill(username);
  await page.locator("#password").fill(password);
  await page.locator("#kc-login").click();
}

test.describe("MFA through the real browser", () => {
  test("TOTP: first login enrolls (Keycloak's own CONFIGURE_TOTP page, real secret, real generated code) -> lands in the shell; second login challenges -> wrong code rejected -> right code accepted", async ({
    browser
  }, testInfo) => {
    const token = await adminToken();
    const username = `e2e-mfa-totp-${Date.now()}`;
    const { password } = await seedMfaFixtureUser(token, username, "otp_required");

    try {
      const context = await browser.newContext({ recordVideo: { dir: testInfo.outputDir } });
      const page = await context.newPage();

      // --- First login: no credential yet -> Keycloak's own enrollment (setup) page. ---
      await login(page, username, password);
      await page.waitForURL(/execution=CONFIGURE_TOTP/, { timeout: 15_000 });
      await expect(page.locator("#kc-totp-settings-form")).toBeVisible();

      const secret = await page.locator("#totpSecret").getAttribute("value");
      expect(secret, "Keycloak's own hidden #totpSecret field must carry the real generated secret").toBeTruthy();

      const enrollCode = totp(secret!);
      await page.locator("#totp").fill(enrollCode);
      await page.locator("#userLabel").fill("e2e-totp-device");
      await page.locator("#saveTOTPBtn").click();

      // Enrollment accepted -> lands in the shell, same as any other successful login.
      await page.waitForURL(/\/app$/, { timeout: 20_000 });
      await expect(page.getByTestId("company-switcher-select")).toBeVisible({ timeout: 15_000 }).catch(() => {
        // This fixture identity has no company membership (MFA-only fixture, out of this
        // spec's scope to also wire org fixtures for) — the switcher may render empty. What
        // matters here is the URL itself: /app, never a Keycloak page.
      });
      expect(page.url()).toContain("/app");

      await page.goto("/app");
      await page.getByRole("button", { name: /log out/i }).click();
      await page.waitForURL((url) => !url.searchParams.has("code"), { timeout: 15_000 });

      // --- Second login: a stored credential now exists -> Keycloak's own runtime OTP
      // CHALLENGE page (kc-otp-login-form / #otp — distinct from the enrollment page's #totp). ---
      await login(page, username, password);
      await page.waitForURL(/login-actions\/authenticate/, { timeout: 15_000 });
      await expect(page.locator("#kc-otp-login-form")).toBeVisible();

      // Wrong code -> rejected, still on the challenge page.
      await page.locator("#otp").fill("000000");
      await page.locator("#kc-login").click();
      await page.waitForTimeout(1000);
      await expect(page.locator("#kc-otp-login-form")).toBeVisible();
      await expect(page.getByText(/Invalid authenticator code/i)).toBeVisible();

      // Right code -> accepted, lands in the shell. Keycloak's own OTP validator rejects a code
      // reused within the same/adjacent 30s window as the last ACCEPTED code (anti-replay,
      // confirmed live: a first draft reused the enrollment code verbatim here and every
      // "right" code was rejected) — wait for a fresh window before generating this one, rather
      // than a code that happens to collide with the enrollment step's.
      await page.waitForTimeout(31_000);
      const challengeCode = totp(secret!);
      await page.locator("#otp").fill(challengeCode);
      await page.locator("#kc-login").click();
      await page.waitForURL(/\/app$/, { timeout: 20_000 });
      expect(page.url()).toContain("/app");

      await context.close();
    } finally {
      await deleteMfaFixtureUser(token, username);
    }
  });

  test("otp_or_passkey_required ('either' mode): with neither credential configured, setup deterministically lands on the SAME TOTP enrollment page (no chooser UI) — and it can be completed", async ({
    browser
  }, testInfo) => {
    const token = await adminToken();
    const username = `e2e-mfa-either-${Date.now()}`;
    const { password } = await seedMfaFixtureUser(token, username, "otp_or_passkey_required");

    try {
      const context = await browser.newContext({ recordVideo: { dir: testInfo.outputDir } });
      const page = await context.newPage();

      await login(page, username, password);
      // "either" with no credential
      // and no chooser UI defaults deterministically to CONFIGURE_TOTP, not a 50/50 or an error.
      await page.waitForURL(/execution=CONFIGURE_TOTP/, { timeout: 15_000 });
      await expect(page.locator("#kc-totp-settings-form")).toBeVisible();

      const secret = await page.locator("#totpSecret").getAttribute("value");
      const code = totp(secret!);
      await page.locator("#totp").fill(code);
      await page.locator("#userLabel").fill("e2e-either-device");
      await page.locator("#saveTOTPBtn").click();
      await page.waitForURL(/\/app$/, { timeout: 20_000 });
      expect(page.url()).toContain("/app");

      await context.close();
    } finally {
      await deleteMfaFixtureUser(token, username);
    }
  });
});
