// SPDX-License-Identifier: Apache-2.0

// Playwright globalSetup: prepares the fixtures the SDK e2e flow needs against the ISOLATED
// `kiban-test` stack (`make test-stack-up`, .env.test; never .env's live/public
// stack, see ../../e2e-shared/env.ts's loadTestEnv), mirroring infra/e2e-login.sh rather than
// reinventing it:
//   1. Keycloak master-admin token (same KC_BOOTSTRAP_ADMIN_USERNAME/PASSWORD bootstrap itself
//      uses, read from .env.test).
//   2. The SEEDED superadmin (infra/secrets-in/superadmin-password, bootstrap-created) has a
//      forced temporary password — a real browser can complete Keycloak's interactive
//      UPDATE_PASSWORD page, but that's Keycloak UX, not anything this SDK owns proving. Same
//      workaround e2e-login.sh uses: clear requiredActions + set a fresh, non-temporary,
//      THROWAWAY password for this test run only (infra/secrets-in/'s stored secret is never
//      read or touched).
//   3. Idempotently upsert a fixture module catalog row distinct from e2e-login.sh's
//      `kiban_e2e_fake` (installed, disabled) so the superadmin enable/disable round trip
//      has a real, safe-to-toggle target — same idempotent upsert SQL shape as
//      infra/e2e-login.sh step 5.
//   4. A fixture company the superadmin is a member of, with the docs module's default
//      module-access rows — the grants route binds every tuple to a company and one enabled
//      module (internal/authz/http.go handleGrants), so the grant/revoke recipe proof needs a
//      real, active company. Same SQL as web/shell/e2e/global-setup.ts, distinct code
//      (`SDKE2E`) so the two suites never share a row.
// process.env values set here are inherited by Playwright's worker processes (Playwright's own
// documented globalSetup pattern) — no extra IPC/temp-file plumbing needed.
import { randomBytes } from "node:crypto";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { loadTestEnv, convergeSuperadminIdentity, convergeModuleRegistration, psqlExec, psqlScalar } from "../../e2e-shared/env.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, "..", "..", "..");

function randomToken(): string {
  return randomBytes(12).toString("hex");
}

async function adminToken(kcBase: string, username: string, password: string): Promise<string> {
  const res = await fetch(`${kcBase}/realms/master/protocol/openid-connect/token`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ grant_type: "password", client_id: "admin-cli", username, password })
  });
  if (!res.ok) throw new Error(`e2e global-setup: could not obtain a Keycloak master admin token (${res.status})`);
  const body = (await res.json()) as { access_token?: string };
  if (!body.access_token) throw new Error("e2e global-setup: Keycloak admin token response had no access_token");
  return body.access_token;
}

async function adminFetch(kcBase: string, token: string, pathname: string, init?: RequestInit): Promise<unknown> {
  const res = await fetch(`${kcBase}${pathname}`, {
    ...init,
    headers: { authorization: `Bearer ${token}`, "content-type": "application/json", ...(init?.headers ?? {}) }
  });
  if (!res.ok) {
    throw new Error(`e2e global-setup: Keycloak admin API ${pathname} -> ${res.status}: ${await res.text()}`);
  }
  const text = await res.text();
  return text ? JSON.parse(text) : undefined;
}

export default async function globalSetup(): Promise<void> {
  const env = loadTestEnv(repoRoot);
  const kcHostPort = env.KEYCLOAK_HOST_PORT ?? "8081";
  const realm = env.KEYCLOAK_REALM ?? "kiban";
  const kcAdminUser = env.KC_BOOTSTRAP_ADMIN_USERNAME;
  const kcAdminPassword = env.KC_BOOTSTRAP_ADMIN_PASSWORD;
  const superadminUsername = env.KIBAN_SUPERADMIN_USERNAME ?? "superadmin";
  if (!kcAdminUser || !kcAdminPassword) {
    throw new Error("e2e global-setup: .env is missing KC_BOOTSTRAP_ADMIN_USERNAME/PASSWORD — run `make dev` first");
  }
  const kcBase = `http://127.0.0.1:${kcHostPort}`;

  const token = await adminToken(kcBase, kcAdminUser, kcAdminPassword);
  const realmUrl = `/admin/realms/${realm}`;

  const users = (await adminFetch(kcBase, token, `${realmUrl}/users?username=${superadminUsername}&exact=true`)) as Array<{
    id: string;
    email?: string;
  }>;
  const superadminId = users[0]?.id;
  if (!superadminId) {
    throw new Error(
      `e2e global-setup: seeded superadmin '${superadminUsername}' not found in Keycloak — did bootstrap run (\`make dev\`)?`
    );
  }

  const superadminPassword = `e2e-sdk-${randomToken()}`;
  await adminFetch(kcBase, token, `${realmUrl}/users/${superadminId}`, {
    method: "PUT",
    body: JSON.stringify({ requiredActions: [] })
  });
  await adminFetch(kcBase, token, `${realmUrl}/users/${superadminId}/reset-password`, {
    method: "PUT",
    body: JSON.stringify({ type: "password", value: superadminPassword, temporary: false })
  });

  // `make check`'s dbtest truncation (internal/identity/dbtest_test.go,
  // internal/org/dbtest_test.go) wipes identity.user_account between runs — this
  // suite must converge them itself instead of assuming a prior bootstrap run's rows survived.
  // Mirrors internal/bootstrap's SuperadminStep/SeedSuperadmin, via the
  // isolated stack's own env the guard above already validated.
  const userRowId = convergeSuperadminIdentity(env, superadminId, users[0]?.email, superadminUsername);

  // The docs module must be installed+enabled for its `docs_document` type to be grantable
  // (registry-owned rows, wiped by `make check`'s registry dbtest truncation; converge via
  // registry's own re-seed, same helper the shell suite uses).
  await convergeModuleRegistration(env, repoRoot, kcBase, realm, token, ["docs"]);

  // Fixture company + superadmin membership + docs default module-access rows (see step 4
  // above; the SQL mirrors web/shell/e2e/global-setup.ts's `SHELLE2E` fixture).
  const fixtureCompanyCode = "SDKE2E";
  let companyId = psqlScalar(env, `SELECT id FROM org.org_unit WHERE code = '${fixtureCompanyCode}' AND parent_id IS NULL`);
  if (!companyId) {
    companyId = psqlScalar(
      env,
      `INSERT INTO org.org_unit (type_key, parent_id, code, name, is_active)
       VALUES ('company', NULL, '${fixtureCompanyCode}', 'SDK E2E Co', true)
       RETURNING id`
    );
  }
  psqlExec(
    env,
    `INSERT INTO org.member (company_id, code, display_name, user_id, is_active)
     VALUES ('${companyId}', 'SUPERADMIN', 'Superadmin', '${userRowId}', true)
     ON CONFLICT (company_id, code) DO UPDATE SET user_id = EXCLUDED.user_id, is_active = true`
  );
  psqlExec(
    env,
    `INSERT INTO authz.default_grant (company_id, module_key, actor)
     VALUES ('${companyId}', 'docs', 'e2e-fixture')
     ON CONFLICT (company_id, module_key) DO NOTHING`
  );
  psqlExec(
    env,
    `INSERT INTO authz.tuple (object_type, object_id, relation, subject_type, subject_id)
     VALUES ('company_module', '${companyId}/docs', 'system', 'system', 'platform')
     ON CONFLICT DO NOTHING`
  );

  // Fixture module catalog row (idempotent upsert — same shape as infra/e2e-login.sh step 5,
  // a distinct module_key so the two suites never fight over the same row). `make check`'s
  // registry dbtest_test.go truncates platform.module_catalog/module_installation, so this must
  // re-run every time, not just on a cold stack.
  const fixtureModuleKey = "kiban_e2e_sdk_fixture";
  psqlExec(
    env,
    `INSERT INTO platform.module_catalog (module_key, display_name, scope_type, mandatory, base_path, health_path, port, license_class, manifest_version, is_active)
     VALUES ('${fixtureModuleKey}', 'Kiban SDK E2E Fixture Module', 'global', false, '/api/${fixtureModuleKey}', '/health', 9998, 'foundation', '0.0.0-test', true)
     ON CONFLICT (module_key) DO UPDATE SET display_name = EXCLUDED.display_name`
  );
  psqlExec(
    env,
    `INSERT INTO platform.module_installation (module_key, installed, enabled)
     VALUES ('${fixtureModuleKey}', true, false)
     ON CONFLICT (module_key) DO NOTHING`
  );

  process.env.KIBAN_E2E_SUPERADMIN_USERNAME = superadminUsername;
  process.env.KIBAN_E2E_SUPERADMIN_PASSWORD = superadminPassword;
  process.env.KIBAN_E2E_FIXTURE_MODULE_KEY = fixtureModuleKey;
  process.env.KIBAN_E2E_COMPANY_ID = companyId;
}
