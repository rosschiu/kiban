// Playwright e2e targets ONLY the isolated `kiban-test` stack (`make test-stack-up`), never
// `.env`'s live stack — a global-setup.ts that loaded .env would reset the public
// superadmin password.
// Mirrors internal/livestack.TargetsLiveStack()'s two-signal logic in TS: public mode ALONE
// isn't refused (a caller may have deliberately redirected at an isolated stack while the live
// one happens to be public) — only refuse when infra/.public-mode is present AND the env this
// call actually resolved to shares a guarded host port with .env's own live baseline.
//
// Three ports are guarded, because global-setup.ts and playwright.config.ts mutate through all
// of them: POSTGRES_HOST_PORT (fixture rows), KEYCLOAK_HOST_PORT (superadmin password reset) and
// KIBAN_GATEWAY_TLS_HOST_PORT (both suites' playwright.config.ts build baseURL from it — sdk:
// passed to its static-server harness which fetches through it; shell: baseURL itself,
// `https://127.0.0.1:<port>` — and both suites perform mutating gateway requests such as login
// password grants and notification.spec.ts's channel-create/subscribe/send-message/mark-read).
// The guard refuses if ANY resolved port matches; the refusal message names which one. These
// three keys are the only host ports either suite uses (`grep -rn "HOST_PORT" web/sdk/e2e
// web/shell/e2e`).
//
// This file is the single shared copy of this logic (including convergeModuleRegistration,
// which only web/shell calls), kept outside either workspace package so both suites import it.
import { existsSync } from "node:fs";
import { readFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import path from "node:path";

export function loadDotEnv(filePath: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const line of readFileSync(filePath, "utf8").split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const eq = trimmed.indexOf("=");
    if (eq === -1) continue;
    out[trimmed.slice(0, eq)] = trimmed.slice(eq + 1);
  }
  return out;
}

// loadTestEnv resolves .env.test — refusing outright (clear error, no fallback to
// .env) if it's absent or if the two-signal live-stack check trips.
export function loadTestEnv(repoRoot: string): Record<string, string> {
  const envTestPath = path.join(repoRoot, ".env.test");
  if (!existsSync(envTestPath)) {
    throw new Error(
      "e2e global-setup: .env.test not found — run `make test-stack-up` first " +
        "(Playwright e2e targets the isolated kiban-test stack only, never .env's live stack)"
    );
  }
  const env = loadDotEnv(envTestPath);

  const publicModeMarker = path.join(repoRoot, "infra", ".public-mode");
  if (existsSync(publicModeMarker)) {
    const liveEnvPath = path.join(repoRoot, ".env");
    if (existsSync(liveEnvPath)) {
      const liveEnv = loadDotEnv(liveEnvPath);
      // Check every port either global-setup.ts / playwright.config.ts
      // actually mutates something through — Postgres (fixture rows), Keycloak (superadmin
      // password reset), and the gateway TLS port (baseURL for both suites' mutating requests).
      // Refuse if ANY resolved port equals .env's own live baseline for that same key.
      //
      // Unlike POSTGRES_HOST_PORT/KEYCLOAK_HOST_PORT (always written explicitly into
      // .env), .env has NO line for KIBAN_GATEWAY_TLS_HOST_PORT — the live gateway's
      // actual port comes from infra/compose.yaml's own shell default
      // (`${KIBAN_GATEWAY_TLS_HOST_PORT:-8443}`). Reading the live side with a bare `?? ""` would
      // make that comparison never match (an empty string never equals a real port), silently
      // defeating the guard for the gateway port. `defaultValue` lets a
      // guarded key fall back to the SAME default the deployment config itself uses, applied to
      // BOTH sides of the comparison, when the key is genuinely absent from that file.
      const guardedPorts: Array<{ key: string; label: string; defaultValue?: string }> = [
        { key: "POSTGRES_HOST_PORT", label: "POSTGRES_HOST_PORT" },
        { key: "KEYCLOAK_HOST_PORT", label: "KEYCLOAK_HOST_PORT" },
        { key: "KIBAN_GATEWAY_TLS_HOST_PORT", label: "KIBAN_GATEWAY_TLS_HOST_PORT", defaultValue: "8443" }
      ];
      for (const { key, label, defaultValue } of guardedPorts) {
        const resolved = env[key] ?? defaultValue ?? "";
        const live = liveEnv[key] ?? defaultValue ?? "";
        if (resolved !== "" && resolved === live) {
          throw new Error(
            "e2e global-setup: refusing to run against the live stack: it is in PUBLIC mode " +
              "(infra/.public-mode present, serving the public deployment) and the resolved " +
              `${label} matches .env's own live value — this must target the ` +
              "isolated kiban-test stack (.env.test, via `make test-stack-up`) instead"
          );
        }
      }
    }
  }
  return env;
}

// --- Shared direct-SQL fixture plumbing, factored here so both global-setup.ts
// files (sdk + shell) call one implementation instead of duplicating psql invocation shape. ---

// psqlArgs builds the common connection args for the admin (migration-owner) role against
// .env.test's resolved Postgres — the same role global-setup.ts's other direct-SQL
// fixtures already connect as (module-catalog fixture, org/member fixture).
export function psqlArgs(env: Record<string, string>): string[] {
  return [
    "-h",
    "127.0.0.1",
    "-p",
    env.POSTGRES_HOST_PORT ?? "5432",
    "-U",
    "kiban",
    "-d",
    env.POSTGRES_DB ?? "kiban",
    "-v",
    "ON_ERROR_STOP=1"
  ];
}

export function psqlProcEnv(env: Record<string, string>): NodeJS.ProcessEnv {
  return { ...process.env, PGPASSWORD: env.KIBAN_DB_PASSWORD ?? "" };
}

// psqlScalar runs one SQL statement in tuples-only mode and returns its first output line,
// trimmed — same "-tAc ... split('\n')[0]" workaround the company/member fixture already uses
// for INSERT ... RETURNING's trailing command-completion tag.
export function psqlScalar(env: Record<string, string>, sql: string): string {
  return (
    execFileSync("psql", [...psqlArgs(env), "-tAc", sql], { env: psqlProcEnv(env), encoding: "utf8" }).split(
      "\n"
    )[0] ?? ""
  ).trim();
}

// psqlExec runs one SQL statement, inheriting stdio (visible in the Playwright globalSetup log,
// same posture as the pre-existing module-catalog/company fixture inserts).
export function psqlExec(env: Record<string, string>, sql: string): void {
  execFileSync("psql", [...psqlArgs(env), "-c", sql], { env: psqlProcEnv(env), stdio: "inherit" });
}

// convergeSuperadminIdentity: makes the seeded
// superadmin's records match Keycloak's CURRENT kc_sub, regardless of what `make check`'s
// dbtest truncation (see internal/org/dbtest_test.go + internal/identity/dbtest_test.go's
// truncation lists) or a rebuilt Keycloak container (which issues a new kc_sub) left behind.
// Writes the exact rows internal/bootstrap's SuperadminStep writes via direct SQL, since
// bootstrap only runs once (its tuple-count marker short-circuits it) and authz's own
// grant route needs a superadmin bearer this setup does not have yet — this is global-setup's
// OWN idempotent convergence, not a bypass of either:
//   1. identity.user_account: resolve-or-create by kc_sub (mirrors UpsertUserAccount).
//   2. authz.tuple: `system:platform#superadmin @ user:<kcSub>` — the platform role's ONLY
//      record — if not already present (mirrors authz/store.Grant's ON CONFLICT DO NOTHING),
//      with the grant_ledger row and the audit.authz__events row store.Grant + bootstrap write,
//      both only when step 2 actually inserted (never on a no-op re-run).
// Steps 2's three INSERTs are one statement (data-modifying CTEs), so the tuple, its ledger
// row and its audit row commit or roll back together (a state change and its audit event are
// never split).
// The superadmin is the ONLY identity this file writes to identity.user_account by SQL (it
// mirrors bootstrap's own seed). Every plain fixture user is provisioned the way a real first
// login is — through the gateway (provisionUserAccount below).
// Returns the resolved identity.user_account.id (uuid, as text).
export function convergeSuperadminIdentity(
  env: Record<string, string>,
  kcSub: string,
  email: string | undefined,
  preferredUsername: string
): string {
  const emailLiteral = email ? `'${email.replace(/'/g, "''")}'` : "NULL";
  const usernameLiteral = `'${preferredUsername.replace(/'/g, "''")}'`;
  const userId = psqlScalar(
    env,
    `INSERT INTO identity.user_account (kc_sub, email, preferred_username)
     VALUES ('${kcSub}', ${emailLiteral}, ${usernameLiteral})
     ON CONFLICT (kc_sub) DO UPDATE SET
       email = EXCLUDED.email, preferred_username = EXCLUDED.preferred_username, updated_at = now()
     RETURNING id`
  );
  if (!userId) {
    throw new Error(`e2e global-setup: convergeSuperadminIdentity: no id returned for kc_sub ${kcSub}`);
  }

  psqlExec(
    env,
    `WITH ins AS (
       INSERT INTO authz.tuple (object_type, object_id, relation, subject_type, subject_id, subject_relation)
       VALUES ('system', 'platform', 'superadmin', 'user', '${kcSub}', '')
       ON CONFLICT DO NOTHING
       RETURNING subject_id
     ), ledger AS (
       INSERT INTO authz.grant_ledger (actor, object_type, object_id, relation, subject_type, subject_id, subject_relation, op, correlation_id)
       SELECT 'bootstrap-e2e', 'system', 'platform', 'superadmin', 'user', subject_id, '', 'grant', 'e2e-convergence' FROM ins
     )
     INSERT INTO audit.authz__events (actor, action, subject, payload)
     SELECT 'bootstrap-e2e', 'authz.platform_role.grant', 'user:' || subject_id,
            '{"role":"kiban-superadmin","grantedBy":"bootstrap-e2e","seed":"e2e-convergence"}'::jsonb
     FROM ins`
  );

  return userId;
}

// ensureKeycloakUser: create-or-converge a PLAIN (non-superadmin) Keycloak user for
// a second e2e fixture identity — the timesheet journey needs a distinct logged-in submitter
// alongside the seeded superadmin (acting as admin/approver, since the default module-access grant
// already gives it company_module#admin for any enabled module, no extra fixture wiring needed
// for that half). Unlike the superadmin (bootstrap-seeded, this file only ever RESETS its
// password), this user does not exist until an e2e run creates it — mirrors
// mintCatalogProbeToken's own idempotent create-or-update-by-name Keycloak admin API shape
// (lookup by exact name, create if absent, update if present) plus the existing
// requiredActions-clear + fresh-password-per-run pattern globalSetup already applies to the
// superadmin. `fresh: true` deletes a pre-existing user of that name first, so the returned
// kc_sub has never been seen by Kiban (a REAL first login, every run — first-login.spec.ts).
// Returns the resolved Keycloak user id (kc_sub) and a fresh throwaway password valid for this
// run only.
export async function ensureKeycloakUser(
  kcBase: string,
  realm: string,
  kcAdminToken: string,
  username: string,
  email: string,
  { fresh = false }: { fresh?: boolean } = {}
): Promise<{ kcUserId: string; password: string }> {
  const realmUrl = `${kcBase}/admin/realms/${realm}`;
  const adminHeaders = { authorization: `Bearer ${kcAdminToken}`, "content-type": "application/json" };

  const lookupRes = await fetch(`${realmUrl}/users?username=${encodeURIComponent(username)}&exact=true`, {
    headers: adminHeaders
  });
  if (!lookupRes.ok) throw new Error(`e2e global-setup: ensureKeycloakUser: user lookup for ${username} -> ${lookupRes.status}`);
  let existing = (await lookupRes.json()) as Array<{ id: string }>;
  if (fresh && existing.length > 0) {
    const deleteRes = await fetch(`${realmUrl}/users/${existing[0]!.id}`, { method: "DELETE", headers: adminHeaders });
    if (!deleteRes.ok) throw new Error(`e2e global-setup: ensureKeycloakUser: delete ${username} -> ${deleteRes.status}`);
    existing = [];
  }

  // firstName/lastName: the realm's user-profile config marks these required (same profile the
  // Keycloakify "Update Account Information" required action enforces on next login when a
  // profile is missing required fields — Keycloak computes this dynamically from the profile
  // config, NOT from a static `requiredActions` list, so clearing `requiredActions` alone does
  // NOT suppress it; found the hard way when the member's first login stalled on exactly this
  // screen instead of reaching /app). The bootstrap-seeded superadmin never hits this because
  // its own converge step (internal/bootstrap) already sets these fields.
  const profileBody = { username, email, enabled: true, emailVerified: true, firstName: "E2E", lastName: "Fixture", requiredActions: [] };

  let kcUserId: string;
  if (existing.length === 0) {
    const createRes = await fetch(`${realmUrl}/users`, {
      method: "POST",
      headers: adminHeaders,
      body: JSON.stringify(profileBody)
    });
    if (!createRes.ok) throw new Error(`e2e global-setup: ensureKeycloakUser: create ${username} -> ${createRes.status}`);
    const created = (await fetch(`${realmUrl}/users?username=${encodeURIComponent(username)}&exact=true`, {
      headers: adminHeaders
    }).then((r) => r.json())) as Array<{ id: string }>;
    kcUserId = created[0]!.id;
  } else {
    kcUserId = existing[0]!.id;
    // Idempotent converge, same posture as the superadmin's own requiredActions clear below —
    // a prior run's user must never accumulate a forced-action state a fresh login would stall on.
    const updateRes = await fetch(`${realmUrl}/users/${kcUserId}`, {
      method: "PUT",
      headers: adminHeaders,
      body: JSON.stringify(profileBody)
    });
    if (!updateRes.ok) throw new Error(`e2e global-setup: ensureKeycloakUser: update ${username} -> ${updateRes.status}`);
  }

  const password = `e2e-${username}-${randomBytes(12).toString("hex")}`;
  const resetRes = await fetch(`${realmUrl}/users/${kcUserId}/reset-password`, {
    method: "PUT",
    headers: adminHeaders,
    body: JSON.stringify({ type: "password", value: password, temporary: false })
  });
  if (!resetRes.ok) throw new Error(`e2e global-setup: ensureKeycloakUser: reset-password for ${username} -> ${resetRes.status}`);

  return { kcUserId, password };
}

// mintCatalogProbeToken: `GET /api/platform/catalog` is mounted behind
// `RequireAuth` (internal/gateway/platform_routes.go — any valid bearer, no superadmin gate)
// so proving the GATEWAY answers means presenting a real token with the "kiban-api" audience
// every TokenVerifier in this codebase requires. The realm ships no client with both
// direct-grant/service-account access AND that audience mapper by default — mirrors
// modules/notification/curl-proof.sh's own precedent exactly (idempotent create-or-reuse
// ephemeral client + "kiban-api-audience" mapper), except this uses a CLIENT CREDENTIALS grant
// (serviceAccountsEnabled) rather than a user password grant, so this probe never needs to know
// the superadmin's throwaway password — it only needs the Keycloak master-admin token
// global-setup already has in hand. The actual TOKEN GRANT (unlike the admin-API client/mapper
// setup, which talks to Keycloak's raw host port) must go through the GATEWAY's own `/auth/*`
// proxy, never Keycloak's raw host port — every TokenVerifier in this codebase (KEYCLOAK_ISSUER_URL,
// infra/compose.yaml) requires the token's `iss` claim to be the gateway's own public origin, the
// same rule curl-proof.sh's own `password_grant` comment documents; a token minted straight from
// Keycloak's host-published port carries the wrong issuer and is rejected 401 AUTH_TOKEN_INVALID.
async function mintCatalogProbeToken(
  kcBase: string,
  gatewayBaseURL: string,
  realm: string,
  adminToken: string
): Promise<string> {
  const clientId = "kiban-e2e-catalog-probe";
  const clientSecret = await ensureAudienceClient(kcBase, realm, adminToken, clientId, { serviceAccountsEnabled: true });
  return gatewayTokenGrant(gatewayBaseURL, realm, {
    grant_type: "client_credentials",
    client_id: clientId,
    client_secret: clientSecret,
    scope: "openid"
  });
}

// ensureAudienceClient: idempotent create-or-update of a confidential client carrying the
// "kiban-api" audience mapper every TokenVerifier requires (the realm ships none with
// direct-grant/service-account access AND that audience — see mintCatalogProbeToken). Returns the
// per-run secret. `grant` selects which flow the client allows.
async function ensureAudienceClient(
  kcBase: string,
  realm: string,
  adminToken: string,
  clientId: string,
  grant: { serviceAccountsEnabled: true } | { directAccessGrantsEnabled: true }
): Promise<string> {
  const realmUrl = `${kcBase}/admin/realms/${realm}`;
  const adminHeaders = { authorization: `Bearer ${adminToken}`, "content-type": "application/json" };
  const clientSecret = `${clientId}-${randomBytes(12).toString("hex")}`;

  const clientBody = JSON.stringify({
    clientId,
    enabled: true,
    protocol: "openid-connect",
    publicClient: false,
    secret: clientSecret,
    standardFlowEnabled: false,
    implicitFlowEnabled: false,
    directAccessGrantsEnabled: false,
    serviceAccountsEnabled: false,
    ...grant
  });

  const existingRes = await fetch(`${realmUrl}/clients?clientId=${clientId}`, { headers: adminHeaders });
  if (!existingRes.ok) throw new Error(`e2e global-setup: ${clientId} client lookup -> ${existingRes.status}`);
  const existing = (await existingRes.json()) as Array<{ id: string }>;

  let clientUuid: string;
  if (existing.length === 0) {
    const createRes = await fetch(`${realmUrl}/clients`, { method: "POST", headers: adminHeaders, body: clientBody });
    if (!createRes.ok) throw new Error(`e2e global-setup: ${clientId} client create -> ${createRes.status}`);
    const created = (await fetch(`${realmUrl}/clients?clientId=${clientId}`, { headers: adminHeaders }).then((r) =>
      r.json()
    )) as Array<{ id: string }>;
    clientUuid = created[0]!.id;
  } else {
    clientUuid = existing[0]!.id;
    const updateRes = await fetch(`${realmUrl}/clients/${clientUuid}`, {
      method: "PUT",
      headers: adminHeaders,
      body: clientBody
    });
    if (!updateRes.ok) throw new Error(`e2e global-setup: ${clientId} client update -> ${updateRes.status}`);
  }

  const mappersRes = await fetch(`${realmUrl}/clients/${clientUuid}/protocol-mappers/models`, { headers: adminHeaders });
  if (!mappersRes.ok) throw new Error(`e2e global-setup: ${clientId} mapper lookup -> ${mappersRes.status}`);
  const mappers = (await mappersRes.json()) as Array<{ name: string }>;
  if (!mappers.some((m) => m.name === "kiban-api-audience")) {
    const mapperRes = await fetch(`${realmUrl}/clients/${clientUuid}/protocol-mappers/models`, {
      method: "POST",
      headers: adminHeaders,
      body: JSON.stringify({
        name: "kiban-api-audience",
        protocol: "openid-connect",
        protocolMapper: "oidc-audience-mapper",
        config: { "included.custom.audience": "kiban-api", "access.token.claim": "true", "id.token.claim": "false" }
      })
    });
    if (!mapperRes.ok) throw new Error(`e2e global-setup: ${clientId} mapper create -> ${mapperRes.status}`);
  }
  return clientSecret;
}

// gatewayTokenGrant: a token grant through the GATEWAY's own /auth proxy (never Keycloak's raw
// host port — the issuer rule mintCatalogProbeToken documents), self-signed TLS tolerated for the
// duration of the call only.
async function gatewayTokenGrant(gatewayBaseURL: string, realm: string, form: Record<string, string>): Promise<string> {
  const prevReject = process.env.NODE_TLS_REJECT_UNAUTHORIZED;
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
  let tokenBody: { access_token?: string };
  try {
    const tokenRes = await fetch(`${gatewayBaseURL}/auth/realms/${realm}/protocol/openid-connect/token`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams(form)
    });
    if (!tokenRes.ok) throw new Error(`e2e global-setup: ${form.grant_type} token grant -> ${tokenRes.status}`);
    tokenBody = (await tokenRes.json()) as { access_token?: string };
  } finally {
    if (prevReject === undefined) delete process.env.NODE_TLS_REJECT_UNAUTHORIZED;
    else process.env.NODE_TLS_REJECT_UNAUTHORIZED = prevReject;
  }
  if (!tokenBody.access_token) throw new Error(`e2e global-setup: ${form.grant_type} token grant had no access_token`);
  return tokenBody.access_token;
}

// provisionUserAccount: the identity.user_account row for a plain fixture user comes from the
// SAME path a real first login uses — the gateway resolves a subject through identity on its
// first authenticated request (internal/gateway/provision.go) — never from a direct SQL insert.
// Password-grants as the user through the gateway, makes one RequireAuth-gated
// request (the public catalog read), then reads back the row id the gateway had identity create.
// Returns the identity.user_account.id (uuid, as text).
export async function provisionUserAccount(
  env: Record<string, string>,
  kcBase: string,
  realm: string,
  kcAdminToken: string,
  kcUserId: string,
  username: string,
  password: string
): Promise<string> {
  const gatewayBaseURL = `https://127.0.0.1:${env.KIBAN_GATEWAY_TLS_HOST_PORT ?? "8443"}`;
  const clientId = "kiban-e2e-user-login";
  const clientSecret = await ensureAudienceClient(kcBase, realm, kcAdminToken, clientId, { directAccessGrantsEnabled: true });
  const token = await gatewayTokenGrant(gatewayBaseURL, realm, {
    grant_type: "password",
    client_id: clientId,
    client_secret: clientSecret,
    username,
    password,
    scope: "openid"
  });

  const prevReject = process.env.NODE_TLS_REJECT_UNAUTHORIZED;
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
  try {
    const res = await fetch(`${gatewayBaseURL}/api/platform/catalog`, { headers: { authorization: `Bearer ${token}` } });
    if (!res.ok) throw new Error(`e2e global-setup: provisionUserAccount: first request for ${username} -> ${res.status}`);
  } finally {
    if (prevReject === undefined) delete process.env.NODE_TLS_REJECT_UNAUTHORIZED;
    else process.env.NODE_TLS_REJECT_UNAUTHORIZED = prevReject;
  }

  const userId = psqlScalar(env, `SELECT id FROM identity.user_account WHERE kc_sub = '${kcUserId}'`);
  if (!userId) {
    throw new Error(`e2e global-setup: provisionUserAccount: the gateway did not provision ${username} (kc_sub ${kcUserId})`);
  }
  return userId;
}

// gatewayCatalogHasModule fetches the gateway's own public catalog passthrough
// (internal/gateway/platform_routes.go: `GET /api/platform/catalog`, RequireAuth-gated but not
// superadmin-gated, proxied straight to registry's `internal/registry/http.go` handler —
// this is the one HTTP-observable signal that the GATEWAY itself (not
// just Postgres) has picked the module back up) and reports whether `moduleKey` is present with
// `installed && enabled` true. Response is the standard `{data: [...]}` success envelope
// (web/sdk/src/client.ts). TLS is self-signed on the isolated stack (same
// `ignoreHTTPSErrors: true` posture playwright.config.ts already uses for the browser) — this
// Node-side fetch disables cert verification for the duration of the call only, restoring the
// previous setting immediately after, since this module is imported by config files too
// (evaluated before any test sandboxing exists).
async function gatewayCatalogHasModule(gatewayBaseURL: string, moduleKey: string, accessToken: string): Promise<boolean> {
  const prevReject = process.env.NODE_TLS_REJECT_UNAUTHORIZED;
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
  try {
    const res = await fetch(`${gatewayBaseURL}/api/platform/catalog`, {
      headers: { authorization: `Bearer ${accessToken}` }
    });
    if (!res.ok) return false;
    const body = (await res.json()) as { data?: Array<{ moduleKey: string; installed: boolean; enabled: boolean }> };
    return (body.data ?? []).some((e) => e.moduleKey === moduleKey && e.installed && e.enabled);
  } catch {
    return false;
  } finally {
    if (prevReject === undefined) delete process.env.NODE_TLS_REJECT_UNAUTHORIZED;
    else process.env.NODE_TLS_REJECT_UNAUTHORIZED = prevReject;
  }
}

// convergeModuleRegistration: the module_catalog/module_installation
// rows for the given moduleKeys are registry-owned (its own Seed() step, run at container boot
// from KIBAN_INSTALLED_MODULES=notification,timesheet — cmd/registry/main.go's builtinModules).
// `make check`'s registry dbtest_test.go truncates BOTH tables. Hand-writing those rows here
// would seed through a path that bypasses documented invariants — registry, not this suite,
// owns the catalog/mandatory/
// license-class shape. Converging legitimately means re-running registry's OWN idempotent
// boot path: restart the `registry` container in the kiban-test compose project (never `kiban`,
// the public project — this function only ever runs after loadTestEnv()'s guard has already
// resolved and accepted .env.test) and let its Seed() reseed from the same env it always
// boots with. Cheap no-op skip if every moduleKey is already converged (avoids a restart on
// every run) — ONE registry restart covers every moduleKey this call was given, never one per
// key.
//
// Restarting the registry container is not enough on its own once
// platform.module_installation shows the row — the GATEWAY (what the browser and
// APIRequestContext actually talk to) caches its own catalog snapshot
// (internal/gateway/catalog.go: 5s TTL, single-flight refresh) and, independently, the container
// restart itself briefly perturbs the compose network the gateway's outbound connections to
// registry sit on. A test starting its first gateway request in that window saw
// ERR_NETWORK_CHANGED. So, after the DB rows are confirmed, this also polls the GATEWAY's own
// public catalog passthrough until IT answers with EVERY given moduleKey installed+enabled —
// i.e. until the thing the suites actually talk to is ready, not just the thing registry wrote
// to. `kcBase`/`realm`/`kcAdminToken` are the same Keycloak master-admin session global-setup
// already established for the superadmin password reset, reused here (mintCatalogProbeToken) to
// obtain a throwaway service-account bearer with the "kiban-api" audience the gateway's
// TokenVerifier requires — see mintCatalogProbeToken's own comment for why a client-credentials
// probe client is used instead of the superadmin's own password.
export async function convergeModuleRegistration(
  env: Record<string, string>,
  repoRoot: string,
  kcBase: string,
  realm: string,
  kcAdminToken: string,
  moduleKeys: string[]
): Promise<void> {
  const isRegistered = (moduleKey: string): boolean =>
    psqlScalar(
      env,
      `SELECT count(*) FROM platform.module_installation WHERE module_key = '${moduleKey}' AND installed AND enabled`
    ) !== "0";
  const allRegistered = (): boolean => moduleKeys.every(isRegistered);

  const gatewayBaseURL = `https://127.0.0.1:${env.KIBAN_GATEWAY_TLS_HOST_PORT ?? "8443"}`;
  const probeToken = await mintCatalogProbeToken(kcBase, gatewayBaseURL, realm, kcAdminToken);
  const allInCatalog = async (): Promise<boolean> => {
    for (const moduleKey of moduleKeys) {
      if (!(await gatewayCatalogHasModule(gatewayBaseURL, moduleKey, probeToken))) return false;
    }
    return true;
  };

  if (allRegistered() && (await allInCatalog())) return;

  execFileSync(
    "docker",
    [
      "compose",
      "-p",
      "kiban-test",
      "--env-file",
      ".env.test",
      "-f",
      "infra/compose.yaml",
      "-f",
      "infra/compose.test.yaml",
      "--project-directory",
      "infra",
      "restart",
      "registry"
    ],
    { cwd: repoRoot, stdio: "inherit" }
  );

  const dbDeadline = Date.now() + 30_000;
  while (Date.now() < dbDeadline) {
    if (allRegistered()) break;
    execFileSync("sleep", ["1"]);
  }
  if (!allRegistered()) {
    throw new Error(
      "e2e global-setup: convergeModuleRegistration: platform.module_installation for " +
        `[${moduleKeys.join(", ")}] still not all installed+enabled 30s after restarting the ` +
        "kiban-test registry container — did KIBAN_INSTALLED_MODULES change, or is the registry " +
        "container unhealthy?"
    );
  }

  // The rows exist — now wait for the GATEWAY's own catalog passthrough to reflect
  // ALL of them (closes the ERR_NETWORK_CHANGED window: the first real request no longer races
  // the gateway's post-restart cache refresh / the compose network settling). A SINGLE
  // successful probe here was observed to still be followed, occasionally, by a real browser's
  // very next request against the same gateway failing ("Failed to fetch") a few seconds later —
  // the `docker compose restart` briefly perturbs the whole compose bridge network (not just the
  // registry container's own reachability), so one lucky request doesn't prove the network path
  // has actually settled. Requiring `requiredConsecutive` successive all-modules-present
  // successes, spaced apart, before declaring readiness gives real settle time instead of racing
  // the first response back.
  const requiredConsecutive = 3;
  let consecutiveSuccesses = 0;
  const gatewayDeadline = Date.now() + 30_000;
  while (Date.now() < gatewayDeadline) {
    if (await allInCatalog()) {
      consecutiveSuccesses++;
      if (consecutiveSuccesses >= requiredConsecutive) return;
    } else {
      consecutiveSuccesses = 0;
    }
    await new Promise((resolve) => setTimeout(resolve, 1000));
  }
  throw new Error(
    "e2e global-setup: convergeModuleRegistration: platform.module_installation shows " +
      `[${moduleKeys.join(", ")}] installed+enabled, but the gateway's own GET ` +
      "/api/platform/catalog still did not reflect that for all of them 30s after the registry " +
      "restart — is the kiban-test gateway container unhealthy, or is its catalog cache stuck?"
  );
}
