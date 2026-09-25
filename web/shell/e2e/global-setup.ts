// SPDX-License-Identifier: Apache-2.0

// Playwright globalSetup: prepares the seeded superadmin for a real browser login against the
// ISOLATED `kiban-test` stack (`make test-stack-up`, .env.test; never
// .env's live/public stack, see ../../e2e-shared/env.ts's loadTestEnv — the
// single shared copy both suites import). Mirrors
// web/sdk/e2e/global-setup.ts's steps 1-2 (Keycloak master-admin
// token, clear the superadmin's forced temp-password requiredAction, set a fresh throwaway
// password for this run only).
//
// It also creates a company + an org member linking it to the superadmin
// (org.org_unit / org.member, direct `psql`, same technique modules/notification/curl-proof.sh
// already uses) — org has no gateway-mounted company/member-create route (only
// `GET /api/org/me/companies` is exposed), so this is test-fixture plumbing, not something the
// notification module itself needed. Without it the superadmin has no company membership at all,
// so the company-scoped notification module could never appear in the nav (compose.ts's
// `computeNavEntries` requires `activeCompanyId` to be set from a real membership).
//
// Additional fixture identities: timesheet.spec.ts's journey needs a distinct
// logged-in submitter alongside the superadmin (who acts as admin/approver — the default
// module-access grant gives it company_module#admin for any enabled module in this fixture company, no
// extra wiring needed for that half). A plain (non-superadmin) Keycloak user does not pre-exist
// the way the superadmin does, so this file now CREATES one (idempotently — `ensureKeycloakUser`)
// rather than only resetting an existing user's password.
import { randomBytes } from "node:crypto";
import { fileURLToPath } from "node:url";
import path from "node:path";
import {
  loadTestEnv,
  convergeSuperadminIdentity,
  provisionUserAccount,
  convergeModuleRegistration,
  ensureKeycloakUser,
  psqlScalar,
  psqlExec
} from "../../e2e-shared/env.js";

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

  const superadminPassword = `e2e-shell-${randomToken()}`;
  await adminFetch(kcBase, token, `${realmUrl}/users/${superadminId}`, {
    method: "PUT",
    body: JSON.stringify({ requiredActions: [] })
  });
  await adminFetch(kcBase, token, `${realmUrl}/users/${superadminId}/reset-password`, {
    method: "PUT",
    body: JSON.stringify({ type: "password", value: superadminPassword, temporary: false })
  });

  process.env.KIBAN_E2E_SUPERADMIN_USERNAME = superadminUsername;
  process.env.KIBAN_E2E_SUPERADMIN_PASSWORD = superadminPassword;

  // `make check`'s dbtest truncation (internal/identity/dbtest_test.go,
  // internal/org/dbtest_test.go) wipes identity.user_account between runs — this
  // suite must converge them itself instead of assuming a prior bootstrap run's (or the sdk
  // suite's own global-setup, which may have already run this exact call) rows survived. Mirrors
  // internal/bootstrap's SuperadminStep/SeedSuperadmin. Idempotent: a second
  // call with the same kc_sub is a no-op past the first INSERT/grant.
  const userRowId = convergeSuperadminIdentity(env, superadminId, users[0]?.email, superadminUsername);

  // notification.spec.ts AND timesheet.spec.ts need their own modules actually
  // registered+enabled — those rows are registry-owned (its own boot Seed(), from
  // KIBAN_INSTALLED_MODULES=notification,timesheet) and are also wiped by `make check`'s
  // registry dbtest_test.go truncation. Converge via registry's own idempotent re-seed path
  // (ONE container restart in the kiban-test project covers both keys), never by hand-writing
  // either row here (registry owns them). Also waits for the GATEWAY's own
  // catalog passthrough to answer, for BOTH module keys, before returning (closes the
  // ERR_NETWORK_CHANGED flake window) — reuses this same Keycloak master-admin session
  // (kcBase/realm/token) to mint its own throwaway probe token.
  await convergeModuleRegistration(env, repoRoot, kcBase, realm, token, ["notification", "timesheet", "docs", "helpdesk"]);

  // Company + member fixture — idempotent create-or-reuse, same posture as every
  // other fixture in this file and in curl-proof.sh. Reused by timesheet.spec.ts
  // rather than a second company: the superadmin is already an active member here, and the
  // default module-access grant (below) already covers any enabled module for this company, so a
  // second fixture identity only needs its OWN org.member row in the SAME company.
  let companyId = psqlScalar(env, `SELECT id FROM org.org_unit WHERE code = 'SHELLE2E' AND parent_id IS NULL`);
  if (!companyId) {
    companyId = psqlScalar(
      env,
      `INSERT INTO org.org_unit (type_key, parent_id, code, name, is_active)
       VALUES ('company', NULL, 'SHELLE2E', 'Shell E2E Co', true)
       RETURNING id`
    );
  }
  const superadminMemberId = psqlScalar(
    env,
    `INSERT INTO org.member (company_id, code, display_name, user_id, is_active)
     VALUES ('${companyId}', 'SUPERADMIN', 'Superadmin', '${userRowId}', true)
     ON CONFLICT (company_id, code) DO UPDATE SET user_id = EXCLUDED.user_id, is_active = true
     RETURNING id`
  );

  // The default module-access grant (`company_module:<companyId>/<moduleKey>#system @
  // system:platform`) is written by three PRODUCTION hooks (bootstrap's converge step, registry's
  // Seed/SetEnabled, org's own company-creation path) — none of which this company passes
  // through: it is fixture-created by direct SQL above (org has no gateway-mounted
  // company/member-create route), the expected gap for any company that comes into being
  // outside org's production API.
  // Mirrors authz/store.EnsureDefaultGrant's own two writes (the tuple + the default_grant
  // bookkeeping claim) as fixture plumbing, same posture as the company/member rows immediately
  // above — never how the real code paths grant this (application code never does a raw
  // INSERT; this is test fixture setup, not application code). It also covers
  // 'timesheet' — timesheet.spec.ts's admin actions (create project, assign approver) are
  // gated on company_module#admin, which only resolves for the superadmin once this exists for
  // the timesheet module key specifically (the base-model resolution chain).
  for (const moduleKey of ["notification", "timesheet", "docs", "helpdesk"]) {
    psqlExec(
      env,
      `INSERT INTO authz.default_grant (company_id, module_key, actor)
       VALUES ('${companyId}', '${moduleKey}', 'e2e-fixture')
       ON CONFLICT (company_id, module_key) DO NOTHING`
    );
    psqlExec(
      env,
      `INSERT INTO authz.tuple (object_type, object_id, relation, subject_type, subject_id)
       VALUES ('company_module', '${companyId}/${moduleKey}', 'system', 'system', 'platform')
       ON CONFLICT DO NOTHING`
    );
  }

  process.env.KIBAN_E2E_COMPANY_ID = companyId;
  process.env.KIBAN_E2E_SUPERADMIN_MEMBER_ID = superadminMemberId;

  // company-switch.spec.ts's own SECOND company — the superadmin needs an
  // active membership in TWO companies to prove switching refetches module data/capabilities
  // rather than serving stale cross-company state. Same idempotent create-or-reuse shape as the
  // first company fixture above, distinct code so re-runs never collide with it, and the SAME
  // default-grant/company_module#system fixture wiring (docs only — company-switch.spec.ts only
  // needs one company-scoped module present in both companies to prove the refetch, and docs's
  // per-document authorization means no company-admin tuple is needed for its own read/create
  // paths beyond the membership-gated create check).
  let secondCompanyId = psqlScalar(env, `SELECT id FROM org.org_unit WHERE code = 'SHELLE2E2' AND parent_id IS NULL`);
  if (!secondCompanyId) {
    secondCompanyId = psqlScalar(
      env,
      `INSERT INTO org.org_unit (type_key, parent_id, code, name, is_active)
       VALUES ('company', NULL, 'SHELLE2E2', 'Shell E2E Second Co', true)
       RETURNING id`
    );
  }
  psqlExec(
    env,
    `INSERT INTO org.member (company_id, code, display_name, user_id, is_active)
     VALUES ('${secondCompanyId}', 'SUPERADMIN', 'Superadmin', '${userRowId}', true)
     ON CONFLICT (company_id, code) DO UPDATE SET user_id = EXCLUDED.user_id, is_active = true`
  );
  for (const moduleKey of ["docs"]) {
    psqlExec(
      env,
      `INSERT INTO authz.default_grant (company_id, module_key, actor)
       VALUES ('${secondCompanyId}', '${moduleKey}', 'e2e-fixture')
       ON CONFLICT (company_id, module_key) DO NOTHING`
    );
    psqlExec(
      env,
      `INSERT INTO authz.tuple (object_type, object_id, relation, subject_type, subject_id)
       VALUES ('company_module', '${secondCompanyId}/${moduleKey}', 'system', 'system', 'platform')
       ON CONFLICT DO NOTHING`
    );
  }
  process.env.KIBAN_E2E_SECOND_COMPANY_ID = secondCompanyId;

  // A second fixture identity — timesheet.spec.ts's own submitter, distinct from the
  // superadmin (who acts as admin/approver in that spec). Does NOT pre-exist the way the
  // superadmin does (bootstrap only ever seeds the one superadmin), so this CREATES the
  // Keycloak user (idempotently) rather than only resetting an existing one's password.
  const timesheetMemberUsername = "e2e-timesheet-member";
  const { kcUserId: timesheetMemberKcSub, password: timesheetMemberPassword } = await ensureKeycloakUser(
    kcBase,
    realm,
    token,
    timesheetMemberUsername,
    `${timesheetMemberUsername}@kiban.local`
  );
  const timesheetMemberUserRowId = await provisionUserAccount(
    env,
    kcBase,
    realm,
    token,
    timesheetMemberKcSub,
    timesheetMemberUsername,
    timesheetMemberPassword
  );
  const timesheetMemberId = psqlScalar(
    env,
    `INSERT INTO org.member (company_id, code, display_name, user_id, is_active)
     VALUES ('${companyId}', 'E2ETSMEMBER', 'E2E Timesheet Member', '${timesheetMemberUserRowId}', true)
     ON CONFLICT (company_id, code) DO UPDATE SET user_id = EXCLUDED.user_id, is_active = true
     RETURNING id`
  );

  process.env.KIBAN_E2E_TIMESHEET_MEMBER_USERNAME = timesheetMemberUsername;
  process.env.KIBAN_E2E_TIMESHEET_MEMBER_PASSWORD = timesheetMemberPassword;
  process.env.KIBAN_E2E_TIMESHEET_MEMBER_ID = timesheetMemberId;

  // docs.spec.ts's own SECOND identity — its two-identity Playwright journey
  // (create as the superadmin/owner, share, then read/edit/lose-access as a second, DISTINCT
  // logged-in member). Same shape as the timesheet member fixture immediately above: a plain
  // (non-superadmin) Keycloak user, created idempotently, with its own org.member row in the SAME
  // fixture company (no company_module#admin needed — docs authorization is per-document, never
  // company-admin-gated; see modules/docs/authz.fragment.json's own _comment on the deliberate
  // absence of a tupleToUserset bridge from viewer/editor to company_module).
  const docsMemberUsername = "e2e-docs-member";
  const { kcUserId: docsMemberKcSub, password: docsMemberPassword } = await ensureKeycloakUser(
    kcBase,
    realm,
    token,
    docsMemberUsername,
    `${docsMemberUsername}@kiban.local`
  );
  const docsMemberUserRowId = await provisionUserAccount(env, kcBase, realm, token, docsMemberKcSub, docsMemberUsername, docsMemberPassword);
  const docsMemberId = psqlScalar(
    env,
    `INSERT INTO org.member (company_id, code, display_name, user_id, is_active)
     VALUES ('${companyId}', 'E2EDOCSMEMBER', 'E2E Docs Member', '${docsMemberUserRowId}', true)
     ON CONFLICT (company_id, code) DO UPDATE SET user_id = EXCLUDED.user_id, is_active = true
     RETURNING id`
  );

  process.env.KIBAN_E2E_DOCS_MEMBER_USERNAME = docsMemberUsername;
  process.env.KIBAN_E2E_DOCS_MEMBER_PASSWORD = docsMemberPassword;
  process.env.KIBAN_E2E_DOCS_MEMBER_ID = docsMemberId;

  // helpdesk.spec.ts's own THREE-identity journey (reporter raises -> admin assigns to
  // agent -> agent progresses/resolves -> reporter comments+reopens -> agent re-resolves ->
  // reporter closes). The superadmin plays admin (company_module#admin already resolves via the
  // default grant above, extended to 'helpdesk'); this needs two MORE distinct, non-superadmin
  // identities — a reporter (a plain member, never granted the agent tier) and an agent-to-be (a
  // plain member at fixture-setup time; the workflow's own assign action is what grants them the
  // agent tier mid-test, proving the auto-grant live rather than pre-seeding it). Same shape as
  // the timesheet/docs member fixtures above: plain Keycloak users, created idempotently, with
  // their own org.member rows in the SAME fixture company.
  const helpdeskReporterUsername = "e2e-helpdesk-reporter";
  const { kcUserId: helpdeskReporterKcSub, password: helpdeskReporterPassword } = await ensureKeycloakUser(
    kcBase,
    realm,
    token,
    helpdeskReporterUsername,
    `${helpdeskReporterUsername}@kiban.local`
  );
  const helpdeskReporterUserRowId = await provisionUserAccount(
    env,
    kcBase,
    realm,
    token,
    helpdeskReporterKcSub,
    helpdeskReporterUsername,
    helpdeskReporterPassword
  );
  const helpdeskReporterMemberId = psqlScalar(
    env,
    `INSERT INTO org.member (company_id, code, display_name, user_id, is_active)
     VALUES ('${companyId}', 'E2EHDREPORTER', 'E2E Helpdesk Reporter', '${helpdeskReporterUserRowId}', true)
     ON CONFLICT (company_id, code) DO UPDATE SET user_id = EXCLUDED.user_id, is_active = true
     RETURNING id`
  );

  process.env.KIBAN_E2E_HELPDESK_REPORTER_USERNAME = helpdeskReporterUsername;
  process.env.KIBAN_E2E_HELPDESK_REPORTER_PASSWORD = helpdeskReporterPassword;
  process.env.KIBAN_E2E_HELPDESK_REPORTER_ID = helpdeskReporterMemberId;

  // walkthrough.spec.ts's steps 4 and 6 make THESE two identities (not just the
  // position-holder-A/B pair below) actually hold a position — the same
  // `member:<memberId>#mapped_user @ user:<kcSub>` bridge tuple the
  // position-holder fixtures below already write for themselves is written here too, for the
  // exact same reason (this fixture links user_id by raw SQL, never through org.Store.LinkUser,
  // so nothing else writes it). Idempotent (ON CONFLICT DO NOTHING), safe to re-run. Without
  // this, the object-mode `position:<id>#holder @ user:<kcSub>` check (AuthzClient.
  // IsPositionHolder) fails even though org's own holder-on-date read (display only) resolves
  // correctly — the "member linked before the tuple-writing code path existed" gap.
  psqlExec(
    env,
    `INSERT INTO authz.tuple (object_type, object_id, relation, subject_type, subject_id, subject_relation)
     VALUES ('member', '${helpdeskReporterMemberId}', 'mapped_user', 'user', '${helpdeskReporterKcSub}', '')
     ON CONFLICT DO NOTHING`
  );

  const helpdeskAgentUsername = "e2e-helpdesk-agent";
  const { kcUserId: helpdeskAgentKcSub, password: helpdeskAgentPassword } = await ensureKeycloakUser(
    kcBase,
    realm,
    token,
    helpdeskAgentUsername,
    `${helpdeskAgentUsername}@kiban.local`
  );
  const helpdeskAgentUserRowId = await provisionUserAccount(env, kcBase, realm, token, helpdeskAgentKcSub, helpdeskAgentUsername, helpdeskAgentPassword);
  const helpdeskAgentMemberId = psqlScalar(
    env,
    `INSERT INTO org.member (company_id, code, display_name, user_id, is_active)
     VALUES ('${companyId}', 'E2EHDAGENT', 'E2E Helpdesk Agent', '${helpdeskAgentUserRowId}', true)
     ON CONFLICT (company_id, code) DO UPDATE SET user_id = EXCLUDED.user_id, is_active = true
     RETURNING id`
  );

  process.env.KIBAN_E2E_HELPDESK_AGENT_USERNAME = helpdeskAgentUsername;
  process.env.KIBAN_E2E_HELPDESK_AGENT_PASSWORD = helpdeskAgentPassword;
  process.env.KIBAN_E2E_HELPDESK_AGENT_ID = helpdeskAgentMemberId;

  // Same bridge-tuple fix as above, for the agent identity (alice).
  psqlExec(
    env,
    `INSERT INTO authz.tuple (object_type, object_id, relation, subject_type, subject_id, subject_relation)
     VALUES ('member', '${helpdeskAgentMemberId}', 'mapped_user', 'user', '${helpdeskAgentKcSub}', '')
     ON CONFLICT DO NOTHING`
  );

  // position-access.spec.ts's own TWO successive holders of one bound position —
  // plain members, never directly granted the agent tier (the whole point: they gain/lose it
  // ONLY by holding the position). Same shape as every other member fixture above, PLUS the
  // `member:<memberId>#mapped_user @ user:<kcSub>` bridge tuple written
  // directly here: this fixture creates the org.member row's user_id link by raw SQL (like every
  // other fixture member above), never through org.Store.LinkUser (org has no gateway-mounted
  // link-user route — same "org has no external create route" gap this file's header already
  // documents), so nothing else writes that tuple for these two rows. Idempotent
  // (ON CONFLICT DO NOTHING), safe to re-run.
  for (const [suffix, code] of [
    ["a", "E2EPOSHOLDERA"],
    ["b", "E2EPOSHOLDERB"]
  ] as const) {
    const username = `e2e-position-holder-${suffix}`;
    const { kcUserId, password } = await ensureKeycloakUser(kcBase, realm, token, username, `${username}@kiban.local`);
    const userRowId = await provisionUserAccount(env, kcBase, realm, token, kcUserId, username, password);
    const memberId = psqlScalar(
      env,
      `INSERT INTO org.member (company_id, code, display_name, user_id, is_active)
       VALUES ('${companyId}', '${code}', 'E2E Position Holder ${suffix.toUpperCase()}', '${userRowId}', true)
       ON CONFLICT (company_id, code) DO UPDATE SET user_id = EXCLUDED.user_id, is_active = true
       RETURNING id`
    );
    psqlExec(
      env,
      `INSERT INTO authz.tuple (object_type, object_id, relation, subject_type, subject_id, subject_relation)
       VALUES ('member', '${memberId}', 'mapped_user', 'user', '${kcUserId}', '')
       ON CONFLICT DO NOTHING`
    );
    const envPrefix = `KIBAN_E2E_POSITION_HOLDER_${suffix.toUpperCase()}`;
    process.env[`${envPrefix}_USERNAME`] = username;
    process.env[`${envPrefix}_PASSWORD`] = password;
    process.env[`${envPrefix}_ID`] = memberId;
    process.env[`${envPrefix}_KCSUB`] = kcUserId;
  }

  // groups.spec.ts's own TWO group members — plain members, never directly granted the
  // agent tier (the whole point: they gain it ONLY by group membership, and lose it ONLY by
  // removal from the group). Deliberately DISTINCT from KIBAN_E2E_POSITION_HOLDER_{A,B} above
  // (same shape, but a different fixture identity) so the two e2e specs can run independently
  // without one spec's own position/agent-binding cleanup racing the other's group membership.
  // Same shape as every other member fixture above, PLUS the `member:<memberId>#mapped_user @
  // user:<kcSub>` bridge tuple written directly here, for the same reason as
  // every other fixture in this file (org has no gateway-mounted link-user route).
  for (const [suffix, code] of [
    ["a", "E2EGROUPMEMBERA"],
    ["b", "E2EGROUPMEMBERB"]
  ] as const) {
    const username = `e2e-group-member-${suffix}`;
    const { kcUserId, password } = await ensureKeycloakUser(kcBase, realm, token, username, `${username}@kiban.local`);
    const userRowId = await provisionUserAccount(env, kcBase, realm, token, kcUserId, username, password);
    const memberId = psqlScalar(
      env,
      `INSERT INTO org.member (company_id, code, display_name, user_id, is_active)
       VALUES ('${companyId}', '${code}', 'E2E Group Member ${suffix.toUpperCase()}', '${userRowId}', true)
       ON CONFLICT (company_id, code) DO UPDATE SET user_id = EXCLUDED.user_id, is_active = true
       RETURNING id`
    );
    psqlExec(
      env,
      `INSERT INTO authz.tuple (object_type, object_id, relation, subject_type, subject_id, subject_relation)
       VALUES ('member', '${memberId}', 'mapped_user', 'user', '${kcUserId}', '')
       ON CONFLICT DO NOTHING`
    );
    const envPrefix = `KIBAN_E2E_GROUP_MEMBER_${suffix.toUpperCase()}`;
    process.env[`${envPrefix}_USERNAME`] = username;
    process.env[`${envPrefix}_PASSWORD`] = password;
    process.env[`${envPrefix}_ID`] = memberId;
    process.env[`${envPrefix}_KCSUB`] = kcUserId;
  }

  // tier-contrast.spec.ts's own THREE non-superadmin fixture identities, all in
  // the SAME fixture company as the superadmin (KIBAN_E2E_COMPANY_ID) — the sweep compares
  // superadmin / company-admin / agent / plain-member across the SAME pages/actions, so all four
  // tiers need to share one company. Grants are direct `company_module#<relation> @ user:<kcSub>`
  // tuples (internal/authz/harness/model.fga: `company_module`'s `admin`/`editor` relations both
  // accept a bare `[user]` leg, alongside `admin from company`/`superadmin from system` — the
  // SAME shape the default module-access grant uses for `system:platform`, just scoped to one
  // identity's own kc_sub instead), never through org.Store or any admin-facing grant endpoint
  // (there is no external company-admin-designation API yet). Deliberately distinct from
  // KIBAN_E2E_HELPDESK_AGENT above (that fixture starts as
  // a plain member and gains the agent tier live, mid-spec, via helpdesk.spec.ts's own assign
  // action) — tier-contrast needs a STANDING agent identity to sweep against, not one whose tier
  // changes during the run.
  //   - tierAdmin: company_module#admin for BOTH helpdesk and docs (the "helpdesk admin
  //     (company_module#admin)" tier) — company-admin, NOT platform
  //     superadmin (no `system:platform#superadmin` tuple).
  //   - tierAgent: company_module#editor for helpdesk ONLY (helpdesk's own agent tier,
  //     authz.fragment.json's `helpdesk.tickets.work` -> `company_module#editor`) — plain member
  //     for docs (docs has no equivalent "agent" tier).
  //   - tierMember: no relation grants at all beyond the org.member row itself — the company-
  //     membership-gated baseline (docs.create/helpdesk.tickets.create's own empty
  //     accessRulePayload) is all this identity ever gets.
  const tierAdminUsername = "e2e-tier-admin";
  const { kcUserId: tierAdminKcSub, password: tierAdminPassword } = await ensureKeycloakUser(
    kcBase,
    realm,
    token,
    tierAdminUsername,
    `${tierAdminUsername}@kiban.local`
  );
  const tierAdminUserRowId = await provisionUserAccount(env, kcBase, realm, token, tierAdminKcSub, tierAdminUsername, tierAdminPassword);
  psqlExec(
    env,
    `INSERT INTO org.member (company_id, code, display_name, user_id, is_active)
     VALUES ('${companyId}', 'E2ETIERADMIN', 'E2E Tier Admin', '${tierAdminUserRowId}', true)
     ON CONFLICT (company_id, code) DO UPDATE SET user_id = EXCLUDED.user_id, is_active = true`
  );
  for (const moduleKey of ["helpdesk", "docs"]) {
    psqlExec(
      env,
      `INSERT INTO authz.tuple (object_type, object_id, relation, subject_type, subject_id)
       VALUES ('company_module', '${companyId}/${moduleKey}', 'admin', 'user', '${tierAdminKcSub}')
       ON CONFLICT DO NOTHING`
    );
  }
  process.env.KIBAN_E2E_TIER_ADMIN_USERNAME = tierAdminUsername;
  process.env.KIBAN_E2E_TIER_ADMIN_PASSWORD = tierAdminPassword;

  const tierAgentUsername = "e2e-tier-agent";
  const { kcUserId: tierAgentKcSub, password: tierAgentPassword } = await ensureKeycloakUser(
    kcBase,
    realm,
    token,
    tierAgentUsername,
    `${tierAgentUsername}@kiban.local`
  );
  const tierAgentUserRowId = await provisionUserAccount(env, kcBase, realm, token, tierAgentKcSub, tierAgentUsername, tierAgentPassword);
  psqlExec(
    env,
    `INSERT INTO org.member (company_id, code, display_name, user_id, is_active)
     VALUES ('${companyId}', 'E2ETIERAGENT', 'E2E Tier Agent', '${tierAgentUserRowId}', true)
     ON CONFLICT (company_id, code) DO UPDATE SET user_id = EXCLUDED.user_id, is_active = true`
  );
  psqlExec(
    env,
    `INSERT INTO authz.tuple (object_type, object_id, relation, subject_type, subject_id)
     VALUES ('company_module', '${companyId}/helpdesk', 'editor', 'user', '${tierAgentKcSub}')
     ON CONFLICT DO NOTHING`
  );
  process.env.KIBAN_E2E_TIER_AGENT_USERNAME = tierAgentUsername;
  process.env.KIBAN_E2E_TIER_AGENT_PASSWORD = tierAgentPassword;

  const tierMemberUsername = "e2e-tier-member";
  const { kcUserId: tierMemberKcSub, password: tierMemberPassword } = await ensureKeycloakUser(
    kcBase,
    realm,
    token,
    tierMemberUsername,
    `${tierMemberUsername}@kiban.local`
  );
  const tierMemberUserRowId = await provisionUserAccount(env, kcBase, realm, token, tierMemberKcSub, tierMemberUsername, tierMemberPassword);
  psqlExec(
    env,
    `INSERT INTO org.member (company_id, code, display_name, user_id, is_active)
     VALUES ('${companyId}', 'E2ETIERMEMBER', 'E2E Tier Member', '${tierMemberUserRowId}', true)
     ON CONFLICT (company_id, code) DO UPDATE SET user_id = EXCLUDED.user_id, is_active = true`
  );
  process.env.KIBAN_E2E_TIER_MEMBER_USERNAME = tierMemberUsername;
  process.env.KIBAN_E2E_TIER_MEMBER_PASSWORD = tierMemberPassword;

  // first-login.spec.ts's identity: a Keycloak user and NOTHING else — no identity row (the
  // gateway provisions it on the first authenticated request), no org.member row
  // (the spec adds it mid-test). Recreated fresh every run so its kc_sub has never been seen by
  // Kiban: a real first login, not a replay.
  const firstLoginUsername = "e2e-first-login";
  const { kcUserId: firstLoginKcSub, password: firstLoginPassword } = await ensureKeycloakUser(
    kcBase,
    realm,
    token,
    firstLoginUsername,
    `${firstLoginUsername}@kiban.local`,
    { fresh: true }
  );
  process.env.KIBAN_E2E_FIRST_LOGIN_USERNAME = firstLoginUsername;
  process.env.KIBAN_E2E_FIRST_LOGIN_PASSWORD = firstLoginPassword;
  process.env.KIBAN_E2E_FIRST_LOGIN_KCSUB = firstLoginKcSub;
}
