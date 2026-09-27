// Fixed test-stack config for the e2e harness. Mirrors infra/e2e-login.sh: hardcoded to the
// known topology (the `kiban` realm, the `kiban-frontend` client) EXCEPT gatewayOrigin's port,
// which static-server.mjs's serveConfigJs() rewrites at serve time from
// KIBAN_GATEWAY_TLS_HOST_PORT (the isolated kiban-test stack's port, never .env's live
// one); the literal
// below is the substitution target/fallback only. Not shipped in the published package (this
// file lives under e2e/, excluded from src/'s tsup build).
export const HARNESS_CONFIG = {
  gatewayOrigin: "https://127.0.0.1:8443",
  realm: "kiban",
  clientId: "kiban-frontend",
  redirectUri: "http://localhost:5173/callback.html",
  // Distinct from infra/e2e-login.sh's `kiban_e2e_fake` fixture key so the two suites never
  // fight over the same catalog row when run against the same `make dev` stack.
  fixtureModuleKey: "kiban_e2e_sdk_fixture",
  // Fixture company/object/subject for the grantObjectAccess/revokeObjectAccess recipe proof.
  // The grants route binds every tuple to a company and one enabled module (authz's
  // handleGrants), so the object type is one the docs module's fragment declares and the
  // company is the one global-setup.ts creates (looked up by code via org.meCompanies(), the
  // superadmin being a member). authz.tuple carries no FK to Keycloak
  // (migrations/authz/0002_authz_tables.sql — plain text columns), so an arbitrary,
  // never-registered subjectId is a valid, safe-to-toggle target — no second Keycloak user
  // fixture needed.
  fixtureCompanyCode: "SDKE2E",
  fixtureGrantModuleKey: "docs",
  fixtureGrantObject: { objectType: "docs_document", objectId: "kiban-sdk-e2e-fixture-doc" },
  fixtureGrantSubjectId: "kiban-sdk-e2e-grant-target"
};
