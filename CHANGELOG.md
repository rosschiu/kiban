# Changelog

All notable changes to Kiban are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and versioning follows
[Semantic Versioning](https://semver.org/).

The current version is in the root [`VERSION`](VERSION) file, which every build stamps into
`kiban_build_info{version,commit}`.

## [Unreleased]

Nothing yet.

## [0.1.0] — 2026-09-25

The first release: a version a developer can clone, deploy with one command, log into, and build
against using the documentation alone.

### Foundation

- **Identity**: embedded Keycloak (OpenID Connect with PKCE, MFA policy per user with
  authenticator app or passkey), synced to a Postgres identity store; a bootstrap flow that seeds
  the superadmin once and delivers the initial password as a 0600 file, never an environment
  variable.
- **Organization**: org-unit tree, members, positions and groups, with the company as the sole
  authorization anchor; database-enforced integrity (cross-company facts are unrepresentable,
  concurrent writes are serialized, `company_id` is immutable).
- **Authorization**: a Postgres-native Zanzibar-subset engine (relation tuples plus a declarative
  model), differential-tested against OpenFGA. Modules ship an authorization fragment that
  references the platform base model but never redefines it; a disabled module's fragment is
  inert.
- **Audit**: every mutation writes its audit event in the same transaction, per service, into
  append-only `audit.*` tables. Audit is part of the foundation, never a paid add-on.
- **Module runtime**: modules are self-contained contracts (manifest, authorization fragment,
  versioned OpenAPI file, checksummed migrations, optional frontend manifest), validated in CI
  (`make validate-modules`), installed by the registry, routed by a version-blind gateway, and
  surfaced by an SDK-driven sample shell. Adding a module needs no gateway or shell code changes;
  it still needs a database role migration and a Compose service entry.
- **Gateway**: a single origin for development and deployment, with TLS from operator
  certificates (a self-signed pair in development) or a reverse proxy in front.

### Sample modules

Four modules built through the same contract, with no contract changes:

- **`notification`**: channels, subscriptions, in-app inbox, email and webhook delivery with
  leased jobs and at-least-once delivery.
- **`docs`** (DocShare): shared files with per-file viewer and editor sharing as live
  authorization tuples, including grant, revoke, a visible audit trail, and superadmin
  excludability.
- **`helpdesk`**: tickets, comments, a status workflow, and assignment to a member, a position,
  or a group, with member, agent and admin tiers.
- **`timesheet`**: projects, weekly entries, versioned submissions, and an assigned-approver
  workflow. Ported from an earlier application with no contract changes; disabled on the public
  demo.

### Position- and group-based access

- **Position-based access**: rights bind to a position on the org chart. Whoever holds the
  position has the access, transactionally following assignment changes; a successor inherits it
  with zero permission edits. Proven end to end at the engine and in the browser.
- **Group-based access**: rights bind to a named set of members. Every current member has the
  access, following membership changes with zero permission edits. Groups are source-aware:
  Kiban-native by default, with a single authoritative writer per group.

### Test assurance

A test-hardening pass across the platform: coverage ratchet gates in `make check` (39 scopes at
release; minimums only rise), OpenAPI response validation, standardized idempotency-conflict
semantics across every module's effectful writes, decision-path regression coverage, and the
OpenFGA differential harness kept green throughout.

### Release hygiene

- One licence for the whole tree: Apache-2.0, copyright Ross Chiu, in every `LICENSE` file,
  SPDX header and module manifest, with a root `NOTICE`. See [`LICENSING.md`](LICENSING.md).
- SPDX headers on every first-party source file, enforced by `make license-check`. The module
  validator rejects a module whose manifest licence class and `LICENSE` file disagree.
- A third-party dependency licence scan (`make license-scan`) for Go and npm; no
  copyleft-incompatible dependency found. See [`THIRD-PARTY-LICENSES.md`](THIRD-PARTY-LICENSES.md).
- A full git-history secret scan with no live secrets found, kept as a gate
  (`make secret-scan`).
- The module contract frozen as v1; every module manifest declares `version: "0.1.0"`.

### Not in this release

OpenTelemetry traces, general UI polish, commercial licence enforcement, Entra ID and other SSO
federation, and mixed-source group membership. See the documentation's Known limitations page.

### Security
- Gateway responses carry `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`,
  `Strict-Transport-Security` (TLS) and the shell is served with an enforced
  Content-Security-Policy. Over-limit bodies are `413 PAYLOAD_TOO_LARGE`. The Keycloak proxy
  pins `Host` to the issuer origin; an unknown signing key triggers one JWKS refetch; every
  proxy sets `X-Forwarded-For` from the edge's view.
- Identity and bootstrap read the Keycloak client secret and admin password from `_FILE`
  mounts; a per-user MFA override can only raise the requirement; the realm's direct-grant
  flow runs the MFA-setup authenticator, so no password-grant client bypasses it.
- The migration validator parses statements (no `public` allowlist, no shared-function
  replacement, no `SECURITY DEFINER`, no role grants beyond the module's own role) and a
  ledger lists every shipped migration, including the four foundation trees
  (`make validate-migrations`).
- Foundation audit tables refuse `TRUNCATE`; every audit row carries the request correlation
  id; a definite authorization denial on an admin route is a 403 audited with its reason.
- The platform role has one record: the `system:platform#superadmin` tuple. Grant and revoke
  are authz operations (`POST/DELETE /api/platform/admin/platform-roles…`), effective
  immediately; the last superadmin cannot be revoked. `identity.platform_role` is dropped after
  a backfill migration.
- Application containers run as uid 65532 with a read-only root filesystem, all capabilities
  dropped and no privilege escalation, in Compose and in the Kubernetes template.
- Postgres roles: `kiban` is the non-superuser owner of the application database and runs the
  migrations and bootstrap; `keycloak` owns the Keycloak database; the superuser
  (`POSTGRES_USER`, default `postgres`) is used only at initialisation. New secrets
  `KIBAN_DB_PASSWORD` and `KC_DB_PASSWORD`. **Stacks created before this change must be
  recreated** (`make dev-clean && make dev`, or dump and restore into a fresh cluster).
- Every object check in the effective-access API is bound to the request's company: `company`
  and `company_module` objects by id, positions and groups through their company, module
  objects through the `company_module` anchor tuple their module writes at creation. An object
  from another company is denied (`ENGINE_DENIED`, evidence `objectCompany=false`).
- `POST /internal/authz/grants` requires `companyId`, accepts only tuples on a module's own
  object types (or that module's `company_module`), checks the anchor, requires the bearer to
  pass the company-scope decision for that module, and requires `company_module#admin` for
  module-tier tuples. Base-model tuples cannot be written through it.
- The Keycloak admin console and the master realm are not reachable through the gateway.
- Bootstrap manages realm brute-force protection and the password policy
  `length(12) and notUsername and notEmail`.
- The docs sample module's module-wide audit view (`GET …/companies/{companyId}/audit`) now
  returns only that company's events. Every docs audit event carries `companyId`; migration
  `0005` backfills existing rows from their document.
- Locally built images no longer include `infra/demo-golden/` database dumps, Kubernetes
  `secret.yaml` files or the documentation trees.

### Changed
- The project home is `github.com/rosschiu/kiban`. The Go module path is
  `github.com/rosschiu/kiban`, the SDK package is `@rosschiu/kiban-sdk`, images are
  `ghcr.io/rosschiu/kiban-*` and the documentation site is `https://rosschiu.github.io/kiban/`.
  Go and npm consumers of an earlier checkout must update their import paths and package name.
- `GET /api/platform/metrics` (superadmin) is the platform's single scrape target: one
  Prometheus exposition merging the gateway's own metrics with every foundation service's and
  every installed+enabled module's `/metrics`, each series labeled `service`, plus
  `kiban_metrics_scrape_up{service}` (`0` for a target that failed or timed out; the response
  is always `200`). Per-service `/metrics` listeners are unchanged.
- The environment file is `.env` at the repository root (`.env.test` and the commented
  `.env.example` alongside it); an environment file under `infra/` is no longer read.
  `make setup` writes the root `.env`; every `docker compose` call passes `--env-file .env`
  with `--project-directory infra`.
- Go 1.26.8; `make check` runs `govulncheck` and fails on any reachable known vulnerability.
- The Keycloak realm, its clients and the MFA-setup authenticator are named `kiban`
  (`kiban-frontend`, `kiban-api`, `kiban-local-mfa-setup`). Existing databases are not migrated:
  a development stack needs `make dev-clean` and a fresh `make dev`. The `KEYCLOAK_REALM`
  default is `kiban` everywhere.
- The commercial licence draft is no longer part of this repository; a module's `license.class`
  is `foundation` or `open`.
- Public mode (`make public-up`) requires `KIBAN_PUBLIC_HOST`; `KIBAN_PUBLIC_NETWORK` selects
  the edge network (default `kiban-public`).
- GitHub releases link the changelog and the documentation site's limitations page.
- Base model: `company#member` and `company_module#member` (a company's active linked
  members; admins are members). Org writes the tuple on member create/deactivate; bootstrap
  backfills existing members. Every declared fragment object type must define a
  `company_module` relation; positions and groups carry a `company` relation written by org.
- The demo credentials are `admin` / `DemoAdmin!2026` and `Demo<Name>!2026` for the demo
  cast, satisfying the realm password policy.
- Compose healthchecks and Kubernetes readiness probes use `/ready` (database ping);
  liveness keeps `/health`.
- Notification delivery retries back off exponentially (capped at 15 minutes) instead of
  exhausting all attempts within seconds.
- Base images are Alpine 3.24 and digest-pinned (`make pin-images`); `gateway-devcert` is a
  published image; `deploy/k8s/apply.sh` is re-runnable; the production overlay pins
  `KC_HOSTNAME`. `POSTGRES_DB` must be `kiban` (refused otherwise at initialisation).
- Global-scope decisions require `requiredPlatformRole` (400 otherwise); `/batch-can` accepts
  at most 100 items and writes one audit row per request; tuple cycles evaluate to false; a
  type declared by two module fragments is refused.
- Org: "today" follows `tenant_defaults.timezone`; deletes check references inside the
  transaction (`409` when referenced); paging is bounded; directory search is literal; group
  member add/remove are honest about no-ops; activating a company writes its default grants.
- SDK: an expired-but-refreshable session survives a reload; `logout()` cancels an in-flight
  refresh; `CatalogEntry` carries `installed`/`enabled`. Shell: distinct messages for session
  expiry, denial, unavailability and network failure; a callback reload lands on `/app`.
- Proof scripts share one live-stack guard and restore the seeded superadmin password.
- The demo reset and seed scripts keep the public Compose overlay in public mode and refuse
  the `kiban` project without it.
- The gateway provisions a user in Kiban on the first request from an unseen subject
  (`KIBAN_IDENTITY_BASE_URL` is now required by the gateway). The sample shell shows "No
  company membership yet" for a user without a company.
- `modulekit` (`github.com/rosschiu/kiban/modulekit`, Apache-2.0): the token verifier, HTTP
  helpers and the authz/org/notification clients every module used to copy, as one importable
  package. The four sample modules use it.
- SDK: `OrgClient` now exposes only the methods the gateway routes (`meCompanies`,
  `memberDirectory`, `admin*`). The 21 methods for `/internal/org/...` routes moved to
  `createInternalOrgClient()` (`@internal`). `decodeIdTokenClaims()` is exported.
- `deploy/quickstart/docker-compose.yml` is generated from `infra/compose.yaml` by
  `scripts/gen-quickstart-compose.sh` (`make quickstart-compose`); `make docs-freshness-check`
  fails when it drifts. `deploy/k8s/base` is one service template plus per-service patches with
  identical rendered output.
- `make migrate-<service>` is one pattern rule; `scripts/set-role-password.sh` replaces the five
  per-service scripts. `make fmt` formats Go.

### Removed
- Gateway ACME mode: TLS is operator certificates or a TLS-terminating proxy; `KIBAN_DOMAIN`
  only feeds redirect URIs and CORS.
- The gateway's HTTP→HTTPS redirect listener and `KIBAN_TLS_PORT`, `KIBAN_HTTP_REDIRECT_PORT`,
  `KIBAN_DEV_HTTP_PORT` (the TLS listener is 8443 and the plain-HTTP listener 8090).
- Undocumented overrides that nothing set: the eight `KIBAN_<SERVICE>_DB_USER` variables,
  `KEYCLOAK_IDENTITY_CLIENT_ID`, `KIBAN_NOTIFICATION_SMTP_FROM`.
- `POST /internal/identity/login-observed` (no caller).
- Sample shell: `@tanstack/react-query` and `sonner` dependencies and unused exports.
- The Go module path is now `github.com/rosschiu/kiban` (was `kiban`). External Go code that
  imports Kiban packages must update its import paths.
- The public documentation is a MkDocs Material site built by `make docs-site`.
- Vocabulary aligned with the documentation's Glossary. SDK: `createPlatformAdminClient` →
  `createSuperadminClient`, `PlatformAdminClient` → `SuperadminClient`, `queryKeys.platformAdmin`
  → `queryKeys.superadmin`. API and SDK: effective-access `authUserId` → `subjectId`. OpenAPI
  operationIds `platformAdmin{Enable,Disable}Module` → `superadmin{Enable,Disable}Module`.
  Timesheet sample module: `GET …/submissions?scope=` → `?view=`. Helpdesk sample module:
  `GET …/tickets?scope=` → `?view=`.
- Org: a company org unit can no longer be given a parent, and a non-company unit can no longer
  be created or moved to the top of a tree (422 on `parentId`).
- The dependency licence inventory moved to `THIRD-PARTY-LICENSES.md` at the repository root.
- The four sample modules' migration checksum ledgers were regenerated once; no migration's SQL
  changed.

### Documentation
- The limitations page lists every known gap, including the sample modules'. Release notes now
  live in this changelog.
- The site has an SDK guide (install, session, clients, recipes, errors) and a Contributing
  page; the glossary stays as the vocabulary reference but is out of the site navigation.
- An "Integrate your app" page walks an existing frontend, an existing backend becoming a
  module, and a backend calling the REST API through numbered steps with tested snippets; the
  Building page is the module reference (runtime contract, manifest, fragment grammar,
  migrations, default grants, internal endpoints, the checklist for adding a module); a
  "Start here" block on the home page and README, and a root `AGENTS.md` for coding agents.
- Pages say what 0.1 does: no machine-to-machine credential; companies, units and members are
  created only through the org service's internal routes; modules are compiled into the
  registry (in-tree Go only); redirect URIs are reconciled at every bootstrap; the audit trail
  is read with SQL; the Operating page documents the audit tables, the Keycloak paths the
  gateway routes, and `KIBAN_DOMAIN`, `KEYCLOAK_AUDIENCE`, `KIBAN_MODULE_HOST_<KEY>`.

### Fixed
- The SDK client refreshes an access token that expires within 30 seconds before sending a
  request (`getAccessTokenExpiresAt`), so a long session never hands a module a token that dies
  between the gateway's check and the module's own; the sample shell wires it.
- The sample shell's timesheet Approvals page asked the service for the caller's own
  submissions (`scope`) instead of the ones assigned to them (`view`), so it was always empty.
- The SDK's `grantObjectAccess` and `revokeObjectAccess` recipes send the `companyId` the
  grants route requires (every call was answered `400` without it); the SDK guide, the recipe
  page and the SDK end-to-end test show and prove the company-bound shape.
- Identity and registry audit rows record the acting subject instead of `unauthenticated`.
- An effective-access request with `requiresEligibility: true` is answered `400` instead of
  crashing the request; a decider without an eligibility source answers unavailable.
- The registry and gateway test fixtures reseed the built-in modules they truncate, so a shared
  test stack keeps its catalog after `make check`.
- Ending an assignment that has already ended is refused (`409 ASSIGNMENT_ALREADY_ENDED`) and
  no longer revokes the current holder's position tuple.
- The gateway module proxy and the notification webhook sender keep one HTTP transport each
  instead of leaking one per request; a client disconnect during a proxied response is no
  longer logged as a panic.
- Enabling a module that is not installed is refused (`409 MODULE_NOT_INSTALLED`) instead of
  activating its fragment and grants while the gateway still refuses to route it.
- An unauthenticated request to `/api/health` is answered `401` like every other `/api/` path
  (the exemption had no handler behind it).

[Unreleased]: https://github.com/rosschiu/kiban/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/rosschiu/kiban/releases/tag/v0.1.0
