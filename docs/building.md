# Building on Kiban

Two audiences: application developers using the SDK, and module developers extending the
platform.

## Using the SDK

```ts
import { createSession, createApiClient, createCapabilitiesClient } from "@rosschiu/kiban-sdk";

const origin = "https://127.0.0.1:8443";
const session = createSession({
  authOrigin: origin,
  realm: "kiban",
  clientId: "kiban-frontend",
  redirectUri: "http://localhost:5173/callback.html",
});

// a "Log in" button: await session.login()
// the callback route, once: await session.handleCallback(window.location.href)

const api = createApiClient({
  baseUrl: origin,
  getAccessToken: () => session.getAccessToken(),
  getAccessTokenExpiresAt: () => session.getTokens()?.expiresAt,
  refreshAccessToken: () => session.refresh(),
});

const capabilities = await createCapabilitiesClient(api).list();
```

The session runs the OpenID Connect authorization-code flow with PKCE, validates state and nonce,
refreshes tokens once at a time, survives a reload while a refresh token is still valid, and
logs out at the identity provider. The API client speaks the platform envelope: every success is
`{ data }`, every failure `{ error: { code, message } }`, surfaced as a `KibanApiError` with the
HTTP status and code.

Typed clients cover the platform surface: capabilities, effective access, organization reads,
and superadmin operations (module enable/disable, platform-role grant and revoke). Two recipes
answer common questions in one call:

- `canI({ featureKey, companyId })` returns `{ allowed, reason }` and never throws for a denial.
- `grantObjectAccess` / `revokeObjectAccess` write one tuple, for a user or for a position or
  group userset. Superadmin only.

The SDK has no runtime dependencies and no dependency on the sample shell. Everything talks to
the gateway origin; never call Keycloak or a module directly.

Step by step, with what you should see: the frontend track of [Integrate your app](integrate.md).
Every client and recipe: the [SDK guide](sdk-guide.md).

## Writing a module

A module is a directory under `modules/<key>/` in this repository, with five artifacts, a Go
service and a small embed file:

```
modules/<key>/
  module.manifest.json      key, version, scopeType, service basePath/port/healthPath, schema
  authz.fragment.json       roles, object types, relations, feature keys
  openapi.yaml              the module's HTTP API under /api/<key>/v1/...
  migrations/               tern migrations for schema <key> only, plus tern.conf and checksums.json
  frontend/                 optional routes a shell can mount (may be absent)
  service/                  the Go service; service/cmd/main.go is the binary
  artifacts.go              go:embed of the manifest and the fragment
  LICENSE                   the licence text the manifest declares
```

In 0.1 a module is compiled into the platform: it is Go, it lives in this repository, its
binary is built by the same Dockerfile as the foundation services, and the registry's list of
known modules is a Go literal. A module in another language, or one built outside this
repository, cannot be installed. The list of edits that turns a directory into a running module
is at the end of this section.

This section is the reference. The numbered walk-through, with what you should see at each
step, is the backend track of [Integrate your app](integrate.md#backend-track).

The contract in plain terms:

- **Authorize every route.** Ask the effective-access API before every read and write. Company
  scope comes from the URL; the decision confirms membership and module enablement, then the
  relation. A denial is a normal outcome; a dependency failure is a refusal.
- **Anchor every object.** Each object type your fragment declares carries a `company_module`
  relation, and you write that tuple when you create the object. Every object check is bound to
  the company in the URL.
- **Grants name the company.** A grants request carries `companyId` and the tuples; only your
  module's own object types (or its `company_module`) are accepted, the caller must pass your
  module's company-scope decision, and module-tier tuples need the company-module administrator.
- **Audit every mutation** in the same transaction as the write, with the actor taken from the
  verified token.
- **Stay in your schema.** Migrations may only touch the module's own schema and its own audit
  table. They are checksummed once shipped.
- **Describe what you serve.** The OpenAPI file must match the running code; the test suite
  validates responses against it.
- **Be honest on `/ready`.** Check your database connection.

For a Go service, import `github.com/rosschiu/kiban/modulekit` (Apache-2.0). It provides a
JWKS-backed bearer token verifier; JSON decoding, UUID path parameters, paging and unique-violation
helpers; an authorization client (`Can`, grant and revoke, the anchor tuple for a new object);
an organization client (member lookup by login or id); and a notification client (post a module
custom event). A module is then its handlers, its store and its wrappers. The sample modules
under `modules/` show the shape.

### Module runtime contract

**What the gateway sends.** For `/api/<key>/...` the gateway validates the bearer, provisions
the identity record on a subject's first request, checks the catalog (installed, enabled,
dependencies present; otherwise `403` with `MODULE_NOT_INSTALLED`, `MODULE_DISABLED` or
`MODULE_DEPENDENCY_MISSING` and your service is never called) and then reverse-proxies the
request to `http://<host>:<service.port>`, where `<host>` is `KIBAN_MODULE_HOST_<KEY>` on the
gateway or `127.0.0.1` when unset.

| On the forwarded request | Value |
|---|---|
| Path and query | Byte for byte the client's, so your service sees the full `/api/<key>/v1/...`, never a stripped path |
| `Authorization` | The client's bearer, verbatim. The gateway has already checked issuer, audience `kiban-api` and signature, but your service verifies it again |
| `x-correlation-id` | Set by the gateway: the client's value if it sent one, otherwise a generated id. Put it on your audit rows and your grants requests |
| `X-Forwarded-For` | The client address, appended to an upstream proxy's list when the gateway is configured to trust one |
| `Host` | The client's `Host` header, preserved |
| `x-user-*` | Never present. A client sending one gets `400` from the gateway. Your service must not read any identity header; the bearer is the only identity source |

Upstream timeouts are the gateway's: 2 seconds to dial, 5 seconds to the first response byte
(`KIBAN_MODULE_DIAL_TIMEOUT`, `KIBAN_MODULE_RESPONSE_HEADER_TIMEOUT` on the gateway); past
them the client gets `503 MODULE_UNAVAILABLE`.

**Environment.** Compose sets these on every module service. Defaults are what the sample
`main.go` files use when a variable is absent (a host-run process).

| Variable | Compose value | Notes |
|---|---|---|
| `KIBAN_LISTEN_ADDR` | `0.0.0.0` | The host part of the listener only; the port is a constant in your `main.go` that must equal the manifest's `service.port`. Default `127.0.0.1` |
| `KIBAN_<KEY>_DB_HOST` | `postgres` | Default `127.0.0.1` |
| `KIBAN_<KEY>_DB_PORT` | `5432` | Required |
| `KIBAN_<KEY>_DB_NAME` | `${POSTGRES_DB}` | Required. One database for the whole platform; your module owns one schema in it |
| `KIBAN_<KEY>_DB_PASSWORD` | `${KIBAN_<KEY>_DB_PASSWORD}` from `.env` | Required. The role name is not configurable: `kiban_<key>` |
| `KEYCLOAK_JWKS_URL` | `http://keycloak:8080/realms/${KEYCLOAK_REALM}/protocol/openid-connect/certs` | Required |
| `KEYCLOAK_ISSUER_URL` | `https://127.0.0.1:${KIBAN_GATEWAY_TLS_HOST_PORT:-8443}/realms/${KEYCLOAK_REALM}` | Required. Compared as a string with the token's `iss`, which is the public origin, not the container hostname |
| `KEYCLOAK_AUDIENCE` | not set | Default `kiban-api` |
| `KIBAN_AUTHZ_BASE_URL` | `http://authz:8140` | Default `http://127.0.0.1:8140` |
| `KIBAN_ORG_BASE_URL` | `http://org:8130` | Default `http://127.0.0.1:8130` |

Anything else is module-specific (the notification module also reads its SMTP host and port, a
webhook HMAC secret and a delivery claim group) and is yours to add to the Compose block.

**Listeners and probes.** One process, one port, `service.port` from the manifest. Serve on it:

| Path | Who calls it | Response |
|---|---|---|
| `GET /health` | Compose healthchecks, operators | `200`. This is `service.healthPath` in the manifest; the registry stores it, the gateway does not probe it |
| `GET /ready` | The Compose healthcheck (`curl -sf http://127.0.0.1:<port>/ready`) | `{ "data": { "status": "ok" } }` after a database ping; `503` with `INTERNAL_ERROR` when the ping fails (`modulekit`'s `httpx.Ready` does exactly this) |
| `GET /metrics` | The gateway's `GET /api/platform/metrics`, which scrapes every enabled module at `http://<host>:<port>/metrics` with a 2 second budget | Prometheus text format |
| `/api/<key>/v1/...` | The gateway | Your API, every route behind your own bearer check and an authorization decision |

`/health`, `/ready` and `/metrics` are served at the root of your listener, not under
`/api/<key>`, and they are the only unauthenticated routes.

**Token claims.** `modulekit.NewTokenVerifier(ctx, jwksURL, issuer, audience, "<key>")` fetches
the JWKS once; `Verify(ctx, token)` parses the JWT against it, requires `iss` to equal
`KEYCLOAK_ISSUER_URL` and `aud` to contain `KEYCLOAK_AUDIENCE`, checks expiry and signature, and
returns the `sub` claim. `azp` is never accepted in place of `aud`. An unknown `kid` triggers one
JWKS refetch and one retry; every other failure is `modulekit.ErrTokenInvalid`. Run
`RefreshPeriodically` (10 minutes by default) so a rotated key is picked up. `sub` is the only
claim a module may use: it is the `kcSub` every internal endpoint takes. Roles or groups in the
token are never authority; authorization is always the decision below.

### Manifest: `module.manifest.json`

Every key is required unless marked optional; the validator rejects unknown keys, except keys
starting with `_`, which are author comments. `notification`'s file is the template.

| Key | Allowed values | Rule |
|---|---|---|
| `contractVersion` | `"1"` | Any other value is refused |
| `moduleKey` | `^[a-z][a-z0-9_]{1,31}$` | Unique across the catalog. Names the directory, the schema, the role `kiban_<key>`, the feature-key prefix, the base path |
| `displayName` | string | Shown in the catalog |
| `version` | semver | What `dependencies[].versionRange` of other modules is checked against |
| `scopeType` | `global`, `company` | Every shipped module is `company` |
| `mandatory` | bool | Copied into the catalog |
| `service.basePath` | exactly `/api/<moduleKey>` | Also `servers[0].url` of the OpenAPI file |
| `service.port` | 1..65535, unique across the catalog | The port the gateway dials. Shipped: 8150, 8160, 8170, 8180 |
| `service.healthPath` | an absolute path | Stored in the catalog |
| `service.image` | `null` | Not read by anything in 0.1; the image comes from the Dockerfile stage named after the key |
| `dependencies[]` | `{ "moduleKey", "versionRange", "required": true }` | Each names a module in the same validate batch (or the `-catalog` snapshot); `versionRange` is a semver range the target's `version` must satisfy; `required` must be `true`; no cycles. The gateway refuses your routes with `MODULE_DEPENDENCY_MISSING` while a dependency is not enabled |
| `org.requiredOrgUnitTypes` | list of type keys | `["company"]` for every shipped module; copied into the catalog |
| `org.usesMembers`, `org.usesPositions` | bool | Declarative; not enforced |
| `data.postgresSchema` | exactly `<moduleKey>` | The schema your migrations create |
| `data.migrationsPath` | `"migrations"` | The directory the validator and tern read |
| `license.class` | `foundation`, `open` | `foundation` requires `license.spdx` `Apache-2.0`; `open` requires `Apache-2.0` or `MIT` |
| `license.spdx` | see above | The module's `LICENSE` file must match the canonical text for that id, whitespace aside |
| `license.entitlementRequired` | bool | Declarative; nothing checks entitlements in 0.1 |
| `events` | `null` | Reserved |

### Authorization fragment: `authz.fragment.json`

The top-level keys are `moduleKey`, `roles`, `objects`, `relations`, `features`, `fieldCatalog`,
`fieldSets`, `rowScopes` and `bootstrapPolicy`. `moduleKey` must equal the manifest's.
Unknown keys are refused; `_`-prefixed keys are comments.

What runs at runtime: the registry embeds the file and installs only its `relations` section
into the authorization engine, where it is merged with the base model. Everything else in the
file is validated for consistency with that model but is not loaded by any service in 0.1:
feature keys are enforced by the string your own handlers pass to the decision endpoint, and
the flags on `roles[]` drive no grant.

**`relations`** (optional; omit the key when every tier you need already exists on the base
model, as `timesheet` and `helpdesk` do). Object type, then relation name, then one expression:

| Form | Meaning |
|---|---|
| `{ "this": true }` | Direct tuples on this relation. `false` is refused |
| `{ "computedUserset": "<relation>" }` | Whoever holds `<relation>` on the same object. Must name a relation of the same type |
| `{ "tupleToUserset": { "tupleset": "<relation>", "computedUserset": "<relation>" } }` | Follow the tuples on `tupleset` (a relation of this type) to their subject objects and check `computedUserset` there. `computedUserset` must be defined on at least one type of the effective model (base plus your fragment) |
| `{ "union": [ ...expressions ] }` | Any of the children; at least one |

Any other construct (`intersection`, `exclusion`, wildcards, conditions) is outside the subset
and refused. Every type you declare must define `"company_module": { "this": true }`, the anchor
every object check binds through. A type may not redeclare a base type (`user`, `system`,
`module`, `company`, `company_module`, `module_role_binding`, `access_bundle`,
`access_segment`, `member_directory`, `member`, `project_directory`, `project`,
`timesheet_entry`, `submission`, `position`, `group`, `document`); it may reference their
relations, typically `company_module`'s `member`, `admin`, `editor`, `viewer`, `submitter` and
`approver`, through a `tupleToUserset` over the anchor. A type name must be unique across the
catalog.

**`roles[]`**, one entry per key:

| Key | Values | Rule |
|---|---|---|
| `roleKey` | string | Shipped modules use `<key>_admin` |
| `label` | string | |
| `scopeType` | `global`, `company` | Validated |
| `grantsShellAccess` | bool | Declarative in 0.1 |
| `seedCompanyCreatorRole` | bool | Declarative in 0.1; see "Default grants" for what is actually written |
| `sortOrder` | int | |

**`objects[]`**, one entry per object type you want listed in a permission UI:

| Key | Values | Rule |
|---|---|---|
| `objectType` | a type declared in this fragment's `relations` | A base type or an undeclared type is refused |
| `label` | string | |
| `scopeKind` | `module`, `directory`, `object`, `document` | Validated |
| `parentKind` | an object type of the effective model | `company_module` for every shipped object |
| `managerRelation` | a relation of `objectType` | The relation that may manage grants, by convention `owner` |
| `grantableRelations` | relations of `objectType` | What a UI may offer to grant, e.g. `["owner", "editor", "viewer"]` |
| `showInPermissionUi` | bool | |
| `sortOrder` | int | |

**`features[]`**, one entry per feature key your handlers check:

| Key | Values | Rule |
|---|---|---|
| `featureKey` | `<moduleKey>.<scope>.<action>` | Must start with `<moduleKey>.`; unique across the catalog. `<moduleKey>.access` is reserved: the platform synthesizes it for every enabled module |
| `label` | string | |
| `scopeType` | `global`, `company` | Validated |
| `requiresCompany` | bool | Declarative |
| `accessRuleKind` | `relation`, `platform_role`, `module_eligibility` | Validated; every shipped feature is `relation` |
| `accessRulePayload` | `{ "objectType", "relation" }` or `{}` | When both are set, `relation` must be defined on `objectType` in the effective model. `{}` means membership only, no relation leg |
| `sortOrder` | int | |
| `isSidebarEntry` | bool | Declarative; a shell may use it for navigation |

**`rowScopes[]`**: `{ "entityType": <a type this fragment declares>, "rules": [ ... ] }`;
`entityType` is validated, `rules` is not interpreted. **`fieldCatalog`** and **`fieldSets`**
are lists of objects, uninterpreted; ship `[]`. **`bootstrapPolicy`** is
`{ "seedCompanyCreatorObjectRelations": [] }`, uninterpreted.

### OpenAPI: `openapi.yaml`

A standard OpenAPI 3 document. The validator requires:

- `servers[0].url` equal to `service.basePath`; the only other server allowed is `/`, for the
  probes. Path keys are relative to the base path: they start with `/` and never with `/api/`.
- Every operation has a unique `operationId`.
- Every operation except `GET /health` and `GET /ready` carries **`x-required-modules`**, a
  non-empty list of module keys, normally `[<key>]`. Each key named must be a module in the
  validate batch or the `-catalog` snapshot. Nothing reads the annotation at runtime; it is the
  contract's statement of which modules a route needs, and the test suite validates your
  responses against the document.

### Migrations

`modules/<key>/migrations/` is a tern tree run as the database owner `kiban`; your service
connects as `kiban_<key>`, which has no DDL rights. `tern.conf` is the same for every module
except the schema name:

```
[database]
host = {{env "KIBAN_DB_HOST"}}
port = {{env "KIBAN_DB_PORT"}}
database = {{env "POSTGRES_DB"}}
user = kiban
password = {{env "KIBAN_DB_PASSWORD"}}
version_table = public.schema_version_<key>
sslmode = disable
```

Files are named `NNNN_description.sql` (four digits, lowercase, `[a-z0-9_]`), numbered without
gaps or duplicates, and each holds the up statements, the line
`---- create above / drop below ----`, and the down statements. `0001` creates the schema and
grants the runtime role its way in:

```sql
CREATE SCHEMA <key> AUTHORIZATION kiban;
GRANT USAGE ON SCHEMA <key> TO kiban_<key>;
GRANT SELECT ON public.schema_version_<key> TO kiban_<key>;

---- create above / drop below ----

REVOKE SELECT ON public.schema_version_<key> FROM kiban_<key>;
REVOKE USAGE ON SCHEMA <key> FROM kiban_<key>;
DROP SCHEMA <key> CASCADE;
```

The `SELECT` on the version table is what lets the service check at startup that its
migrations have been applied. Later files create tables under `<key>.` and grant `kiban_<key>`
table by table. Your audit table is `audit.<key>__events` with an append-only trigger calling
the shared `audit.reject_mutation()` and `GRANT SELECT, INSERT` to your role; do not redefine
that function (the four shipped modules did so before the rule existed and are grandfathered
by checksum).

**The role file in the registry tree.** `kiban_<key>` is created by the platform, not by you,
because role creation and the shared `audit` schema's grant list are outside a module's fence.
Add `migrations/registry/00NN_<key>_role.sql` (next free number) with, as `0005` and `0006` do
for notification:

```sql
CREATE ROLE kiban_<key> LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
GRANT CONNECT ON DATABASE kiban TO kiban_<key>;
GRANT USAGE ON SCHEMA audit TO kiban_<key>;

---- create above / drop below ----

REVOKE USAGE ON SCHEMA audit FROM kiban_<key>;
REVOKE CONNECT ON DATABASE kiban FROM kiban_<key>;
DROP ROLE kiban_<key>;
```

The role's password is set after the tree runs, from `KIBAN_<KEY>_DB_PASSWORD`, by
`scripts/set-role-password.sh`, both in `infra/migrate-entrypoint.sh` (Compose) and in the
`Makefile`'s `migrate-<key>` target (host run).

**The ledger.** Every migrations directory carries `checksums.json`, file name to SHA-256. The
validator fails when a file is missing from it, a listed file is missing on disk, or a hash has
changed: a shipped migration is never edited, a new one is added. Record a new file with

```
go run ./cmd/modvalidate -write-checksums modules/<key>/
go run ./cmd/modvalidate -write-checksums migrations/registry
```

**What a module migration may not do.** The validator tokenizes each statement (strings,
comments, dollar quotes and quoted identifiers are real tokens, so nothing hides in them) and
applies a positive rule table. Allowed: `CREATE`, `ALTER`, `DROP` and `COMMENT ON` for schema,
extension, table, index, function, procedure, trigger, type, sequence, view, policy and domain;
`GRANT` and `REVOKE` with an `ON` clause; `INSERT`, `UPDATE`, `DELETE`, `TRUNCATE`; a `WITH`
query. Within those, the following are refused by name:

- A reference outside the fence: anything not in schema `<key>`, not `audit.<key>__*`, not
  `public.schema_version_<key>`. `audit.reject_mutation()` may be referenced as a trigger
  function but not created, replaced, altered or dropped.
- An unqualified object name (`CREATE TABLE channel` lands on `search_path`); `CREATE SCHEMA`
  of anything but `<key>` (`CREATE SCHEMA IF NOT EXISTS audit` is tolerated as a no-op); a
  schema owned by anyone but `kiban`.
- `CREATE EXTENSION` other than a bare `pgcrypto`; `SECURITY DEFINER`; setting `search_path`;
  `ALTER ... OWNER TO`; `ALTER ... SET SCHEMA`.
- `GRANT`/`REVOKE` without `ON` (role membership); `WITH GRANT OPTION`; grants on a database,
  tablespace, language, type, domain, parameter or foreign object; grants on a schema other than
  `<key>` or `audit`; grants to, or revokes from, any role but `kiban_<key>`.
- `TRUNCATE` outside schema `<key>` (audit tables are append-only).
- Any other statement: `DO`, `SET`, `CREATE ROLE`, `VACUUM`, `COPY` and so on.

The registry tree is checked for layout and ledger only; its files legitimately create roles
and grant on shared schemas.

### Default grants

Nothing in the fragment grants anyone anything. When a module becomes installed and enabled
(registry start with the key in `KIBAN_INSTALLED_MODULES`, or `POST
/api/platform/admin/modules/<key>/enable`), the registry writes, for every active company, two
tuples on the object `company_module:<companyId>/<key>` through the authorization service's
audited store: the anchor `#company @ company:<companyId>`, which is what lets a company's
members resolve `member` and its administrators resolve `admin` on your module, and
`#system @ system:platform`, which is what lets a superadmin resolve `admin`. The org service
writes the same pair for every enabled module when a company is created, in the company's own
transaction. The anchor is ensured on every pass; the `system` tuple is written once per
(company, module) and never again, so an operator who deletes it to exclude superadmins from a
module stays in control. Disabling a module removes nothing. `roles[].seedCompanyCreatorRole`
and `bootstrapPolicy` are not consulted; a creator role for a module is something your module
grants itself, through the grants endpoint, when it decides to.

### Internal endpoints

The three calls a module makes. The walk-through in [Integrate your app](integrate.md#backend-track)
shows each in context; here is every field. All three are reachable only inside the Compose
network, which is one reason a module container must never publish a host port.

**`POST /internal/authz/effective-access/can`** on `KIBAN_AUTHZ_BASE_URL`, with the user's
bearer. The subject is always the bearer's `sub`.

| Request field | Type | Meaning |
|---|---|---|
| `featureKey` | string | Recorded as evidence and in the denial audit row. Use your fragment's key |
| `moduleKey` | string | Your key. Step 6 requires this module to be installed and enabled |
| `scope` | `"company"` or `"global"` | `global` skips the company steps and needs `requiredPlatformRole` |
| `companyId` | uuid | Required for company scope; the company from your URL |
| `object` | `{ "type", "id" }` | Optional. With `relation`, the object of the relation check. `company_module` ids are `<companyId>/<moduleKey>` |
| `relation` | string | Optional. Empty means no relation check: the decision stops after membership and module state |
| `requiredPlatformRole` | string | Optional. The platform role for a global check, or the operator exception below |
| `allowPlatformOperatorCompanyScope` | bool | Optional. Lets a holder of `requiredPlatformRole` pass the membership step without being a member; the company must still be active |
| `requiredCompanyRole` | string | Optional. A company role checked after membership |
| `actorId` | string | Must be absent or equal the bearer's `sub`; anything else is `400` |
| `requiresEligibility` | bool | Must be absent or `false`; `true` is `400` in this deployment |
| `correlationId` | string | Forward your request's `x-correlation-id` |

The steps, in order: subject exists; Keycloak account enabled; lifecycle active; for global
scope, platform role held; for company scope, company active, then membership (or the operator
exception), then `requiredCompanyRole`; module enabled; relation check when `relation` is set.
An object check is bound to `companyId`: a `company_module` object must be that company's, and a
module object must be anchored to that company's module or the answer is a denial.

| Response | Shape |
|---|---|
| `200` | `{ "data": { "allowed": bool, "reason": "<reason>", "evidence": [ { "key", "value" } ] } }` |
| `503` `AUTHORIZATION_UNAVAILABLE` | A dependency could not answer; `details` carries `dependency`, `step` and `evidence`. Refuse the request, never fail open |
| `400` | Malformed body, `actorId` mismatch, `requiresEligibility`, or global scope without `requiredPlatformRole` |
| `401` | No or invalid bearer |

`reason` is one of `ALLOWED`, `AUTH_USER_NOT_FOUND`, `KEYCLOAK_DISABLED`,
`USER_LIFECYCLE_DISABLED`, `COMPANY_INACTIVE`, `COMPANY_MEMBERSHIP_REQUIRED`,
`COMPANY_ACCESS_BLOCKED`, `MODULE_DISABLED` (also when the module is not installed),
`PLATFORM_ROLE_REQUIRED`, `COMPANY_ROLE_REQUIRED`, `ENGINE_DENIED`,
`BUSINESS_ELIGIBILITY_DENIED`, `DEPENDENCY_UNAVAILABLE`.

`modulekit.AuthzClient.Can(ctx, bearer, featureKey, companyID, relation)` sends
`scope: "company"` with your key and, when `relation` is not empty, the object
`company_module:<companyId>/<key>`; `DoCan` sends any request.

**`POST /internal/authz/grants`** on `KIBAN_AUTHZ_BASE_URL`, with the user's bearer.

| Request field | Type | Meaning |
|---|---|---|
| `op` | `"grant"` or `"revoke"` | |
| `companyId` | uuid | The company every tuple is bound to |
| `tuples[]` | list, non-empty | One relation tuple each |
| `tuples[].objectType`, `tuples[].objectId` | strings | A type your fragment declares, or `company_module` with id `<companyId>/<key>`. Never a base type |
| `tuples[].relation` | string | A relation of that type |
| `tuples[].subjectType`, `tuples[].subjectId` | strings | `user` and a `kcSub`; or `position`/`group` and its id with `subjectRelation` |
| `tuples[].subjectRelation` | string, optional | A userset subject: `holder` for a position, `member` for a group. Must be a relation of `subjectType` |
| `correlationId` | string | Forward your request's `x-correlation-id` |

Checks, all before any write: every object belongs to one module and that module is enabled;
the bearer passes the company-scope decision for (module, company) (a superadmin passes without
membership); each module object is anchored to `company_module:<companyId>/<key>`, either
already or by a `company_module` tuple in the same request (which is how a create writes the
anchor and the owner together); a tuple on `company_module` itself requires the bearer to hold
`admin` on it. The tuples and an audit row commit in one transaction.

| Response | Shape |
|---|---|
| `200` | `{ "data": { "status": "ok", "count": <tuples written> } }` |
| `422` `VALIDATION_FAILED` | An object type, anchor, `company_module` id or `subjectRelation` the rules above refuse |
| `403` `AUTHORIZATION_DENIED` | The bearer failed the decision or lacks `admin`; `details.reason` says which |
| `503` `AUTHORIZATION_UNAVAILABLE` | The decision or the anchor check could not run |
| `400` | Bad JSON, bad `op`, empty `tuples`, `companyId` not a UUID |

`modulekit.AuthzClient.AnchorTuple(objectType, objectID, companyID)` builds the anchor and
`GrantOrRevoke(ctx, bearer, companyID, op, tuples, correlationID)` sends the request.

**`GET /internal/org/companies/{companyId}/members/by-kcsub/{kcSub}`** on
`KIBAN_ORG_BASE_URL`. No bearer: org's fact reads are open inside the network.

| | |
|---|---|
| `companyId` | uuid path segment; a non-UUID is `400` |
| `kcSub` | the token's `sub` |
| `200` | `{ "data": { "isMember": bool, "isActive": bool, "memberId": "<uuid>" or null } }`. `memberId` is `null` when `isMember` is false; `isActive` is the member row's flag |

`modulekit.OrgClient.MemberByKcSub(ctx, companyID, kcSub)` returns
`(memberID, isMember, isActive, err)`; `GetMember(ctx, memberID)` returns the row with its
linked user.

### Validate

```
make validate-modules            # every modules/*/
go run ./cmd/modvalidate modules/<key>/
make validate-migrations         # the foundation trees, including migrations/registry
```

The validator loads the five artifacts plus `frontend/frontend.manifest.json` when present,
applies every rule above, then the cross-module rules: `moduleKey`, `service.basePath`,
`service.port`, frontend route ids, feature keys and object types are unique across the batch
(pass `-catalog snapshot.json` to include modules outside it), dependencies resolve and form no
cycle. A frontend manifest needs `routeBase` equal to `/app/<key>`, a semver `sdkVersionRange`,
unique route ids and paths, `:param` segments that are identifiers, and each route's
`featureKey` declared in the fragment or equal to `<key>.access`. `make check` runs all of it.

### Adding a module to the platform

Every item is needed; the platform has no runtime registration in 0.1.

1. `modules/<key>/`: the artifacts above, `artifacts.go` with `//go:embed authz.fragment.json`
   and `//go:embed module.manifest.json` exporting `AuthzFragmentJSON` and `ManifestJSON`, and
   `LICENSE`.
2. `internal/registry/builtin.go`: an entry in `BuiltinModules` mirroring the manifest
   (`ModuleKey`, `DisplayName`, `ScopeType`, `Mandatory`, `BasePath`, `HealthPath`, `Port`,
   `LicenseClass`, `ManifestVersion` and `RequiredOrgUnitTypes` from `mustManifest`,
   `AuthzFragment` from `mustAuthzRelations`), plus the `var <key>AuthzRelations` next to the
   existing four. A key in `KIBAN_INSTALLED_MODULES` that the list does not know stops the
   registry at startup.
3. `migrations/registry/00NN_<key>_role.sql` as above, then
   `go run ./cmd/modvalidate -write-checksums migrations/registry`.
4. `infra/Dockerfile.service`: a `go build ... -o /out/<key> ./modules/<key>/service/cmd` line
   in the builder stage and a `FROM runtime-base AS <key>` stage that copies the binary and sets
   it as the entrypoint.
5. `Makefile`: `migrate-<key>` in `MIGRATE_TARGETS`, `MIGRATE_DIR_<key> :=
   modules/<key>/migrations` and `MIGRATE_PW_<key> := ./scripts/set-role-password.sh kiban_<key>
   KIBAN_<KEY>_DB_PASSWORD`.
6. `infra/migrate-entrypoint.sh`: after the foundation trees, `go tool tern migrate -m
   modules/<key>/migrations -c modules/<key>/migrations/tern.conf` followed by the same
   `set-role-password.sh` line.
7. `.env.example` and `.env`: `KIBAN_<KEY>_DB_PASSWORD=`; `infra/compose.yaml`: the same
   variable on the `migrate` service's environment.
8. `infra/compose.yaml`: a `<key>` service copied from `notification`'s block (build target
   `<key>`, the environment table above, the `/ready` healthcheck, `depends_on` `postgres`,
   `migrate`, `bootstrap`, `org` and `registry`), and `<key>` appended to
   `KIBAN_INSTALLED_MODULES` on the `registry` service.
9. `infra/compose.yaml`, `gateway` service: `KIBAN_MODULE_HOST_<KEY>: <key>` and `<key>` under
   `depends_on`. Without the variable the gateway dials `127.0.0.1:<port>`, which is not your
   container.
10. `make validate-modules`, `make validate-migrations`, then `make dev` to rebuild the images
    and start the stack. Enable the module for a company with
    `POST /api/platform/admin/modules/<key>/enable` or the sample shell.

A module missing from `KIBAN_INSTALLED_MODULES` at the registry's first boot is not installed
later without a registry restart with the updated list.

The four sample modules are the worked examples. `notification` is the smallest complete one;
`helpdesk` shows position- and group-based assignment; `docs` (DocShare) shows per-object
sharing as live tuples.

## Contributing

Gates are `make check` (format, vet, vulnerability check, unit tests, module and migration
validation, web checks, coverage ratchet over 40 scopes, licence checks, secret scan) and
`make test` (full tests including the OpenFGA differential harness). Both need the isolated test
stack: `make test-stack-up` first. Coverage minimums only ever rise. See `CONTRIBUTING.md` in
the repository.
