# Integrate your app

This page takes an existing application and connects it to a running Kiban for login and
access decisions. It is written as numbered steps; each step says what to run and what you
should see.

## Which track

- **Frontend track**: you have a browser application (React, Next, anything that runs in a
  browser) and want Kiban to handle login and to answer "may this user do this here?".
- **Backend track**: you have a Go service and want it to become a Kiban module: routed by the
  gateway, authorizing every request through Kiban.
- **REST-only track**: you have a backend in any language and want to call Kiban's HTTP API
  without the SDK.

## Read this before you start

Three things 0.1 does not do. They shape every track below.

1. **A backend gets its own token only through a service client.** `KIBAN_SERVICE_CLIENTS`
   (set before `bootstrap` runs) creates confidential Keycloak clients with a service account;
   the client-credentials grant then issues a token the gateway accepts. Without one, a backend
   can act only with a user's bearer token forwarded to it. The REST-only track shows both.
2. **Companies, org units and members are created through the org service's internal routes,
   not the gateway.** The gateway exposes reads (`/api/org/me/companies`, the member directory)
   and the superadmin's position and group administration under `/api/org/admin/...`. Creating a
   company or a member means calling the org container from inside the Compose network with a
   superadmin's bearer. The REST-only track shows how.
3. **A module is compiled into the platform.** The registry's list of known modules is a Go
   literal, every module binary is built by the same Dockerfile, and each module needs a role
   migration in the registry's migration set. A module written in another language, or one
   built outside this repository, cannot be installed in 0.1.

Every track assumes a running Kiban. `make dev` from a checkout gives you a gateway at
`https://127.0.0.1:8443`; the image quickstart gives you `http://localhost:3000`. See the
[Quickstart](quickstart.md).

## Frontend track

Every TypeScript snippet on this page is compiled and run against the SDK by its test suite, so
it works against the package as shipped.

### 1. Register your application's origin

Keycloak only completes a login whose `redirect_uri` is registered on the `kiban-frontend`
client. Bootstrap writes that list on every start of the stack:

- With `KIBAN_DOMAIN` unset (the default for `make dev` and the image quickstart), the list is
  fixed: `http://localhost:3000/*`, `http://localhost:5173/*`, `http://localhost/*`,
  `https://127.0.0.1:8443/*` and the test stack's `https://127.0.0.1:18543/*`. A development
  server on `http://localhost:5173` or `http://localhost:3000` works without any change.
- With `KIBAN_DOMAIN=app.example.com` (the `make public-up` path sets it from
  `KIBAN_PUBLIC_HOST`), the list becomes exactly `https://app.example.com/*` and nothing else.
  Your application must be served from that origin, or behind the same reverse proxy as the
  gateway.

For any other origin, open the Keycloak admin console at `http://127.0.0.1:<KEYCLOAK_HOST_PORT>`
(`8081` for `make dev`, `25081` for the image quickstart), log in as `KC_BOOTSTRAP_ADMIN_USERNAME`
with `KC_BOOTSTRAP_ADMIN_PASSWORD` from `.env`, switch to realm `kiban`, open client
`kiban-frontend` and add your origin to "Valid redirect URIs" and "Web origins". Be aware that
bootstrap reconciles both lists to the set above every time the stack starts, so a console edit
lasts until the next `make dev` or `docker compose up`. There is no configuration variable for
an extra origin in 0.1.

You should see: after the change, a login started from your origin lands back on your callback
route instead of Keycloak's "Invalid parameter: redirect_uri" page.

### 2. Install the SDK

The package is on GitHub Packages, which needs an authenticated read even for public packages:
a personal access token with the `read:packages` scope.

```
# .npmrc, next to your package.json
@rosschiu:registry=https://npm.pkg.github.com
//npm.pkg.github.com/:_authToken=${NPM_TOKEN}
```

```
npm i @rosschiu/kiban-sdk
```

You should see `@rosschiu/kiban-sdk` in `package.json`. The package is ESM only and has no
runtime dependencies; it needs `fetch` and `crypto.subtle`, which every current browser has.

### 3. Create the session

One session object per application, created once at startup. `authOrigin` is the gateway; the
SDK never talks to Keycloak directly.

```ts
import { createSession } from "@rosschiu/kiban-sdk";

const gatewayOrigin = "https://127.0.0.1:8443";

const session = createSession({
  authOrigin: gatewayOrigin,
  realm: "kiban",
  clientId: "kiban-frontend",
  redirectUri: "http://localhost:5173/callback.html",
  persistTokens: true
});
```

`persistTokens: true` writes the token set to `sessionStorage` under `kiban.oidc.tokens` so a
reload keeps the session; the entry goes away when the tab closes. Leave it off to keep tokens
in memory only.

You should see nothing yet: `session.isAuthenticated()` is `false` until step 4 completes.

### 4. Gate a route on login and finish the login

A protected route asks the session first. When the user is signed out the SDK records a PKCE
transaction and sends the browser to Keycloak; the function returns `false` so the route
renders nothing.

```ts
export async function requireLogin(session: Session): Promise<boolean> {
  if (session.isAuthenticated()) return true;
  await session.login();
  return false;
}
```

The callback route (`redirectUri` above) exchanges the code once on load. The call is
idempotent for the same code, so a React StrictMode double effect does not exchange it twice.

```ts
export async function finishLogin(session: Session, callbackUrl: string): Promise<void> {
  await session.handleCallback(callbackUrl);
}
```

Call it as `finishLogin(session, window.location.href)`, then navigate to your application's
home.

You should see: the browser goes to
`https://127.0.0.1:8443/auth/realms/kiban/protocol/openid-connect/auth?...code_challenge_method=S256`,
shows the Keycloak login page, and returns to your callback route with `code` and `state` in
the query. After `finishLogin`, `session.isAuthenticated()` is `true`. On a `make dev` stack the
first login as the superadmin also forces a password change.

### 5. Build the API client

Every request goes through one client that attaches the bearer and a correlation id, unwraps
the `{ data }` envelope and turns `{ error }` into a `KibanApiError`.

```ts
import { createApiClient } from "@rosschiu/kiban-sdk";

const api = createApiClient({
  baseUrl: gatewayOrigin,
  getAccessToken: () => session.getAccessToken(),
  getAccessTokenExpiresAt: () => session.getTokens()?.expiresAt,
  refreshAccessToken: () => session.refresh()
});
```

You should see: `await createOrgClient(api).meCompanies()` returns the companies the user is an
active member of. For a freshly bootstrapped stack that is `[]` even for the superadmin: nobody
is a member of anything until a company and a member exist (see the REST-only track's escape
hatch, or the finding "Read this before you start", point 2).

### 6. Ask before showing a feature

`canI` answers "may this user use this feature, in this company?". A denial is a normal
`{ allowed: false, reason }`, never an exception. For a module feature, pass the module key; the
decision then also checks that the module is enabled for the company.

```ts
export async function canSeeInbox(api: ApiClient, companyId: string): Promise<boolean> {
  const canI = createCanI(createEffectiveAccessClient(api));
  const inbox = await canI({ featureKey: "notification.inbox.view", moduleKey: "notification", companyId });
  return inbox.allowed;
}
```

You should see `true` for an active member of `companyId` when the notification module is
enabled there, and `false` with a reason such as `COMPANY_MEMBERSHIP_REQUIRED` otherwise. The
request on the wire is `POST /api/auth/effective-access/can` with
`{ "featureKey": "notification.inbox.view", "moduleKey": "notification", "scope": "company", "companyId": "..." }`.
The gateway answers for the bearer only; a body naming another subject is rejected.

### 7. Call a module endpoint

The SDK has no typed client for the sample modules. `api.request` takes the path from the
module's OpenAPI file, and the gateway forwards it to the module unchanged. Paths follow
`/api/<module>/v1/...`.

```ts
export interface NotificationChannel {
  id: string;
  companyId: string;
  key: string;
  label: string;
  kind: "in_app" | "email" | "webhook";
  target: string | null;
  createdAt: string;
}

export async function listChannels(api: ApiClient, companyId: string): Promise<NotificationChannel[]> {
  const page = await api.request<Page<NotificationChannel>>(`/api/notification/v1/companies/${companyId}/channels`, {
    query: { page: 1, pageSize: 50 }
  });
  return page.items;
}
```

You should see an array (empty on a new stack). A `403` with code `MODULE_DISABLED` or
`MODULE_NOT_INSTALLED` means the module is off for this deployment; `AUTHORIZATION_DENIED` means
the module's own check (`notification.inbox.view` here) refused the bearer. The types come from
the module's [API reference](api/notification.html).

### 8. Handle 401 and refresh

The API client already does the common case: on a `401` it calls `session.refresh()` once
(concurrent callers share one refresh) and retries the request once. A second `401` is thrown
as a `KibanApiError`, so a rejected endpoint never loops. What is left for you is the branch on
the error code:

```ts
try {
  await org.adminCreateGroup(summary.companyId, { code: "sales", name: "Sales" });
} catch (err) {
  if (!(err instanceof KibanApiError)) throw err;
  switch (err.code) {
    case ApiErrorCode.AuthTokenMissing:
    case ApiErrorCode.AuthTokenInvalid:
      session.login(); // refresh already failed; start over
      break;
    case ApiErrorCode.Forbidden:
    case ApiErrorCode.AuthorizationDenied:
      // the caller may not do this; hide the control
      break;
    case ApiErrorCode.ModuleDisabled:
    case ApiErrorCode.ModuleNotInstalled:
      // the module is off for this deployment
      break;
    case ApiErrorCode.ValidationFailed:
    case ApiErrorCode.Conflict:
      // show err.message and err.details to the user
      break;
    case ApiErrorCode.AuthorizationUnavailable:
      // authz could not answer (503); retry later, never fail open
      break;
    default:
      throw err;
  }
}
```

You should see: an access token lives 300 seconds and the refresh token 30 minutes idle (the
realm's defaults). Within those limits the user never sees a login page again; past them the
`AuthTokenInvalid` branch starts a new login.

### 9. Log out

```ts
export function signOut(session: Session): void {
  session.logout();
}
```

You should see: the tokens are cleared, the browser goes to Keycloak's logout endpoint with the
ID token as `id_token_hint`, and comes back to the origin root of `redirectUri`
(`http://localhost:5173/`), not to the callback route. Pass `postLogoutRedirectUri` to
`createSession` for a different landing page; it must be registered on the client too.

For the full API and the recipes, see the [SDK guide](sdk-guide.md).

## Backend track

Your Go service becomes a module: it lives under `modules/<key>/` in this repository, is built
into the platform's images, and receives every `/api/<key>/...` request from the gateway. This
track adds a module named `<key>`; the notification module in `modules/notification/` is the
smallest complete example and every path below names it.

### 1. Know what the gateway sends you

For a request to `/api/<key>/v1/...` the gateway:

- validates the bearer (issuer, audience `kiban-api`, signature via the JWKS), and answers
  `401 AUTH_TOKEN_INVALID` itself when that fails;
- makes sure the user has an identity record (first request of a subject is provisioned);
- forwards the request with the path and query untouched, so your service sees the full
  `/api/<key>/v1/...` path, not a stripped one;
- forwards the `Authorization` header verbatim and sets `x-correlation-id`;
- rejects any client-supplied `x-user-*` header with `400`, so no such header ever reaches you.

The proxy only forwards once the module is installed and enabled and its dependencies are
present; otherwise the caller gets `403` with `MODULE_NOT_INSTALLED`, `MODULE_DISABLED` or
`MODULE_DEPENDENCY_MISSING` and your service is never called.

### 2. Verify the token yourself

The gateway's check does not replace yours: a module runs inside the Compose network and must
not trust a header on its own. `modulekit` (Apache-2.0, import
`github.com/rosschiu/kiban/modulekit`) gives you the verifier:

```go
verifier, err := modulekit.NewTokenVerifier(ctx,
    values["KEYCLOAK_JWKS_URL"], values["KEYCLOAK_ISSUER_URL"], values["KEYCLOAK_AUDIENCE"], "<key>")
// per request:
rawBearer := r.Header.Get("Authorization")
subject, err := verifier.Verify(r.Context(), modulekit.BearerFromHeader(rawBearer))
```

`Verify` returns the token's `sub` claim (the user's Keycloak subject, `kcSub` everywhere else
on this page) or `modulekit.ErrTokenInvalid`. Start
`go verifier.RefreshPeriodically(ctx, logger, modulekit.DefaultJWKSRefreshInterval)` so a
rotated key is picked up. Compose sets the three variables for every module:

| Variable | Value in Compose |
|---|---|
| `KEYCLOAK_JWKS_URL` | `http://keycloak:8080/realms/kiban/protocol/openid-connect/certs` |
| `KEYCLOAK_ISSUER_URL` | `https://127.0.0.1:8443/realms/kiban` (compared as a string with the token's `iss`) |
| `KEYCLOAK_AUDIENCE` | `kiban-api` (the default in every service) |

Never read roles or anything but the subject from the token: authorization is the next step.

### 3. Ask the authorization service before every read and write

`POST /internal/authz/effective-access/can` on `KIBAN_AUTHZ_BASE_URL` (`http://authz:8140` in
Compose), with the user's own bearer forwarded verbatim:

```json
{
  "featureKey": "<key>.things.view",
  "moduleKey": "<key>",
  "scope": "company",
  "companyId": "<uuid from the URL>",
  "object": { "type": "company_module", "id": "<companyId>/<key>" },
  "relation": "member"
}
```

```json
{ "data": { "allowed": true, "reason": "ALLOWED", "evidence": [] } }
```

`object` and `relation` are optional: without them the decision stops after confirming the
subject, the company, the membership and that the module is enabled; with them it also checks
the relation (here: `member` of the company's module; the base model gives every module's
`company_module` six relations, `member`, `admin`, `editor`, `viewer`, `submitter` and
`approver`, see [Building on Kiban](building.md#authorization-fragment-authzfragmentjson)). A `503` means the decision could not be made; refuse the request, never
fail open. In code:

```go
authz := modulekit.NewAuthzClient(&http.Client{Timeout: 5 * time.Second}, values["KIBAN_AUTHZ_BASE_URL"], "<key>")
allowed, reason, err := authz.Can(r.Context(), rawBearer, "<key>.things.view", companyID, "member")
```

The notification module wraps this in one `withAuth(featureKey, handler)` middleware
(`modules/notification/service/http.go`); copy that shape.

### 4. Write a grant when you create an object

Every object your module owns carries an anchor tuple binding it to the company's module, and
usually an owner. Both are written through `POST /internal/authz/grants` in one request, again
with the user's bearer:

```json
{
  "op": "grant",
  "companyId": "<uuid>",
  "tuples": [
    { "objectType": "<key>_thing", "objectId": "<thingId>", "relation": "company_module",
      "subjectType": "company_module", "subjectId": "<companyId>/<key>" },
    { "objectType": "<key>_thing", "objectId": "<thingId>", "relation": "owner",
      "subjectType": "user", "subjectId": "<kcSub>" }
  ],
  "correlationId": "<the request's x-correlation-id>"
}
```

```json
{ "data": { "status": "ok", "count": 2 } }
```

`op` is `grant` or `revoke`. The authorization service only accepts object types your fragment
declares (or the company's `company_module`), requires the anchor to point at the request's
company, and gates the write on the bearer's access to that module in that company. With the
kit: `authz.AnchorTuple("<key>_thing", thingID, companyID)` builds the first tuple and
`authz.GrantOrRevoke(ctx, rawBearer, companyID, "grant", tuples, correlationID)` sends them.

### 5. Look up the member when you need one

Membership facts live in the org service (`KIBAN_ORG_BASE_URL`, `http://org:8130`). The read a
module needs most is "is this subject an active member of this company, and which member row is
it?":

```
GET /internal/org/companies/{companyId}/members/by-kcsub/{kcSub}
```

```json
{ "data": { "isMember": true, "isActive": true, "memberId": "<uuid>" } }
```

`memberId` is `null` when `isMember` is false. This read takes no bearer: org's internal fact
reads are open inside the network, which is one reason a module container must never be
published on a host port. With the kit:
`memberID, isMember, isActive, err := org.MemberByKcSub(ctx, companyID, kcSub)`.

### 6. Write the five artifacts and `artifacts.go`

```
modules/<key>/
  module.manifest.json      key, version, scopeType, service basePath/port/healthPath, schema
  authz.fragment.json       roles, object types, relations, feature keys
  openapi.yaml              every operation, with x-required-modules: [<key>]
  migrations/               tern migrations for schema <key> only, plus checksums.json
  frontend/                 optional routes a shell can mount (may be empty)
  service/                  the Go service; service/cmd/main.go is the binary
  artifacts.go              go:embed of the manifest and the fragment
```

`artifacts.go` is not optional: the registry has no filesystem access to `modules/` at runtime
and reads both files from your package (`modules/notification/artifacts.go` is five lines of
`//go:embed`). The manifest's `service.port` must be unique across modules (notification is
`8150`, timesheet `8160`, docs `8170`, helpdesk `8180`) and `service.healthPath` must be set;
`data.postgresSchema` is the schema your migrations create. Every feature key starts with
`<key>.`; every object type carries a `company_module` relation. [Building on
Kiban](building.md) lists the validator's rules in full.

Your `main.go` reads the same environment every module gets: `KIBAN_LISTEN_ADDR`,
`KIBAN_<KEY>_DB_HOST`, `KIBAN_<KEY>_DB_PORT`, `KIBAN_<KEY>_DB_NAME`,
`KIBAN_<KEY>_DB_PASSWORD`, the three `KEYCLOAK_*` variables, `KIBAN_AUTHZ_BASE_URL` and
`KIBAN_ORG_BASE_URL`; it connects to Postgres as `kiban_<key>`, listens on
`KIBAN_LISTEN_ADDR:<port>` and serves `GET /health` and `GET /ready` (the latter checks the
database). Copy `modules/notification/service/cmd/main.go` and rename.

### 7. Register the module in the registry

This is the compiled-in part. In `internal/registry/builtin.go`, add an entry to
`BuiltinModules` mirroring your manifest, and a `var <key>AuthzRelations =
mustAuthzRelations(<key>artifacts.AuthzFragmentJSON)` next to the existing four:

```go
{
    ModuleKey: "<key>", DisplayName: "<Name>", ScopeType: "company", Mandatory: false,
    BasePath: "/api/<key>", HealthPath: "/health", Port: <port>, LicenseClass: "foundation",
    ManifestVersion:      mustManifest(<key>artifacts.ManifestJSON).Version,
    RequiredOrgUnitTypes: mustManifest(<key>artifacts.ManifestJSON).Org.RequiredOrgUnitTypes,
    AuthzFragment:        <key>AuthzRelations,
},
```

Then add `<key>` to `KIBAN_INSTALLED_MODULES` on the `registry` service in
`infra/compose.yaml` (`notification,timesheet,docs,helpdesk` today). A key in that list that
the literal does not know is a startup failure, and a module missing from the list at first
boot is not installed later without a registry restart with the updated list.

### 8. Add the role migration

Your migrations run as the database owner, but your service connects as its own role with no
DDL rights, and that role is created by the registry's migration set, not yours. Add
`migrations/registry/00NN_<key>_role.sql` (next free number) with the shape of
`0005_notification_role.sql` and `0006_notification_audit_usage.sql`:

```sql
CREATE ROLE kiban_<key> LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
GRANT CONNECT ON DATABASE kiban TO kiban_<key>;
GRANT USAGE ON SCHEMA audit TO kiban_<key>;

---- create above / drop below ----

REVOKE USAGE ON SCHEMA audit FROM kiban_<key>;
REVOKE CONNECT ON DATABASE kiban FROM kiban_<key>;
DROP ROLE kiban_<key>;
```

Your own `migrations/0001_schema.sql` then creates schema `<key>` owned by `kiban`, grants
`USAGE` on it and `SELECT` on `public.schema_version_<key>` to `kiban_<key>`. Your audit
migration must reference the shared `audit.reject_mutation()` in its trigger and never redefine
it: the validator refuses a `CREATE OR REPLACE FUNCTION` of it and grandfathers only the four
shipped `0003_audit.sql` files. Record both ledgers:

```
go run ./cmd/modvalidate -write-checksums migrations/registry
go run ./cmd/modvalidate -write-checksums modules/<key>/
```

Add `KIBAN_<KEY>_DB_PASSWORD=` to `.env.example` and your `.env`, a `migrate-<key>` line to the
`MIGRATE_TARGETS` table in the `Makefile`, and the tern run plus
`./scripts/set-role-password.sh kiban_<key> KIBAN_<KEY>_DB_PASSWORD` to
`infra/migrate-entrypoint.sh`, after the foundation trees.

### 9. Add the Compose service and the gateway variable

Three edits in `infra/`:

- `Dockerfile.service`: a `go build ... -o /out/<key> ./modules/<key>/service/cmd` line in the
  builder stage and a `FROM runtime-base AS <key>` stage copying it, like `notification`'s.
- `compose.yaml`: a `<key>` service copied from the `notification` block (build target `<key>`,
  the `KIBAN_<KEY>_DB_*` variables, the `KEYCLOAK_*` trio, `KIBAN_AUTHZ_BASE_URL`,
  `KIBAN_ORG_BASE_URL`, a `curl -sf http://127.0.0.1:<port>/ready` healthcheck, and
  `depends_on` `migrate`, `bootstrap`, `org` and `registry`), plus `KIBAN_<KEY>_DB_PASSWORD` on
  the `migrate` service.
- On the `gateway` service: `KIBAN_MODULE_HOST_<KEY>: <key>`, and `<key>` under the gateway's
  `depends_on`. Without the variable the gateway dials `127.0.0.1:<port>`, which is not your
  container.

Nothing in the gateway's code changes: the route `/api/<key>/...` exists as soon as the catalog
lists the module.

### 10. Validate, run, prove

```
make validate-modules      # your artifacts against the module contract
make validate-migrations   # the registry tree's new file and ledger
make dev                   # rebuilds the images and starts everything
```

You should see `modvalidate` exit silently, `make dev` end with `<key>` in the container list as
healthy, and the module in the catalog:

```
curl -sk https://127.0.0.1:8443/api/platform/capabilities \
  -H "Authorization: Bearer $TOKEN" | jq '.data[] | select(.module=="<key>")'
```

`$TOKEN` is a user's access token (the REST-only track shows where to get one). Enable the
module for a company through the sample shell's administration pages or
`POST /api/platform/admin/modules/<key>/enable`, then call one of your routes through the
gateway and check that a member gets `200`, a non-member gets `403 AUTHORIZATION_DENIED`, and no
bearer gets `401`. `make check` runs the validators, the unit tests and the coverage gate over
the whole tree, including your module.

## REST-only track

### What you can and cannot do

- Every call needs a user's access token in `Authorization: Bearer ...`. There is no service
  account and no way to obtain a token without a browser login (finding 1 above). A backend
  therefore acts on behalf of the user whose token it holds, typically forwarded from your own
  frontend on the same request.
- Through the gateway you can read what the user may do and see, write object grants as a
  superadmin, administer positions and groups as a superadmin, enable and disable modules, and
  call module APIs. You cannot create a company, an org unit or a member through the gateway
  (finding 2). The escape hatch below does it from inside the network.
- Every response is an envelope: `{ "data": ... }` on success, `{ "error": { "code",
  "message", "details"? } }` on failure. Send `x-correlation-id` if you want to find the request
  in the gateway's logs and the audit rows; the gateway generates one otherwise.

### Route families

All on the gateway origin. The full contract is the [Platform API](api/platform.html) and each
module's file under [Reference](reference.md).

| Family | What it is | Who may call it |
|---|---|---|
| `POST /api/auth/effective-access/can`, `.../batch-can` | The access decision for the bearer, one or many objects | Any user, for themselves only |
| `GET /api/auth/effective-access/summary?companyId=` | Feature keys, role bindings and object grants the bearer holds | Any user, for themselves only |
| `POST /api/auth/grants` | Write or remove relation tuples, bound to one company (`companyId`) and one enabled module | Superadmin; the authz service also requires the company to be active and the objects to belong to one enabled module |
| `GET /api/org/me/companies` | Companies the bearer is an active member of | Any user |
| `GET /api/org/companies/{id}/members?q=&page=&pageSize=` | Member directory of one company | Active members of that company, or a superadmin |
| `/api/org/admin/companies/{id}/positions`, `.../groups`, `/api/org/admin/positions/{id}/assignments`, `/api/org/admin/groups/{id}/members` | Position and group administration | Superadmin |
| `GET /api/platform/capabilities[/{module}]`, `GET /api/platform/catalog` | What is installed and enabled | Any user |
| `POST /api/platform/admin/modules/{key}/enable`, `.../disable`; `/api/platform/admin/platform-roles` | Module enablement, the superadmin role | Superadmin |
| `/api/<module>/v1/...` | The module's own API, forwarded unchanged | Whatever the module decides |

A minimal call:

```
curl -sk https://127.0.0.1:8443/api/auth/effective-access/can \
  -H "Authorization: Bearer $TOKEN" -H "content-type: application/json" \
  -d '{"featureKey":"core.company.view","scope":"company","companyId":"'"$COMPANY"'"}'
```

You should see `{"data":{"allowed":true,"reason":"ALLOWED","evidence":[...]}}` for a member and
`allowed: false` with `COMPANY_MEMBERSHIP_REQUIRED` for anyone else. The gateway ignores any
subject named in the body and answers for the bearer; naming a different `actorId` is a `400`.

### Getting a token for the shell

Because there is no direct grant for users, take the token from a browser session. Log in to the sample
shell (`https://127.0.0.1:8443`), open the browser's developer tools and run:

```js
JSON.parse(sessionStorage.getItem("kiban.oidc.tokens")).accessToken
```

The shell persists its tokens under that key. Export the value as `TOKEN`. It is valid for 300
seconds; take a fresh one when you get `401 AUTH_TOKEN_INVALID`. The same token carries your
subject: `sub` in its payload is the `kcSub` the escape hatch below needs.

### Getting a token for a service

A worker, a connector or a mailer has no browser. Give it a service client: add its id to
`KIBAN_SERVICE_CLIENTS` in `.env` (comma-separated) and run the stack; bootstrap creates a
confidential client with a service account and the `kiban-api` audience. Read the secret in the
Keycloak admin console: realm `kiban`, Clients, the id, Credentials. Then:

```
curl -sf https://127.0.0.1:8443/auth/realms/kiban/protocol/openid-connect/token \
  -d grant_type=client_credentials -d client_id=tokidesk-worker -d client_secret=$SECRET
```

You should see a JSON body with `access_token`, valid for 300 seconds; request a new one when
you get `401 AUTH_TOKEN_INVALID`. Its `sub` is the client's service-account user. The gateway
provisions that user on its first request, and until an administrator adds it as a member of a
company (the escape hatch below, with this `sub` as `kcSub`) it is a member of nothing:
`GET /api/org/me/companies` answers `200` with `[]`. What the service may do is decided by the
memberships and tuples an administrator gives that subject, never by the client itself.

### Escape hatch: create a company and its first member

The org service's routes are not mounted on the gateway, but they are reachable from any
container on the Compose network, and every mutation checks the bearer with the authorization
service: it must belong to a superadmin, or the answer is `403 AUTHORIZATION_DENIED`. Run these
from a checkout with the stack up (`make dev`); the org image has `curl`. `$TOKEN` is the
superadmin's token from the previous step.

Create the company. A company has no parent; `typeKey` is `company`:

```
docker compose --env-file .env --project-directory infra exec org \
  curl -sf http://127.0.0.1:8130/internal/org/units \
  -H "Authorization: Bearer $TOKEN" -H "content-type: application/json" \
  -d '{"typeKey":"company","parentId":null,"code":"acme","name":"Acme Ltd"}'
```

```json
{ "data": { "id": "<companyId>", "typeKey": "company", "parentId": null, "code": "ACME", "name": "Acme Ltd", "isActive": true } }
```

Creating an active company also grants every enabled module's administrator relation for it
in the same transaction, so the company is never without an accountable administrator. An org
unit below the company is the same call with `"typeKey": "business_unit"` or `"territory"` (the
shipped taxonomy) and `"parentId": "<companyId>"`. Codes are normalised to upper case.

Create a member and link it to your login. `kcSub` is the `sub` claim of your token; the
identity record for it exists as soon as you have made one request through the gateway:

```
docker compose --env-file .env --project-directory infra exec org \
  curl -sf http://127.0.0.1:8130/internal/org/members \
  -H "Authorization: Bearer $TOKEN" -H "content-type: application/json" \
  -d '{"companyId":"<companyId>","code":"ross","displayName":"Ross Chiu","email":"ross@example.com"}'

docker compose --env-file .env --project-directory infra exec org \
  curl -sf http://127.0.0.1:8130/internal/org/members/<memberId>/link-user \
  -H "Authorization: Bearer $TOKEN" -H "content-type: application/json" \
  -d '{"kcSub":"<sub from your token>"}'
```

```json
{ "data": { "id": "<memberId>", "companyId": "<companyId>", "code": "ROSS", "displayName": "Ross Chiu", "email": "ross@example.com", "userId": "<uuid>", "isActive": true, "user": { "kcSub": "...", "email": "...", "preferredUsername": "...", "lifecycle": "active" } } }
```

You should see: `GET /api/org/me/companies` through the gateway now lists `ACME`, and the
`can` call above answers `ALLOWED` for `core.company.view`. From here the sample shell's
administration pages (or the `/api/org/admin/...` routes) create positions and groups, and
`POST /api/auth/grants` shares module objects (each request names the company, and every tuple
in it must belong to one enabled module of that company).

For the image quickstart the same commands work with `docker compose exec org` from the
directory holding its `docker-compose.yml`.

## Next

- [Building on Kiban](building.md): the module contract and the validator's rules.
- [SDK guide](sdk-guide.md): every client and recipe.
- [Known limitations](limitations.md): what 0.1 does not do.
