# SDK guide

`@rosschiu/kiban-sdk` is the TypeScript package a web application or a module frontend uses to
talk to a Kiban deployment: the login flow, the tokens, typed calls to the platform API and the
error envelope. It has no runtime dependencies (native `fetch` and `crypto` only) and talks to
the gateway origin alone, never to Keycloak or to a module's service directly. The sample shell
in `web/shell/` is one consumer of it; you do not need the shell to use the SDK.

Every sample on this page compiles against the package as shipped: the same code lives in
`web/sdk/docs-snippets/guide.ts`, which the SDK's type check and unit tests cover.

## Install

The package is published to GitHub Packages, so npm needs to know where the `@rosschiu` scope
lives. GitHub Packages requires an authenticated read even for public packages: a token with
the `read:packages` scope.

```
# .npmrc, next to your package.json
@rosschiu:registry=https://npm.pkg.github.com
//npm.pkg.github.com/:_authToken=${NPM_TOKEN}
```

```
npm i @rosschiu/kiban-sdk
```

The package ships ESM only (`dist/index.js` and `dist/index.d.ts`). Node 20 or a modern browser
gives you the `fetch` and `crypto.subtle` it relies on.

## Create a session

The session runs the OpenID Connect authorization-code flow with PKCE (S256) against the
gateway's Keycloak proxy, validates `state` and `nonce`, and refreshes tokens one flight at a
time.

```ts
import { createSession } from "@rosschiu/kiban-sdk";

const gatewayOrigin = "https://127.0.0.1:8443"; // your gateway; self-signed TLS in `make dev`

const session = createSession({
  authOrigin: gatewayOrigin,
  realm: "kiban",
  clientId: "kiban-frontend",
  redirectUri: "http://localhost:5173/callback.html",
  persistTokens: true
});
```

- A "Log in" button calls `await session.login()`; the browser goes to Keycloak and comes back to
  `redirectUri` with `code` and `state`.
- The callback route calls `await session.handleCallback(window.location.href)` once on load.
  The call is idempotent for the same `code`, so a React StrictMode double effect does not
  exchange the code twice.
- `session.isAuthenticated()` and `session.getAccessToken()` are synchronous and never trigger a
  refresh. `session.refresh()` does; concurrent callers share one network call.
- `session.logout()` clears the tokens and sends the browser to Keycloak's logout endpoint, then
  back to `postLogoutRedirectUri` (default: the origin root of `redirectUri`, not the callback
  route).

`redirectUri` must be registered on the `kiban-frontend` client. Bootstrap writes that list on
every start: exactly `https://<KIBAN_DOMAIN>/*` when `KIBAN_DOMAIN` is set, otherwise the fixed
localhost set. An edit in the Keycloak admin console lasts until the next start, and no variable
adds an extra origin. [Integrate your app](integrate.md#1-register-your-applications-origin)
has the list and the steps.

### Where tokens live

The token set (access, refresh and ID token plus expiry) is held in memory. With
`persistTokens: true` it is also written to `sessionStorage` under `kiban.oidc.tokens`, so a page
reload or a direct link keeps the session; the entry goes away when the tab closes. The SDK never
writes tokens to `localStorage`. On reload a persisted set is only trusted if it is still usable:
not expired, or expired but carrying a refresh token (the next 401 refreshes it). Anything else
is dropped and the user logs in again.

To keep tokens out of browser storage entirely, pass a memory adapter:

```ts
import { createMemoryStorage, createSession } from "@rosschiu/kiban-sdk";

const session = createSession({
  authOrigin: gatewayOrigin,
  realm: "kiban",
  clientId: "kiban-frontend",
  redirectUri: "http://localhost:5173/callback.html",
  storage: createMemoryStorage()
});
```

A reload then needs a new `login()`, which Keycloak's SSO cookie usually completes without a
password prompt. Any script on your origin can read the tokens, so serve your application with a
Content-Security-Policy as the gateway does for the sample shell.

`decodeIdTokenClaims(idToken)` reads the ID token's claims for display (name, email) without
verifying the signature. Use it for the header, never for an authorization decision.

## The API client

`createApiClient` is the one fetch wrapper every typed client is built on. It attaches the bearer
and an `x-correlation-id`, JSON-encodes the body, unwraps the `{ data }` envelope and turns an
`{ error }` envelope into a `KibanApiError`.

```ts
import { createApiClient } from "@rosschiu/kiban-sdk";

const api = createApiClient({
  baseUrl: gatewayOrigin,
  getAccessToken: () => session.getAccessToken(),
  getAccessTokenExpiresAt: () => session.getTokens()?.expiresAt,
  refreshAccessToken: () => session.refresh()
});
```

A token that expires within the next 30 seconds is refreshed before the request is sent, when
`getAccessTokenExpiresAt` is wired. On a 401 the client calls `refreshAccessToken` once and retries
the request once if it returned a token. A second 401 is thrown as a `KibanApiError`, so a persistently rejected endpoint never
loops. A 204 resolves to `undefined`. `api.request<T>(path, options)` is available for a module's
own endpoints: `options` takes `method`, `body`, `headers`, `query` and an `AbortSignal`.

## The clients

Each client is a function of the API client and returns an object of typed methods.

| Client | Methods | Endpoint |
|---|---|---|
| `createCapabilitiesClient(api)` | `list()`, `get(moduleKey)` | `GET /api/platform/capabilities[/{module}]` |
| `createEffectiveAccessClient(api)` | `can(request)`, `batchCan(request)`, `summary(companyId?)` | `POST /api/auth/effective-access/can`, `/batch-can`, `GET .../summary` |
| `createOrgClient(api)` | `meCompanies()`, `memberDirectory(companyId, q?, page?, pageSize?)`, and the superadmin-only `adminListPositions`, `adminCreatePosition`, `adminAssignPosition`, `adminEndAssignment`, `adminListGroups`, `adminCreateGroup`, `adminListGroupMembers`, `adminAddGroupMember`, `adminRemoveGroupMember` | `/api/org/...` |
| `createSuperadminClient(api)` | `catalog()`, `enableModule(key)`, `disableModule(key)`, `grantPlatformRole(subjectId, role)`, `revokePlatformRole(subjectId, role)` | `/api/platform/catalog`, `/api/platform/admin/...` |

Effective access is self-scoped: the gateway answers for the bearer only, and a request body
naming another subject is rejected. `summary()` returns the feature keys, role bindings and
direct object grants the caller holds, globally or in one company; it is a display composition
for navigation, while `can` and `batchCan` are the gate a component asks before acting.

```ts
import { createEffectiveAccessClient, createOrgClient } from "@rosschiu/kiban-sdk";

const effectiveAccess = createEffectiveAccessClient(api);
const org = createOrgClient(api);

const companies = await org.meCompanies();
const summary = await effectiveAccess.summary(companies[0]?.id);

const decisions = await effectiveAccess.batchCan({
  featureKey: "docs.create",
  moduleKey: "docs",
  scope: "company",
  companyId: summary.companyId,
  items: [
    { object: { type: "docs_document", id: "doc-1" }, relation: "viewer" },
    { object: { type: "docs_document", id: "doc-2" }, relation: "viewer" }
  ]
});
const visible = decisions.filter((d) => d.decision.allowed).map((d) => d.object.id);
```

The sample modules (notification, docs, helpdesk, timesheet) have no clients in the SDK; call
their endpoints with `api.request` and the types from their OpenAPI files in the
[reference](reference.md).

`queryKeys` is a key factory for TanStack Query users, one entry per client above, so cache
invalidation uses the same keys everywhere. `createSessionContext()` keeps the active company
selection and user preferences in `localStorage`; it is a convenience for the UI, not an
authorization source.

## Recipes

Two use-case functions answer common product questions in one call. Each has a pattern page and
a live end-to-end test in the repository.

### `canI`: "can I use this feature, here?"

```ts
import { createCanI } from "@rosschiu/kiban-sdk";

const canI = createCanI(effectiveAccess);

const admin = await canI({
  featureKey: "auth.platform_administration.access",
  requiredPlatformRole: "kiban-superadmin"
});

const view = await canI({ featureKey: "core.company.view", companyId: summary.companyId });
if (!view.allowed) {
  console.log(view.reason); // e.g. "COMPANY_MEMBERSHIP_REQUIRED"
}
```

Omit `companyId` for a global check, set it for a company-scoped one. A denial is a normal
`{ allowed: false, reason }` result and does not throw; `KibanApiError` is thrown only for a
transport or envelope failure.

### `grantObjectAccess`: "share this object with that subject"

```ts
import { createGrantObjectAccess } from "@rosschiu/kiban-sdk";

const { grantObjectAccess, revokeObjectAccess } = createGrantObjectAccess(api);

await grantObjectAccess({
  companyId: summary.companyId, // the company whose docs module owns the document
  objectType: "docs_document",
  objectId: "doc-1",
  relation: "viewer",
  subjectType: "group",
  subjectId: "group-12",
  subjectRelation: "member" // every current member of the group; omit for a single user
});

await revokeObjectAccess({
  companyId: summary.companyId,
  objectType: "docs_document",
  objectId: "doc-1",
  relation: "viewer",
  subjectType: "group",
  subjectId: "group-12",
  subjectRelation: "member"
});
```

Both write one tuple through `POST /api/auth/grants`. The gateway admits only a superadmin
(anyone else receives `403 FORBIDDEN`), and the authz service then binds the request to the
company named by `companyId` and to the one enabled module whose fragment declares the object
type: `docs_document` belongs to the docs module, a base type such as `company` is refused, and
the object must already be anchored to that company's module (the module does this when it
creates the object). A request without a UUID `companyId` is answered `400`; an object type no
enabled module declares, or an unanchored object, `422`. A position's holder is
`subjectType: "position"` with `subjectRelation: "holder"`.

## Error handling

Every failed request throws `KibanApiError` with `status`, `code`, `message`, optional `details`
and the `correlationId` the client sent, which also appears in the gateway's logs and audit
rows. `ApiErrorCode` holds the canonical codes as constants; the ones a frontend usually
branches on:

```ts
import { ApiErrorCode, KibanApiError } from "@rosschiu/kiban-sdk";

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

`code` is `"UNKNOWN_ERROR"` when the response carried no envelope (a proxy error page, a network
failure midway). Do not parse `message`; it is for people.

## Wire types

The package exports the request and response shapes as TypeScript types, hand-typed from the Go
handlers and pinned by tests: `Capability`, `CatalogEntry`, `EffectiveAccessRequest`,
`EffectiveAccessDecision`, `EffectiveAccessSummary`, `AuthzTuple`, `OrgMeCompany`,
`OrgPositionWithHolder`, `OrgGroupWithMemberCount`, `Page<T>` (`items`, `total`, `page`,
`pageSize`, `totalPages`) and `Cursor<T>`. `ApiErrorCode` and `EffectiveAccessReason` are string
constants checked against the same golden file as the Go side, so a code you compare against
exists on the wire.

## Versioning

The SDK follows semantic versioning and ships with each platform release; before 1.0 a minor
version may rename an export, and the rename is listed under "Changed (breaking)" in
[`web/sdk/CHANGELOG.md`](https://github.com/rosschiu/kiban/blob/main/web/sdk/CHANGELOG.md). Pin
the version and read that file when you bump it.

## Reference

- [SDK API reference](sdk/index.html), generated from the source's doc comments at the same
  commit.
- [Recipes catalog](https://github.com/rosschiu/kiban/blob/main/web/sdk/RECIPES.md), with the
  pattern page and test for each recipe.
- [Platform API](api/platform.html) for the endpoints the clients call.
