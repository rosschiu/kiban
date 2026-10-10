# @rossbsol/kiban-sdk

TypeScript SDK for the Kiban platform: OIDC/PKCE session handling (single-flight refresh,
StrictMode-safe callback), an envelope-aware fetch wrapper, typed clients over the gateway's
`/api/platform/*`, `/api/auth/*` and `/api/org/*` surface, TanStack-convention query-key factories, and named use-case recipes.
Zero runtime dependencies (native `fetch`/`crypto` only). Everything talks to the gateway
origin, never to Keycloak or a module directly.

## Quickstart

```ts
import { createSession, createApiClient, createCapabilitiesClient } from "@rossbsol/kiban-sdk";

const gatewayOrigin = "https://127.0.0.1:8443"; // your `make dev` gateway (self-signed dev TLS)

const session = createSession({
  authOrigin: gatewayOrigin,
  realm: "kiban",
  clientId: "kiban-frontend",
  redirectUri: "http://localhost:5173/callback.html"
});

// 1. Somewhere a "Log in" button calls: await session.login()  (redirects to Keycloak)
// 2. Your callback route calls, once, on load:
await session.handleCallback(window.location.href);

// 3. Build the envelope-aware API client, wiring the session's single-flight refresh in:
const apiClient = createApiClient({
  baseUrl: gatewayOrigin,
  getAccessToken: () => session.getAccessToken(),
  refreshAccessToken: () => session.refresh()
});

// 4. Call a typed client:
const capabilities = await createCapabilitiesClient(apiClient).list();
```

## What's here

Every row is reachable through the gateway unless marked otherwise. The e2e suite covers
login/logout, `summary`, `capabilities.list`, `meCompanies`, `canI`, grant/revoke and module
enable/disable; the rest is unit-tested only.

| Module | Status |
|---|---|
| `auth/session.ts`, `auth/context.ts` | OIDC/PKCE session + app-side company/preferences context |
| `client.ts`, `capabilities.ts` | fetch wrapper + envelope, `GET /api/platform/capabilities[/{module}]` |
| `superadmin.ts` | `GET /api/platform/catalog`, `POST /api/platform/admin/modules/{key}/enable\|disable`, `POST /api/platform/admin/platform-roles`, `DELETE /api/platform/admin/platform-roles/{role}/{subjectId}` |
| `demoMode.ts` | `GET /api/platform/demo-mode` |
| `effectiveAccess.ts` | `POST /api/auth/effective-access/can\|batch-can`, `GET /api/auth/effective-access/summary` (self-scoped) |
| `org.ts` | `meCompanies()` (`GET /api/org/me/companies`), the member directory, and the `admin*` position/group methods (no e2e coverage) |
| `orgInternal.ts` | `createInternalOrgClient()`: org's `/internal/org/...` paths, not gateway-exposed (see "Known gaps"); excluded from the typedoc reference |
| `queryKeys.ts` | TanStack-convention key factories for every client above |
| `recipes/canI.ts`, `recipes/grantObjectAccess.ts` | Recipes |
| `server/` | The `@rosschiu/kiban-sdk/server` entry for a Node backend: service credentials, token verifier, app client |

Wire shapes are typed by hand from the Go handlers (`internal/authz/http.go`,
`internal/authz/summary.go`, `internal/org/http.go`, `internal/registry/http.go`).

## Where tokens live

`createSession` keeps the TokenSet (access, refresh, ID token) in memory. With
`persistTokens: true` it is also written to the injected `storage`, so a page reload keeps the
session. The default storage is `sessionStorage`: per tab, cleared on tab close, never
`localStorage`. An expired access token with a valid refresh token is hydrated and refreshed by
the next 401; an expired set without one is dropped. Without `persistTokens` the tokens never
reach browser storage and a reload needs a new login, which Keycloak's SSO cookie usually
completes without a password prompt. The login transaction (PKCE verifier, `state`, `nonce`) is
always written to `storage` for the redirect, so `createMemoryStorage()` is for tests and hosts
without browser storage, not for a browser login. Tokens are
readable by any script on the origin, so the gateway serves the sample shell with a
Content-Security-Policy (`default-src 'self'`, no inline scripts) and the other security headers.
A host embedding this SDK is expected to do the same.

## Known gaps

**Unit and member administration has no typed methods.** The gateway exposes it under
`/api/org/admin/units` (superadmin) and `/api/org/admin/members` (superadmin, or an administrator
of that company); call those routes with `api.request`. `createOrgClient()` carries
`meCompanies()` (self-scoped, `GET /api/org/me/companies`, kcSub injected from the bearer),
`memberDirectory()`, and the `admin*` position/group methods (`/api/org/admin/...`; superadmin,
or an administrator of that company). `createInternalOrgClient()` (`orgInternal.ts`, `@internal`,
not in the typedoc reference) targets `/internal/org/...` paths, which the gateway does not
mount.

## Recipes

- [`canI`](docs/recipes/canI.md): "can I `<feature>` in `<company>`?"
- [`grantObjectAccess`](docs/recipes/grantObjectAccess.md): "share object X with user Y as `<relation>`"

## Scripts

- `npm run -w sdk test`: vitest unit suite (mocked fetch; no live stack needed)
- `npm run -w sdk typecheck`: `tsc --noEmit`, includes `docs-snippets/` so the recipe docs'
  code samples are compile-checked
- `npm run -w sdk build`: tsup, emits `dist/index.js` and `dist/server/index.js` (ESM), each with its `.d.ts`
- `npm run -w sdk e2e`: Playwright against the isolated `kiban-test` stack
  (`make test-stack-up`; builds first)
