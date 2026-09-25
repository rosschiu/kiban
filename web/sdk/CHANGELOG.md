# Changelog — `@rosschiu/kiban-sdk`

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning follows
[Semantic Versioning](https://semver.org/). This file tracks the SDK package specifically
(`web/sdk/`, published as `@rosschiu/kiban-sdk`); see the root [`CHANGELOG.md`](../../CHANGELOG.md) for
the platform-wide release notes this package version ships alongside.

## [Unreleased]

### Changed (breaking — pre-1.0)
- Vocabulary alignment: `createPlatformAdminClient` → `createSuperadminClient`, `PlatformAdminClient` → `SuperadminClient`, `queryKeys.platformAdmin` → `queryKeys.superadmin` (source file `src/superadmin.ts`); `EffectiveAccessSummary.authUserId` → `subjectId`.

## [0.1.0] — 2026-09-25

First tagged version of the SDK, released with Kiban 0.1.0.

### Added

- OIDC/PKCE session management (`src/auth/pkce.ts`, `src/auth/session.ts`,
  `src/auth/context.ts`): the SDK owns the browser's OIDC session end to end (PKCE flow,
  single-flight token refresh); frontend module code never sees a refresh token, only a fetch
  client with the access token attached.
- Envelope-aware API client (`src/client.ts`): typed request/response handling matching the
  platform's `{ data }` / `{ error: { code, message, details? } }` envelope conventions, with
  `KibanApiError` carrying the canonical error code.
- Typed clients for organization data (`src/org.ts`), platform-admin operations
  (`src/platformAdmin.ts`), module capability checks (`src/capabilities.ts`), and effective-access
  summaries (`src/effectiveAccess.ts`).
- Recipes (`src/recipes/`): `canI` (feature/relation access checks) and
  `grantObjectAccess` (the standard grant-a-relation-on-an-object flow), each with an e2e proof
  in the shell/Playwright suites.
- `src/types.ts`'s `ApiErrorCode`/`EffectiveAccessReason` enums, drift-pinned against
  `contracts/wire-enums.json` (the same golden the Go side's `internal/errenv` and
  `internal/authz/decision` check against) — a change to either language's enum without updating
  the golden fails that language's own test.
- React Query key factory (`src/queryKeys.ts`) for consistent cache invalidation across consumers.

### License

`Apache-2.0` (was `UNLICENSED`) — see [`LICENSE`](LICENSE) and the root
[`LICENSING.md`](../../LICENSING.md) for the full path → license map.

[Unreleased]: https://github.com/rosschiu/kiban/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/rosschiu/kiban/releases/tag/v0.1.0
