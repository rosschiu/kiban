<!-- SPDX-License-Identifier: Apache-2.0 -->

<!--
Source of truth for docs/sdk/recipes.md — copied there verbatim by `make docs-sdk` (after
typedoc's own `cleanOutputDir` wipe, since typedoc owns everything else under docs/sdk/ and
would delete a hand-written file living inside that directory). Edit here, never edit
docs/sdk/recipes.md directly — `make check`'s docs-freshness gate would just overwrite it anyway.
-->

# SDK recipes


Named use-case recipes: each is one SDK call that answers a common product question in one round
trip, backed by a documented pattern page and a live e2e test. A recipe is only listed here once
both exist. This page is the catalog; each recipe's own pattern page (with a copy-paste snippet,
type-checked by `web/sdk/docs-snippets/check.ts` as part of `npm run -w sdk typecheck`) has the
full detail.

## `canI`: "can I `<feature>` in `<company>`?"

One call over `effectiveAccess.can()` that collapses the wire decision into a plain
`{allowed, reason}` result, for the common "should I show/allow this" question a component asks
before rendering a gated action or nav entry. A denial is a normal result and does not throw;
`KibanApiError` is thrown only for a transport or envelope failure. Global-scope (omit
`companyId`) covers superadministration-style checks; company-scope (`companyId` set) covers
membership/company-role-gated features.

- Pattern + snippet: [`docs/recipes/canI.md`](docs/recipes/canI.md)
- Unit test (request-shape + allow/deny/evidence mapping): `web/sdk/test/recipes/canI.test.ts`
- Live e2e test: [`web/sdk/e2e/login.spec.ts`](e2e/login.spec.ts)
  (login → summary → `canI` → `grantObjectAccess` → logout)

## `grantObjectAccess` / `revokeObjectAccess`: "share object X with subject Y as `<relation>`"

One call over the gateway's superadmin-guarded `POST /api/auth/grants`
(`internal/gateway/foundation_routes.go`, forwarding to authz's `handleGrants`) that grants (or,
via the inverse `revokeObjectAccess`, revokes) one authz tuple: a plain user, or a userset subject
(set `subjectRelation` to grant to a position's holder or a group's members). Only a caller
holding `auth.platform_administration.access` may call either; every other caller gets `403`.

- Pattern + snippet: [`docs/recipes/grantObjectAccess.md`](docs/recipes/grantObjectAccess.md)
- Unit test: `web/sdk/test/recipes/grantObjectAccess.test.ts`
- Live e2e test: [`web/sdk/e2e/login.spec.ts`](e2e/login.spec.ts) (the superadmin bearer grants,
  then revokes, a fixture object)

## Adding a recipe

A new recipe needs, in the same change (a recipe must have an e2e test before it is documented):
the SDK function under `src/recipes/`, a unit test, a pattern page under
`docs/recipes/<name>.md` (type-checked via `docs-snippets/check.ts`), a live e2e test extending
`e2e/login.spec.ts` (or a new spec file), and a new entry on this page linking both.
