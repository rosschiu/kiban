# Recipe: `grantObjectAccess` — "share object X with user Y as `<relation>`"

Named use-case recipe: one call over the gateway's superadmin-guarded grant route
(`POST /api/auth/grants`, `op: "grant"`, forwarding to authz's transactional
`handleGrants`), instead of hand-assembling `tupleWire`/`grantsRequestWire` at every call site.
`revokeObjectAccess` is the inverse (`op: "revoke"`, same tuple shape).

## Pattern

```ts
import { createApiClient, createGrantObjectAccess } from "@rosschiu/kiban-sdk";

const apiClient = createApiClient({
  baseUrl: "https://127.0.0.1:8443", // always the gateway origin
  getAccessToken: () => session.getAccessToken(),
  refreshAccessToken: () => session.refresh()
});

const { grantObjectAccess, revokeObjectAccess } = createGrantObjectAccess(apiClient);

// Share a document with a user as "viewer" (superadmin bearer — authz's own store.Grant call
// is this recipe's transaction boundary, one row, one audit event). `companyId` is the company
// whose docs module owns the document.
await grantObjectAccess({
  companyId: "1d2a6a4e-6f6f-4b9e-9c1e-1f2b3c4d5e6f",
  objectType: "docs_document",
  objectId: "doc-1",
  relation: "viewer",
  subjectType: "user",
  subjectId: "kc-sub-of-the-target-user",
  correlationId: crypto.randomUUID()
});

// ... and later, revoke it:
await revokeObjectAccess({
  companyId: "1d2a6a4e-6f6f-4b9e-9c1e-1f2b3c4d5e6f",
  objectType: "docs_document",
  objectId: "doc-1",
  relation: "viewer",
  subjectType: "user",
  subjectId: "kc-sub-of-the-target-user"
});
```

Every call names the company the tuple belongs to. The authz service binds the request to that
company and to the one enabled module whose fragment declares the object type (`docs_document`
belongs to the docs module; a base type such as `company` is refused), and the object must
already be anchored to `company_module:<companyId>/<module>`, which the module writes when it
creates the object. A request without a UUID `companyId` is answered `400`; an object type no
enabled module declares, or an unanchored object, is answered `422`.

The platform's authorization usage rules still apply at the call site — this recipe does not
enforce them for you: grant at the natural scope (never fan out object-level grants to simulate
broad access), and remember shell reachability is explicit (an object grant never implies
company/module shell access on its own — bundle a shell grant alongside it when the caller needs
one).

## Gateway exposure and tests

`POST /api/auth/grants` (`internal/gateway/foundation_routes.go`) sits behind
`RequireSuperadmin` — only a caller holding `auth.platform_administration.access` (the
`kiban-superadmin` platform role) may call this route; every other caller gets 403. Behind the
guard, the authz service additionally binds the tuples to the request's company and one enabled
module, as described above. v1 keeps the grant recipe honest this way: only superadmins grant
(per-object manager-relation delegation is not supported yet). `grantObjectAccess`'s **logic**
is covered by `test/recipes/grantObjectAccess.test.ts` (mocked fetch: company + tuple shape and
grant/revoke op mapping); the **live** e2e test is `e2e/login.spec.ts`, using the seeded
superadmin's bearer to anchor, grant, revoke and un-anchor a fixture document in a fixture
company.
