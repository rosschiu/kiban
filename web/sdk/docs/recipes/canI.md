# Recipe: `canI` — "can I `<feature>` in `<company>`?"

Named use-case recipe: one call that answers a plain yes/no-with-reason question
against authz's effective-access decision, instead of hand-assembling `canRequestWire` fields
every call site.

## Pattern

```ts
import { createApiClient, createEffectiveAccessClient, createCanI } from "@rosschiu/kiban-sdk";

const apiClient = createApiClient({
  baseUrl: "https://127.0.0.1:8443", // always the gateway origin
  getAccessToken: () => session.getAccessToken(),
  refreshAccessToken: () => session.refresh()
});

const effectiveAccess = createEffectiveAccessClient(apiClient);
const canI = createCanI(effectiveAccess);

// Global-scope check (no companyId): superadministration, module roles, ...
const superadmin = await canI({
  featureKey: "auth.platform_administration.access",
  requiredPlatformRole: "kiban-superadmin"
});
if (superadmin.allowed) {
  // show the superadmin nav entry
}

// Company-scope check (companyId set): membership/company-role gated features.
const canViewCompany = await canI({
  featureKey: "core.company.view",
  companyId: "11111111-1111-1111-1111-111111111111"
});
if (!canViewCompany.allowed) {
  // canViewCompany.reason is one of decision.Reason's canonical strings, e.g.
  // "COMPANY_MEMBERSHIP_REQUIRED" — safe to show in a FriendlyErrorAlert-style mapping.
}
```

`canI` never throws for a *denial* — a denial is a normal `{allowed:false, reason}` result, same
as authz's own wire contract (`decisionWire`). It throws a `KibanApiError` only for a transport/
envelope failure (network error, 5xx, malformed response) — treat that the same as any other API
call failure (retry/backoff or a `FriendlyErrorAlert`), not as a denial.

## Gateway exposure and tests

`effectiveAccess.can()`/`batchCan()` call the gateway's own self-scoped mounts (`POST
/api/auth/effective-access/can`/`batch-can` — `internal/gateway/foundation_routes.go`), which
forward to authz's real endpoint (`internal/authz/http.go`). The gateway bearer-validates every
call; authz itself rejects any request body naming a subject other than the bearer (400) — `canI`
never sends one. `canI`'s **logic** is covered by `test/recipes/canI.test.ts` (mocked fetch:
request-shape + allowed/denied/evidence mapping); the **live** e2e test is `e2e/login.spec.ts`
(login → summary → `canI` → `grantObjectAccess` → logout).
