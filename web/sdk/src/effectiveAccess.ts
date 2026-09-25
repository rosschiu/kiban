// SPDX-License-Identifier: Apache-2.0

// Typed client over the gateway's self-scoped effective-access surface
// (internal/gateway/foundation_routes.go — `POST /api/auth/effective-access/can`,
// `POST /api/auth/effective-access/batch-can`, `GET /api/auth/effective-access/summary`).
//
// The gateway bearer-validates every call and (for `can`/`batch-can`) forwards to authz's own endpoint, which
// itself rejects any request body naming a subject other than the bearer (400) — the SDK never
// sends one (no actor/subject field exists on EffectiveAccessRequest). `summary` additionally has
// its `kcSub` INJECTED by the gateway from the validated bearer, never accepted from the caller —
// there is no kcSub parameter on this client's `summary()` at all, by construction. Exercised
// live by e2e/login.spec.ts (login -> summary -> can -> ...).
import type { ApiClient } from "./client.js";
import type {
  EffectiveAccessBatchItem,
  EffectiveAccessBatchResult,
  EffectiveAccessDecision,
  EffectiveAccessRequest,
  EffectiveAccessSummary
} from "./types.js";

/** Typed client over the gateway's self-scoped effective-access surface. */
export interface EffectiveAccessClient {
  /** POST /api/auth/effective-access/can — one decision, self-scoped (the gateway forwards to
   * authz's `/internal/authz/effective-access/can`, which rejects any body naming a different
   * subject than the bearer). */
  can(request: EffectiveAccessRequest): Promise<EffectiveAccessDecision>;
  /** POST /api/auth/effective-access/batch-can — one decision per item, sharing the base
   * request's scope/company/role fields (batchCanRequestWire embeds canRequestWire). */
  batchCan(
    request: EffectiveAccessRequest & { items: EffectiveAccessBatchItem[] }
  ): Promise<EffectiveAccessBatchResult[]>;
  /** GET /api/auth/effective-access/summary[?companyId=] — the caller's own EffectiveAccessSummary
   * (apiVersion 1): featureKeys/roleBindings/objectAccess for shell nav/feature gating. `kcSub` is
   * gateway-injected from the bearer; there is no way to ask for anyone else's summary through
   * this client. companyId is optional — omit for the global-scope-only fields. */
  summary(companyId?: string): Promise<EffectiveAccessSummary>;
}

/** Builds an {@link EffectiveAccessClient} over `client`. */
export function createEffectiveAccessClient(client: ApiClient): EffectiveAccessClient {
  return {
    can: (request) =>
      client.request<EffectiveAccessDecision>("/api/auth/effective-access/can", {
        method: "POST",
        body: request
      }),
    batchCan: (request) =>
      client.request<EffectiveAccessBatchResult[]>("/api/auth/effective-access/batch-can", {
        method: "POST",
        body: request
      }),
    summary: (companyId) =>
      client.request<EffectiveAccessSummary>("/api/auth/effective-access/summary", {
        query: { companyId }
      })
  };
}
