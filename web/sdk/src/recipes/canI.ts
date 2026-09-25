// SPDX-License-Identifier: Apache-2.0

// Recipe: "can I <feature> in <company>?" — one call over effectiveAccess.can(), collapsing the
// wire decision into a boolean + reason for the common case.
//
// Gateway-exposed: built directly on effectiveAccess.ts, whose own doc comment explains the
// underlying route — `POST /api/auth/effective-access/can`. Unit-tested in
// test/recipes/canI.test.ts (request shape and allowed/denied/evidence mapping) and exercised
// live by e2e/login.spec.ts.
import type { EffectiveAccessClient } from "../effectiveAccess.js";
import type { EffectiveAccessObjectRef, EffectiveAccessReasonValue } from "../types.js";

/** Parameters for the `canI` recipe — a subset of {@link EffectiveAccessClient.can}'s
 * request shape, with `scope` derived from whether `companyId` is set. */
export interface CanIParams {
  featureKey: string;
  moduleKey?: string;
  /** Omit for a global-scope check (e.g. superadministration); set for a company-scope
   * check. */
  companyId?: string;
  requiredPlatformRole?: string;
  requiredCompanyRole?: string;
  object?: EffectiveAccessObjectRef;
  relation?: string;
  requiresEligibility?: boolean;
}

/** The `canI` recipe's collapsed result: allow/deny + the canonical reason string. */
export interface CanIResult {
  allowed: boolean;
  reason: EffectiveAccessReasonValue | string;
}

/** Builds the `canI(params)` recipe over an already-constructed EffectiveAccessClient. */
export function createCanI(effectiveAccess: EffectiveAccessClient) {
  return async function canI(params: CanIParams): Promise<CanIResult> {
    const decision = await effectiveAccess.can({
      featureKey: params.featureKey,
      moduleKey: params.moduleKey,
      scope: params.companyId ? "company" : "global",
      companyId: params.companyId,
      requiredPlatformRole: params.requiredPlatformRole,
      requiredCompanyRole: params.requiredCompanyRole,
      object: params.object,
      relation: params.relation,
      requiresEligibility: params.requiresEligibility
    });
    return { allowed: decision.allowed, reason: decision.reason };
  };
}
