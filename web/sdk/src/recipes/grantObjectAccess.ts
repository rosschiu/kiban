// SPDX-License-Identifier: Apache-2.0

// Recipe: "share object X with user Y as <relation>" — one call over the gateway's
// superadmin-guarded grant route (POST /api/auth/grants, internal/gateway/foundation_routes.go,
// forwarding to authz's handleGrants), admin bearer.
//
// The route sits behind the superadmin guard (RequireSuperadmin — only a caller holding
// `auth.platform_administration.access` may call it; every other caller gets 403), and
// handleGrants binds every tuple to `companyId` and the one enabled module that declares the
// object type (a module object must be anchored to `company_module:<companyId>/<module>`).
// Exercised live by e2e/login.spec.ts (the superadmin bearer grants, then revokes, a fixture
// object).
import type { ApiClient } from "../client.js";
import type { AuthzTuple } from "../types.js";

/** Parameters for `grantObjectAccess`/`revokeObjectAccess` — the company the tuple is bound to
 * plus one authz tuple, plain-user or userset (`subjectRelation` set) subject. */
export interface GrantObjectAccessParams {
  /** The company whose module owns the object (`grantsRequestWire.companyId`, a UUID). */
  companyId: string;
  objectType: string;
  objectId: string;
  relation: string;
  subjectType: string;
  subjectId: string;
  subjectRelation?: string;
  correlationId?: string;
}

/** Result of a grant/revoke call (`/api/auth/grants`'s own `{status,count}` shape). */
export interface GrantObjectAccessResult {
  status: string;
  count: number;
}

/** Builds the `grantObjectAccess(params)` recipe over a raw ApiClient (authz's grants endpoint
 * has no dedicated named client in Design's file list — see org.ts/effectiveAccess.ts for the
 * three that do). Also exports `revokeObjectAccess` for the inverse op (same endpoint,
 * `op: "revoke"`). */
export function createGrantObjectAccess(client: ApiClient) {
  function toTuple(params: GrantObjectAccessParams): AuthzTuple {
    return {
      objectType: params.objectType,
      objectId: params.objectId,
      relation: params.relation,
      subjectType: params.subjectType,
      subjectId: params.subjectId,
      subjectRelation: params.subjectRelation
    };
  }

  async function grantObjectAccess(params: GrantObjectAccessParams): Promise<GrantObjectAccessResult> {
    return client.request<GrantObjectAccessResult>("/api/auth/grants", {
      method: "POST",
      body: { op: "grant", companyId: params.companyId, tuples: [toTuple(params)], correlationId: params.correlationId }
    });
  }

  async function revokeObjectAccess(params: GrantObjectAccessParams): Promise<GrantObjectAccessResult> {
    return client.request<GrantObjectAccessResult>("/api/auth/grants", {
      method: "POST",
      body: { op: "revoke", companyId: params.companyId, tuples: [toTuple(params)], correlationId: params.correlationId }
    });
  }

  return {
    /** Grants the tuple described by `params`. */
    grantObjectAccess,
    /** Revokes the tuple described by `params` (same shape, inverse op). */
    revokeObjectAccess
  };
}
