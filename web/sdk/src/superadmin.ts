// SPDX-License-Identifier: Apache-2.0

// Typed client over the gateway's `/api/platform/*` surface (internal/gateway/
// platform_routes.go + foundation_routes.go): capability/catalog reads (bearer-only) plus the
// superadmin-guarded module enable/disable and platform-role grant/revoke mutations. Exercised
// live by e2e/login.spec.ts (login → capabilities → this client's `enableModule` → logout).
import type { ApiClient } from "./client.js";
import type { CatalogEntry } from "./types.js";

/** Typed client over the gateway's `/api/platform/*` capability/catalog reads and
 * superadmin-guarded module enable/disable mutations. */
export interface SuperadminClient {
  /** GET /api/platform/catalog — the full module catalog (routing metadata; no auth gate at
   * registry's own layer, but the gateway still requires a bearer per mountPlatformRoutes). */
  catalog(): Promise<CatalogEntry[]>;
  /** POST /api/platform/admin/modules/{key}/enable — requires the caller to hold
   * `auth.platform_administration.access` (superadmin); 403 KibanApiError otherwise. */
  enableModule(moduleKey: string): Promise<{ enabled: boolean }>;
  /** POST /api/platform/admin/modules/{key}/disable — same guard as enableModule. */
  disableModule(moduleKey: string): Promise<{ enabled: boolean }>;
  /** POST /api/platform/admin/platform-roles — grant `role` (only `"kiban-superadmin"` exists) to
   * the user identified by `subjectId` (their Keycloak subject id). Same guard as enableModule;
   * 404 when identity has never seen the subject; 422 for any other role. */
  grantPlatformRole(subjectId: string, role: PlatformRole): Promise<PlatformRoleGrant>;
  /** DELETE /api/platform/admin/platform-roles/{role}/{subjectId} — revoke it. 404 when the
   * subject does not hold the role; 409 CONFLICT when it is the platform's last superadmin (the
   * caller revoking themselves included). */
  revokePlatformRole(subjectId: string, role: PlatformRole): Promise<PlatformRoleGrant>;
}

/** The platform roles — exactly one exists. */
export type PlatformRole = "kiban-superadmin";

/** A platform-role grant/revoke result: the subject and role the call applied to. */
export interface PlatformRoleGrant {
  subjectId: string;
  role: PlatformRole;
}

/** Builds a {@link SuperadminClient} over `client`. */
export function createSuperadminClient(client: ApiClient): SuperadminClient {
  return {
    catalog: () => client.request<CatalogEntry[]>("/api/platform/catalog"),
    enableModule: (moduleKey) =>
      client.request<{ enabled: boolean }>(`/api/platform/admin/modules/${encodeURIComponent(moduleKey)}/enable`, {
        method: "POST"
      }),
    disableModule: (moduleKey) =>
      client.request<{ enabled: boolean }>(`/api/platform/admin/modules/${encodeURIComponent(moduleKey)}/disable`, {
        method: "POST"
      }),
    grantPlatformRole: (subjectId, role) =>
      client.request<PlatformRoleGrant>("/api/platform/admin/platform-roles", {
        method: "POST",
        body: { subjectId, role }
      }),
    revokePlatformRole: (subjectId, role) =>
      client.request<PlatformRoleGrant>(
        `/api/platform/admin/platform-roles/${encodeURIComponent(role)}/${encodeURIComponent(subjectId)}`,
        { method: "DELETE" }
      )
  };
}
