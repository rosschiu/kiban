// SPDX-License-Identifier: Apache-2.0

// types.ts is mostly type-only declarations (erased at compile time, zero runtime statements),
// but it also exports two runtime const objects whose exact string values ARE the wire contract
// with the Go services (internal/errenv's APIError.code, internal/authz/decision's Reason) —
// "Exact strings are contract" per the source comments. These are behavioral assertions on that
// contract, not coverage padding: a value drifting here silently breaks every caller matching on
// `error.code` or `decision.reason`.
import { describe, expect, it } from "vitest";
import { ApiErrorCode, EffectiveAccessReason } from "../src/types.js";

describe("ApiErrorCode — internal/errenv canonical error codes", () => {
  it("maps every known key to its exact wire string", () => {
    expect(ApiErrorCode).toEqual({
      BadRequest: "BAD_REQUEST",
      AuthTokenMissing: "AUTH_TOKEN_MISSING",
      AuthTokenInvalid: "AUTH_TOKEN_INVALID",
      Forbidden: "FORBIDDEN",
      AuthorizationDenied: "AUTHORIZATION_DENIED",
      ModuleNotInstalled: "MODULE_NOT_INSTALLED",
      ModuleDisabled: "MODULE_DISABLED",
      ModuleDependencyMissing: "MODULE_DEPENDENCY_MISSING",
      ModuleUnavailable: "MODULE_UNAVAILABLE",
      PayloadTooLarge: "PAYLOAD_TOO_LARGE",
      NotFound: "NOT_FOUND",
      Conflict: "CONFLICT",
      ValidationError: "VALIDATION_ERROR",
      InternalError: "INTERNAL_ERROR",
      AuthorizationUnavailable: "AUTHORIZATION_UNAVAILABLE",
      ValidationFailed: "VALIDATION_FAILED",
      IdempotencyConflict: "IDEMPOTENCY_CONFLICT",
      GroupExternallyManaged: "GROUP_EXTERNALLY_MANAGED"
    });
  });

  it("every value is UPPER_SNAKE_CASE (the wire convention)", () => {
    for (const value of Object.values(ApiErrorCode)) {
      expect(value).toMatch(/^[A-Z][A-Z0-9_]*$/);
    }
  });
});

describe("EffectiveAccessReason — internal/authz/decision canonical reasons", () => {
  it("maps every known key to its exact wire string", () => {
    expect(EffectiveAccessReason).toEqual({
      Allowed: "ALLOWED",
      AuthUserNotFound: "AUTH_USER_NOT_FOUND",
      KeycloakDisabled: "KEYCLOAK_DISABLED",
      UserLifecycleDisabled: "USER_LIFECYCLE_DISABLED",
      CompanyInactive: "COMPANY_INACTIVE",
      CompanyMembershipRequired: "COMPANY_MEMBERSHIP_REQUIRED",
      CompanyAccessBlocked: "COMPANY_ACCESS_BLOCKED",
      ModuleDisabled: "MODULE_DISABLED",
      PlatformRoleRequired: "PLATFORM_ROLE_REQUIRED",
      CompanyRoleRequired: "COMPANY_ROLE_REQUIRED",
      EngineDenied: "ENGINE_DENIED",
      BusinessEligibilityDenied: "BUSINESS_ELIGIBILITY_DENIED",
      DependencyUnavailable: "DEPENDENCY_UNAVAILABLE"
    });
  });

  it("Allowed is the single positive reason; every other value is a denial reason", () => {
    expect(EffectiveAccessReason.Allowed).toBe("ALLOWED");
    const denials = Object.entries(EffectiveAccessReason).filter(([key]) => key !== "Allowed");
    expect(denials.length).toBe(Object.keys(EffectiveAccessReason).length - 1);
    for (const [, value] of denials) {
      expect(value).not.toBe("ALLOWED");
    }
  });
});
