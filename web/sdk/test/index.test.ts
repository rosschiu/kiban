// SPDX-License-Identifier: Apache-2.0

// index.ts is the package's public import surface (the barrel file every host app actually
// imports from). This test forces the barrel module itself to load and asserts every runtime
// export it re-exports is present and is the expected kind of value — catching an accidental
// broken/missing re-export at the barrel level, which per-module unit tests (importing straight
// from src/*.js) would never exercise.
import { describe, expect, it } from "vitest";
import * as sdk from "../src/index.js";

describe("SDK public import surface (src/index.ts)", () => {
  it("re-exports every client factory as a function", () => {
    expect(typeof sdk.createApiClient).toBe("function");
    expect(typeof sdk.createCapabilitiesClient).toBe("function");
    expect(typeof sdk.createEffectiveAccessClient).toBe("function");
    expect(typeof sdk.createOrgClient).toBe("function");
    expect(typeof sdk.createInternalOrgClient).toBe("function");
    expect(typeof sdk.createSuperadminClient).toBe("function");
    expect(typeof sdk.createCanI).toBe("function");
    expect(typeof sdk.createGrantObjectAccess).toBe("function");
  });

  it("re-exports the auth module's factories as functions", () => {
    expect(typeof sdk.createSession).toBe("function");
    expect(typeof sdk.createSessionContext).toBe("function");
    expect(typeof sdk.decodeIdTokenClaims).toBe("function");
    expect(typeof sdk.generateCodeChallenge).toBe("function");
    expect(typeof sdk.generateCodeVerifier).toBe("function");
    expect(typeof sdk.generateRandomToken).toBe("function");
  });

  it("re-exports the storage adapters as functions", () => {
    expect(typeof sdk.createMemoryStorage).toBe("function");
    expect(typeof sdk.defaultLocalStorage).toBe("function");
    expect(typeof sdk.defaultSessionStorage).toBe("function");
  });

  it("re-exports KibanApiError as the same class used by the client module", () => {
    expect(sdk.KibanApiError).toBeInstanceOf(Function);
    const err = new sdk.KibanApiError(404, "NOT_FOUND", "nope");
    expect(err).toBeInstanceOf(Error);
    expect(err.name).toBe("KibanApiError");
  });

  it("re-exports queryKeys as the same factory object (identity, not a rebuild)", () => {
    expect(sdk.queryKeys.capabilities.all).toEqual(["capabilities"]);
  });

  it("re-exports the ApiErrorCode and EffectiveAccessReason contract objects", () => {
    expect(sdk.ApiErrorCode.NotFound).toBe("NOT_FOUND");
    expect(sdk.EffectiveAccessReason.Allowed).toBe("ALLOWED");
  });
});
