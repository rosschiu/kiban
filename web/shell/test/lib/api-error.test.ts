// SPDX-License-Identifier: Apache-2.0

import { KibanApiError } from "@rosschiu/kiban-sdk";
import { describe, expect, it } from "vitest";
import { describeApiError, isServiceFailure } from "../../src/lib/api-error";

const fallback = "Could not load the thing.";

describe("describeApiError", () => {
  it("maps 401 to a session-expired message", () => {
    expect(describeApiError(new KibanApiError(401, "AUTH_TOKEN_INVALID", "x"), fallback)).toBe(
      "Your session has expired. Please log in again.",
    );
  });

  it("maps 403 to a not-authorized message", () => {
    expect(describeApiError(new KibanApiError(403, "AUTHORIZATION_DENIED", "x"), fallback)).toBe(
      "You do not have permission to do this.",
    );
  });

  it("maps 503 to a temporarily-unavailable message, distinct from a permissions problem", () => {
    expect(describeApiError(new KibanApiError(503, "AUTHORIZATION_UNAVAILABLE", "x"), fallback)).toBe(
      "The service is temporarily unavailable. Please try again in a moment.",
    );
  });

  it("maps other 5xx to a server-error message carrying the correlation id", () => {
    expect(describeApiError(new KibanApiError(500, "INTERNAL_ERROR", "x", undefined, "cid-1"), fallback)).toBe(
      "Something went wrong on the server. Please try again (reference cid-1).",
    );
    expect(describeApiError(new KibanApiError(502, "UNKNOWN_ERROR", "x"), fallback)).toBe(
      "Something went wrong on the server. Please try again.",
    );
  });

  it("maps a fetch TypeError (no response at all) to a connection message", () => {
    expect(describeApiError(new TypeError("Failed to fetch"), fallback)).toBe(
      "Could not reach the server. Check your connection and try again.",
    );
  });

  it("returns the page's own fallback for plain 4xx and for unknown errors", () => {
    expect(describeApiError(new KibanApiError(404, "NOT_FOUND", "x"), fallback)).toBe(fallback);
    expect(describeApiError(new KibanApiError(409, "CONFLICT", "x"), fallback)).toBe(fallback);
    expect(describeApiError(new Error("boom"), fallback)).toBe(fallback);
    expect(describeApiError("string", fallback)).toBe(fallback);
  });
});

describe("isServiceFailure", () => {
  it("is true only for 5xx and network failures", () => {
    expect(isServiceFailure(new KibanApiError(503, "AUTHORIZATION_UNAVAILABLE", "x"))).toBe(true);
    expect(isServiceFailure(new KibanApiError(500, "INTERNAL_ERROR", "x"))).toBe(true);
    expect(isServiceFailure(new TypeError("Failed to fetch"))).toBe(true);
    expect(isServiceFailure(new KibanApiError(403, "AUTHORIZATION_DENIED", "x"))).toBe(false);
    expect(isServiceFailure(new KibanApiError(404, "NOT_FOUND", "x"))).toBe(false);
    expect(isServiceFailure(new Error("boom"))).toBe(false);
  });
});
