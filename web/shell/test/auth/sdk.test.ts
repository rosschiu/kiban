// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { getShellSdk } from "../../src/auth/sdk";

describe("getShellSdk", () => {
  it("memoizes the session + api client across calls", () => {
    const first = getShellSdk();
    const second = getShellSdk();
    expect(second.session).toBe(first.session);
    expect(second.apiClient).toBe(first.apiClient);
  });

  it("builds an api client pointed at the gateway origin", () => {
    const { apiClient } = getShellSdk();
    expect(apiClient.baseUrl).toBe(window.location.origin);
  });
});
