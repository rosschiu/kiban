// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it, vi } from "vitest";

// Regression test: getShellSdk() must opt into the SDK's `persistTokens`
// (default false, "memory-only, the safer default" per auth/session.ts) — otherwise a real
// browser's full-page navigation (a bookmark, a shared link, a refresh — exactly what the
// dynamic module route hosts are built to support) silently drops the session (sign in, then
// `page.goto()` a direct module-state URL bounces back to
// /login). Isolated into its own file/mock so the existing test/auth/sdk.test.ts keeps exercising
// the REAL createSession/createApiClient.
const createSession = vi.fn((_config: Record<string, unknown>) => ({ getAccessToken: () => null, refresh: vi.fn() }));
const createApiClient = vi.fn((_config: Record<string, unknown>) => ({ baseUrl: "https://gateway.invalid", request: vi.fn() }));

vi.mock("@rosschiu/kiban-sdk", () => ({
  createSession: (config: Record<string, unknown>) => createSession(config),
  createApiClient: (config: Record<string, unknown>) => createApiClient(config),
}));

const { getShellSdk } = await import("../../src/auth/sdk");

describe("getShellSdk persistTokens wiring", () => {
  it("passes persistTokens: true to createSession", () => {
    getShellSdk();
    expect(createSession).toHaveBeenCalledTimes(1);
    expect(createSession.mock.calls[0]?.[0]).toMatchObject({ persistTokens: true });
  });
});
