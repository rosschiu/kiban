// SPDX-License-Identifier: Apache-2.0

import { act, renderHook, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}

// getShellSdk() memoizes an api client that captures `fetch` at build time, so each test gets a
// fresh module graph (and therefore a fresh client over its own fetch spy).
async function loadHook() {
  return (await import("../../src/hooks/use-demo-mode")).useDemoMode;
}

describe("useDemoMode", () => {
  beforeEach(() => {
    vi.resetModules();
  });
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("resolves to true when GET /api/platform/demo-mode answers enabled: true", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(jsonResponse(200, { data: { enabled: true } }));
    const useDemoMode = await loadHook();

    const { result } = renderHook(() => useDemoMode());
    expect(result.current).toBe(false); // initial render, before the fetch resolves

    await waitFor(() => expect(result.current).toBe(true));
  });

  it("stays false when the deployment is not the demo (enabled: false)", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(jsonResponse(200, { data: { enabled: false } }));
    const useDemoMode = await loadHook();

    const { result } = renderHook(() => useDemoMode());
    await act(async () => {
      await Promise.resolve();
    });
    expect(result.current).toBe(false);
  });

  it("fails closed to false on a network/server error", async () => {
    vi.spyOn(globalThis, "fetch").mockRejectedValue(new Error("network down"));
    const useDemoMode = await loadHook();

    const { result } = renderHook(() => useDemoMode());
    await act(async () => {
      await Promise.resolve();
    });
    expect(result.current).toBe(false);
  });
});
