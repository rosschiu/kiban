// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it, vi } from "vitest";
import { createApiClient } from "../src/client.js";
import { createDemoModeClient } from "../src/demoMode.js";

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}

describe("createDemoModeClient", () => {
  it("get() calls GET /api/platform/demo-mode and unwraps {enabled}", async () => {
    const fetchFn = vi.fn().mockResolvedValue(jsonResponse(200, { data: { enabled: true } }));
    const client = createDemoModeClient(createApiClient({ baseUrl: "https://gateway.test", fetchFn }));

    const result = await client.get();

    expect(result).toEqual({ enabled: true });
    const [url] = fetchFn.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("https://gateway.test/api/platform/demo-mode");
  });

  it("get() reflects enabled: false for a non-demo deployment", async () => {
    const fetchFn = vi.fn().mockResolvedValue(jsonResponse(200, { data: { enabled: false } }));
    const client = createDemoModeClient(createApiClient({ baseUrl: "https://gateway.test", fetchFn }));

    const result = await client.get();

    expect(result).toEqual({ enabled: false });
  });

  it("works with no bearer token configured (unauthenticated route)", async () => {
    const fetchFn = vi.fn().mockResolvedValue(jsonResponse(200, { data: { enabled: true } }));
    const client = createDemoModeClient(createApiClient({ baseUrl: "https://gateway.test", fetchFn, getAccessToken: () => null }));

    await client.get();

    const [, init] = fetchFn.mock.calls[0] as [string, RequestInit];
    expect((init.headers as Record<string, string>).Authorization).toBeUndefined();
  });
});
