// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it, vi } from "vitest";
import { createApiClient } from "../src/client.js";
import { createCapabilitiesClient } from "../src/capabilities.js";

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}

describe("createCapabilitiesClient", () => {
  it("list() calls GET /api/platform/capabilities and unwraps the array", async () => {
    const capability = {
      module: "core",
      installed: true,
      enabled: true,
      dependencies: [],
      missingDependencies: []
    };
    const fetchFn = vi.fn().mockResolvedValue(jsonResponse(200, { data: [capability] }));
    const client = createCapabilitiesClient(createApiClient({ baseUrl: "https://gateway.test", fetchFn }));

    const result = await client.list();

    expect(result).toEqual([capability]);
    const [url] = fetchFn.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("https://gateway.test/api/platform/capabilities");
  });

  it("get(moduleKey) calls GET /api/platform/capabilities/{module}, URI-encoded", async () => {
    const capability = {
      module: "core",
      installed: false,
      enabled: false,
      dependencies: ["auth"],
      missingDependencies: ["auth"]
    };
    const fetchFn = vi.fn().mockResolvedValue(jsonResponse(200, { data: capability }));
    const client = createCapabilitiesClient(createApiClient({ baseUrl: "https://gateway.test", fetchFn }));

    const result = await client.get("core/sub");

    expect(result).toEqual(capability);
    const [url] = fetchFn.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("https://gateway.test/api/platform/capabilities/core%2Fsub");
  });

  it("get() surfaces a NOT_FOUND KibanApiError for an unknown module", async () => {
    const fetchFn = vi.fn().mockResolvedValue(
      jsonResponse(404, { error: { code: "NOT_FOUND", message: "module not found in the registry catalog" } })
    );
    const client = createCapabilitiesClient(createApiClient({ baseUrl: "https://gateway.test", fetchFn }));

    await expect(client.get("nope")).rejects.toMatchObject({ status: 404, code: "NOT_FOUND" });
  });
});
