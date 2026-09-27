// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it, vi } from "vitest";
import { createApiClient } from "../../src/client.js";
import { createEffectiveAccessClient } from "../../src/effectiveAccess.js";
import { createCanI } from "../../src/recipes/canI.js";

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}

describe("canI recipe", () => {
  it("global scope (no companyId): sends scope:'global' and maps an allowed decision", async () => {
    const fetchFn = vi.fn().mockResolvedValue(jsonResponse(200, { data: { allowed: true, reason: "ALLOWED", evidence: [] } }));
    const effectiveAccess = createEffectiveAccessClient(createApiClient({ baseUrl: "https://gateway.test", fetchFn }));
    const canI = createCanI(effectiveAccess);

    const result = await canI({ featureKey: "auth.platform_administration.access", requiredPlatformRole: "kiban-superadmin" });

    expect(result).toEqual({ allowed: true, reason: "ALLOWED" });
    const [, init] = fetchFn.mock.calls[0] as [string, RequestInit];
    const body = JSON.parse(init.body as string);
    expect(body.scope).toBe("global");
    expect(body.companyId).toBeUndefined();
  });

  it("company scope (companyId set): sends scope:'company' and maps a denied decision + reason", async () => {
    const fetchFn = vi
      .fn()
      .mockResolvedValue(jsonResponse(200, { data: { allowed: false, reason: "COMPANY_MEMBERSHIP_REQUIRED", evidence: [] } }));
    const effectiveAccess = createEffectiveAccessClient(createApiClient({ baseUrl: "https://gateway.test", fetchFn }));
    const canI = createCanI(effectiveAccess);

    const result = await canI({ featureKey: "core.company.view", companyId: "company-1" });

    expect(result).toEqual({ allowed: false, reason: "COMPANY_MEMBERSHIP_REQUIRED" });
    const [, init] = fetchFn.mock.calls[0] as [string, RequestInit];
    const body = JSON.parse(init.body as string);
    expect(body.scope).toBe("company");
    expect(body.companyId).toBe("company-1");
  });

  it("propagates a KibanApiError from the underlying client (e.g. today's 404 through the gateway) rather than swallowing it", async () => {
    const fetchFn = vi.fn().mockResolvedValue(jsonResponse(404, { error: { code: "NOT_FOUND", message: "not found" } }));
    const effectiveAccess = createEffectiveAccessClient(createApiClient({ baseUrl: "https://gateway.test", fetchFn }));
    const canI = createCanI(effectiveAccess);

    await expect(canI({ featureKey: "x" })).rejects.toMatchObject({ status: 404 });
  });
});
