// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it, vi } from "vitest";
import { createApiClient } from "../src/client.js";
import { createEffectiveAccessClient } from "../src/effectiveAccess.js";

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}

describe("createEffectiveAccessClient", () => {
  it("can() posts to /api/auth/effective-access/can and unwraps the decision", async () => {
    const decision = { allowed: true, reason: "ALLOWED", evidence: [] };
    const fetchFn = vi.fn().mockResolvedValue(jsonResponse(200, { data: decision }));
    const client = createEffectiveAccessClient(createApiClient({ baseUrl: "https://gateway.test", fetchFn }));

    const result = await client.can({ featureKey: "auth.platform_administration.access", scope: "global" });

    expect(result).toEqual(decision);
    const [url, init] = fetchFn.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("https://gateway.test/api/auth/effective-access/can");
    expect(init.method).toBe("POST");
    expect(JSON.parse(init.body as string)).toEqual({
      featureKey: "auth.platform_administration.access",
      scope: "global"
    });
  });

  it("batchCan() posts to /api/auth/effective-access/batch-can and unwraps the results array", async () => {
    const results = [
      { object: { type: "company", id: "c1" }, relation: "viewer", decision: { allowed: false, reason: "COMPANY_MEMBERSHIP_REQUIRED", evidence: [] } }
    ];
    const fetchFn = vi.fn().mockResolvedValue(jsonResponse(200, { data: results }));
    const client = createEffectiveAccessClient(createApiClient({ baseUrl: "https://gateway.test", fetchFn }));

    const result = await client.batchCan({
      featureKey: "core.company.view",
      scope: "company",
      companyId: "c1",
      items: [{ object: { type: "company", id: "c1" }, relation: "viewer" }]
    });

    expect(result).toEqual(results);
    const [url] = fetchFn.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("https://gateway.test/api/auth/effective-access/batch-can");
  });

  it("surfaces a KibanApiError for a non-2xx response (e.g. 404 when unreachable through the gateway)", async () => {
    const fetchFn = vi.fn().mockResolvedValue(jsonResponse(404, { error: { code: "NOT_FOUND", message: "not found" } }));
    const client = createEffectiveAccessClient(createApiClient({ baseUrl: "https://gateway.test", fetchFn }));

    await expect(client.can({ featureKey: "x", scope: "global" })).rejects.toMatchObject({ status: 404, code: "NOT_FOUND" });
  });

  it("summary() calls GET /api/auth/effective-access/summary with companyId as a query param, and unwraps the composed summary", async () => {
    const summary = {
      apiVersion: 1,
      subjectId: "kc-sub-1",
      companyId: "company-1",
      moduleKey: "",
      featureKeys: ["auth.platform_administration.access"],
      roleBindings: [{ scope: "global", role: "kiban-superadmin" }],
      objectAccess: [{ objectType: "doc", objectId: "d1", relations: ["viewer"] }],
      rowScopes: [],
      fieldPolicies: []
    };
    const fetchFn = vi.fn().mockResolvedValue(jsonResponse(200, { data: summary }));
    const client = createEffectiveAccessClient(createApiClient({ baseUrl: "https://gateway.test", fetchFn }));

    const result = await client.summary("company-1");

    expect(result).toEqual(summary);
    const [url] = fetchFn.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("https://gateway.test/api/auth/effective-access/summary?companyId=company-1");
  });

  it("summary() omits companyId from the query when not given (no kcSub param exists on this method — the gateway injects it)", async () => {
    const summary = {
      apiVersion: 1,
      subjectId: "kc-sub-1",
      companyId: "",
      moduleKey: "",
      featureKeys: [],
      roleBindings: [],
      objectAccess: [],
      rowScopes: [],
      fieldPolicies: []
    };
    const fetchFn = vi.fn().mockResolvedValue(jsonResponse(200, { data: summary }));
    const client = createEffectiveAccessClient(createApiClient({ baseUrl: "https://gateway.test", fetchFn }));

    await client.summary();

    const [url] = fetchFn.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("https://gateway.test/api/auth/effective-access/summary");
  });
});
