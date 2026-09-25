// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it, vi } from "vitest";
import { createApiClient } from "../src/client.js";
import { createSuperadminClient } from "../src/superadmin.js";

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}

describe("createSuperadminClient", () => {
  it("catalog() calls GET /api/platform/catalog", async () => {
    const entries = [
      {
        moduleKey: "kiban_e2e_fake",
        displayName: "Kiban E2E Fake Module",
        scopeType: "global",
        mandatory: false,
        basePath: "/api/kiban_e2e_fake",
        healthPath: "/health",
        port: 9999,
        licenseClass: "foundation",
        manifestVersion: "0.0.0-test",
        isActive: true,
        installed: true,
        enabled: true
      }
    ];
    const fetchFn = vi.fn().mockResolvedValue(jsonResponse(200, { data: entries }));
    const client = createSuperadminClient(createApiClient({ baseUrl: "https://gateway.test", fetchFn }));

    const result = await client.catalog();

    expect(result).toEqual(entries);
    const [url] = fetchFn.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("https://gateway.test/api/platform/catalog");
  });

  it("enableModule() posts to /api/platform/admin/modules/{key}/enable, URI-encoded", async () => {
    const fetchFn = vi.fn().mockResolvedValue(jsonResponse(200, { data: { enabled: true } }));
    const client = createSuperadminClient(createApiClient({ baseUrl: "https://gateway.test", fetchFn }));

    const result = await client.enableModule("kiban_e2e_fake");

    expect(result).toEqual({ enabled: true });
    const [url, init] = fetchFn.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("https://gateway.test/api/platform/admin/modules/kiban_e2e_fake/enable");
    expect(init.method).toBe("POST");
  });

  it("disableModule() surfaces a FORBIDDEN KibanApiError for a non-superadmin caller", async () => {
    const fetchFn = vi
      .fn()
      .mockResolvedValue(jsonResponse(403, { error: { code: "FORBIDDEN", message: "superadministration requires superadmin access" } }));
    const client = createSuperadminClient(createApiClient({ baseUrl: "https://gateway.test", fetchFn }));

    await expect(client.disableModule("kiban_e2e_fake")).rejects.toMatchObject({ status: 403, code: "FORBIDDEN" });
  });

  it("grantPlatformRole() posts {subjectId, role} to /api/platform/admin/platform-roles", async () => {
    const fetchFn = vi.fn().mockResolvedValue(jsonResponse(200, { data: { subjectId: "kc-sub-1", role: "kiban-superadmin" } }));
    const client = createSuperadminClient(createApiClient({ baseUrl: "https://gateway.test", fetchFn }));

    const result = await client.grantPlatformRole("kc-sub-1", "kiban-superadmin");

    expect(result).toEqual({ subjectId: "kc-sub-1", role: "kiban-superadmin" });
    const [url, init] = fetchFn.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("https://gateway.test/api/platform/admin/platform-roles");
    expect(init.method).toBe("POST");
    expect(JSON.parse(init.body as string)).toEqual({ subjectId: "kc-sub-1", role: "kiban-superadmin" });
  });

  it("revokePlatformRole() deletes /api/platform/admin/platform-roles/{role}/{subjectId} and surfaces the last-superadmin 409", async () => {
    const fetchFn = vi
      .fn()
      .mockResolvedValue(jsonResponse(409, { error: { code: "CONFLICT", message: "at least one superadmin must remain" } }));
    const client = createSuperadminClient(createApiClient({ baseUrl: "https://gateway.test", fetchFn }));

    await expect(client.revokePlatformRole("kc sub/1", "kiban-superadmin")).rejects.toMatchObject({ status: 409, code: "CONFLICT" });
    const [url, init] = fetchFn.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("https://gateway.test/api/platform/admin/platform-roles/kiban-superadmin/kc%20sub%2F1");
    expect(init.method).toBe("DELETE");
  });
});
