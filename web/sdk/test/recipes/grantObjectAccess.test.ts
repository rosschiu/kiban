// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it, vi } from "vitest";
import { createApiClient } from "../../src/client.js";
import { createGrantObjectAccess } from "../../src/recipes/grantObjectAccess.js";

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}

describe("grantObjectAccess recipe", () => {
  it("grantObjectAccess() posts op:'grant' with the company and one tuple to /api/auth/grants", async () => {
    const fetchFn = vi.fn().mockResolvedValue(jsonResponse(200, { data: { status: "ok", count: 1 } }));
    const client = createApiClient({ baseUrl: "https://gateway.test", fetchFn });
    const { grantObjectAccess } = createGrantObjectAccess(client);

    const result = await grantObjectAccess({
      companyId: "c1",
      objectType: "directory",
      objectId: "dir-1",
      relation: "viewer",
      subjectType: "user",
      subjectId: "user-1",
      correlationId: "corr-1"
    });

    expect(result).toEqual({ status: "ok", count: 1 });
    const [url, init] = fetchFn.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("https://gateway.test/api/auth/grants");
    expect(init.method).toBe("POST");
    expect(JSON.parse(init.body as string)).toEqual({
      op: "grant",
      companyId: "c1",
      tuples: [
        {
          objectType: "directory",
          objectId: "dir-1",
          relation: "viewer",
          subjectType: "user",
          subjectId: "user-1",
          subjectRelation: undefined
        }
      ],
      correlationId: "corr-1"
    });
  });

  it("revokeObjectAccess() posts op:'revoke' with the same company and tuple shape", async () => {
    const fetchFn = vi.fn().mockResolvedValue(jsonResponse(200, { data: { status: "ok", count: 1 } }));
    const client = createApiClient({ baseUrl: "https://gateway.test", fetchFn });
    const { revokeObjectAccess } = createGrantObjectAccess(client);

    await revokeObjectAccess({ companyId: "c1", objectType: "directory", objectId: "dir-1", relation: "viewer", subjectType: "user", subjectId: "user-1" });

    const [, init] = fetchFn.mock.calls[0] as [string, RequestInit];
    expect(JSON.parse(init.body as string)).toMatchObject({ op: "revoke", companyId: "c1" });
  });

  it("surfaces a KibanApiError for a non-2xx response (e.g. 403 from the superadmin guard when the caller isn't a superadmin)", async () => {
    const fetchFn = vi.fn().mockResolvedValue(jsonResponse(404, { error: { code: "NOT_FOUND", message: "not found" } }));
    const client = createApiClient({ baseUrl: "https://gateway.test", fetchFn });
    const { grantObjectAccess } = createGrantObjectAccess(client);

    await expect(
      grantObjectAccess({ companyId: "c1", objectType: "directory", objectId: "dir-1", relation: "viewer", subjectType: "user", subjectId: "user-1" })
    ).rejects.toMatchObject({ status: 404 });
  });
});
