// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it, vi } from "vitest";
import { createApiClient } from "../src/client.js";
import { createOrgClient } from "../src/org.js";

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}

describe("createOrgClient", () => {
  it("meCompanies() calls GET /api/org/me/companies (gateway-exposed, kcSub injected server-side — no id/kcSub parameter on this method)", async () => {
    const companies = [{ id: "c1", code: "ACME", name: "Acme", isActive: true }];
    const fetchFn = vi.fn().mockResolvedValue(jsonResponse(200, { data: companies }));
    const client = createOrgClient(createApiClient({ baseUrl: "https://gateway.test", fetchFn }));

    const result = await client.meCompanies();

    expect(result).toEqual(companies);
    const [url, init] = fetchFn.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("https://gateway.test/api/org/me/companies");
    expect(init.method ?? "GET").toBe("GET");
  });

  // ---- The gateway-exposed `/api/org/admin/...` position surface. ----

  it("adminListPositions() calls GET /api/org/admin/companies/{companyId}/positions with page/pageSize query params", async () => {
    const page = {
      items: [{ id: "p1", companyId: "c1", code: "CFO", title: "CFO", orgUnitId: "c1", assignmentId: "a1", memberId: "m1", holderDisplayName: "Alice" }],
      total: 1,
      page: 1,
      pageSize: 25,
      totalPages: 1
    };
    const fetchFn = vi.fn().mockResolvedValue(jsonResponse(200, { data: page }));
    const client = createOrgClient(createApiClient({ baseUrl: "https://gateway.test", fetchFn }));

    const result = await client.adminListPositions("c1", 2, 10);

    expect(result).toEqual(page);
    const [url, init] = fetchFn.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("https://gateway.test/api/org/admin/companies/c1/positions?page=2&pageSize=10");
    expect(init.method ?? "GET").toBe("GET");
  });

  it("adminCreatePosition() posts {code,title} to /api/org/admin/companies/{companyId}/positions — no companyId/orgUnitId in the body", async () => {
    const position = { id: "p1", companyId: "c1", code: "CFO", title: "CFO", orgUnitId: "c1" };
    const fetchFn = vi.fn().mockResolvedValue(jsonResponse(201, { data: position }));
    const client = createOrgClient(createApiClient({ baseUrl: "https://gateway.test", fetchFn }));

    const result = await client.adminCreatePosition("c1", { code: "cfo", title: "CFO" });

    expect(result).toEqual(position);
    const [url, init] = fetchFn.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("https://gateway.test/api/org/admin/companies/c1/positions");
    expect(init.method).toBe("POST");
    expect(JSON.parse(init.body as string)).toEqual({ code: "cfo", title: "CFO" });
  });

  it("adminAssignPosition() posts {memberId} to /api/org/admin/positions/{id}/assignments", async () => {
    const assignment = { id: "a1", positionId: "p1", memberId: "m1", validFrom: "2026-08-17", validTo: null };
    const fetchFn = vi.fn().mockResolvedValue(jsonResponse(201, { data: assignment }));
    const client = createOrgClient(createApiClient({ baseUrl: "https://gateway.test", fetchFn }));

    const result = await client.adminAssignPosition("p1", "m1");

    expect(result).toEqual(assignment);
    const [url, init] = fetchFn.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("https://gateway.test/api/org/admin/positions/p1/assignments");
    expect(init.method).toBe("POST");
    expect(JSON.parse(init.body as string)).toEqual({ memberId: "m1" });
  });

  it("adminEndAssignment() posts no body to /api/org/admin/assignments/{id}/end", async () => {
    const assignment = { id: "a1", positionId: "p1", memberId: "m1", validFrom: "2026-08-01", validTo: "2026-08-17" };
    const fetchFn = vi.fn().mockResolvedValue(jsonResponse(200, { data: assignment }));
    const client = createOrgClient(createApiClient({ baseUrl: "https://gateway.test", fetchFn }));

    const result = await client.adminEndAssignment("a1");

    expect(result).toEqual(assignment);
    const [url, init] = fetchFn.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("https://gateway.test/api/org/admin/assignments/a1/end");
    expect(init.method).toBe("POST");
    expect(init.body).toBeUndefined();
  });

  // ---- The gateway-exposed `/api/org/admin/...` group surface. ----

  it("adminListGroups() calls GET /api/org/admin/companies/{companyId}/groups with page/pageSize query params", async () => {
    const page = {
      items: [
        {
          id: "g1", companyId: "c1", code: "SUPPORT", name: "Support Team", source: "kiban",
          externalRef: null, isActive: true, isKibanManaged: true, memberCount: 2
        }
      ],
      total: 1,
      page: 1,
      pageSize: 25,
      totalPages: 1
    };
    const fetchFn = vi.fn().mockResolvedValue(jsonResponse(200, { data: page }));
    const client = createOrgClient(createApiClient({ baseUrl: "https://gateway.test", fetchFn }));

    const result = await client.adminListGroups("c1", 2, 10);

    expect(result).toEqual(page);
    const [url, init] = fetchFn.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("https://gateway.test/api/org/admin/companies/c1/groups?page=2&pageSize=10");
    expect(init.method ?? "GET").toBe("GET");
  });

  it("adminCreateGroup() posts {code,name} to /api/org/admin/companies/{companyId}/groups — no companyId in the body", async () => {
    const group = {
      id: "g1", companyId: "c1", code: "SUPPORT", name: "Support Team", source: "kiban",
      externalRef: null, isActive: true, isKibanManaged: true
    };
    const fetchFn = vi.fn().mockResolvedValue(jsonResponse(201, { data: group }));
    const client = createOrgClient(createApiClient({ baseUrl: "https://gateway.test", fetchFn }));

    const result = await client.adminCreateGroup("c1", { code: "support", name: "Support Team" });

    expect(result).toEqual(group);
    const [url, init] = fetchFn.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("https://gateway.test/api/org/admin/companies/c1/groups");
    expect(init.method).toBe("POST");
    expect(JSON.parse(init.body as string)).toEqual({ code: "support", name: "Support Team" });
  });

  it("adminListGroupMembers() calls GET /api/org/admin/groups/{id}/members", async () => {
    const members = [
      { groupId: "g1", memberId: "m1", addedBy: "actor", addedAt: "2026-08-18T00:00:00Z", memberDisplayName: "Alice", memberEmail: "alice@example.test" }
    ];
    const fetchFn = vi.fn().mockResolvedValue(jsonResponse(200, { data: members }));
    const client = createOrgClient(createApiClient({ baseUrl: "https://gateway.test", fetchFn }));

    const result = await client.adminListGroupMembers("g1");

    expect(result).toEqual(members);
    const [url, init] = fetchFn.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("https://gateway.test/api/org/admin/groups/g1/members");
    expect(init.method ?? "GET").toBe("GET");
  });

  it("adminAddGroupMember() posts {memberId} to /api/org/admin/groups/{id}/members", async () => {
    const gm = { groupId: "g1", memberId: "m1", addedBy: "actor", addedAt: "2026-08-18T00:00:00Z", memberDisplayName: "Alice", memberEmail: null };
    const fetchFn = vi.fn().mockResolvedValue(jsonResponse(201, { data: gm }));
    const client = createOrgClient(createApiClient({ baseUrl: "https://gateway.test", fetchFn }));

    const result = await client.adminAddGroupMember("g1", "m1");

    expect(result).toEqual(gm);
    const [url, init] = fetchFn.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("https://gateway.test/api/org/admin/groups/g1/members");
    expect(init.method).toBe("POST");
    expect(JSON.parse(init.body as string)).toEqual({ memberId: "m1" });
  });

  it("adminRemoveGroupMember() sends DELETE to /api/org/admin/groups/{id}/members/{memberId}", async () => {
    const fetchFn = vi.fn().mockResolvedValue(jsonResponse(200, { data: { groupId: "g1", memberId: "m1" } }));
    const client = createOrgClient(createApiClient({ baseUrl: "https://gateway.test", fetchFn }));

    const result = await client.adminRemoveGroupMember("g1", "m1");

    expect(result).toEqual({ groupId: "g1", memberId: "m1" });
    const [url, init] = fetchFn.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("https://gateway.test/api/org/admin/groups/g1/members/m1");
    expect(init.method).toBe("DELETE");
  });

  it("adminAddGroupMember() surfaces the 409 GROUP_EXTERNALLY_MANAGED error for an externally-sourced group", async () => {
    const fetchFn = vi.fn().mockResolvedValue(
      jsonResponse(409, { error: { code: "GROUP_EXTERNALLY_MANAGED", message: "group is externally managed" } })
    );
    const client = createOrgClient(createApiClient({ baseUrl: "https://gateway.test", fetchFn }));

    await expect(client.adminAddGroupMember("g1", "m1")).rejects.toMatchObject({ code: "GROUP_EXTERNALLY_MANAGED" });
  });
});
