// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it, vi } from "vitest";
import { createApiClient } from "../src/client.js";
import { createInternalOrgClient } from "../src/orgInternal.js";

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}

describe("createInternalOrgClient", () => {
  it("createUnit() posts to /internal/org/units", async () => {
    const unit = { id: "u1", typeKey: "company", parentId: null, code: "ACME", name: "Acme", isActive: true };
    const fetchFn = vi.fn().mockResolvedValue(jsonResponse(201, { data: unit }));
    const client = createInternalOrgClient(createApiClient({ baseUrl: "https://gateway.test", fetchFn }));

    const result = await client.createUnit({ typeKey: "company", code: "ACME", name: "Acme" });

    expect(result).toEqual(unit);
    const [url, init] = fetchFn.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("https://gateway.test/internal/org/units");
    expect(init.method).toBe("POST");
  });

  it("companyState() calls GET /internal/org/companies/{id}/state", async () => {
    const fetchFn = vi.fn().mockResolvedValue(jsonResponse(200, { data: { exists: true, isActive: true } }));
    const client = createInternalOrgClient(createApiClient({ baseUrl: "https://gateway.test", fetchFn }));

    const result = await client.companyState("company-1");

    expect(result).toEqual({ exists: true, isActive: true });
    const [url] = fetchFn.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("https://gateway.test/internal/org/companies/company-1/state");
  });

  it("listMembers() sends companyId/page/pageSize as query params and unwraps the Page envelope", async () => {
    const page = { items: [], total: 0, page: 1, pageSize: 25, totalPages: 1 };
    const fetchFn = vi.fn().mockResolvedValue(jsonResponse(200, { data: page }));
    const client = createInternalOrgClient(createApiClient({ baseUrl: "https://gateway.test", fetchFn }));

    const result = await client.listMembers("company-1", 2, 10);

    expect(result).toEqual(page);
    const [url] = fetchFn.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("https://gateway.test/internal/org/members?companyId=company-1&page=2&pageSize=10");
  });

  it("linkUser() posts {kcSub} to /internal/org/members/{id}/link-user", async () => {
    const member = { id: "m1", companyId: "c1", code: "M1", displayName: "Jane", email: "jane@example.test", userId: "u1", isActive: true };
    const fetchFn = vi.fn().mockResolvedValue(jsonResponse(200, { data: member }));
    const client = createInternalOrgClient(createApiClient({ baseUrl: "https://gateway.test", fetchFn }));

    const result = await client.linkUser("m1", "kc-sub-1");

    expect(result).toEqual(member);
    const [url, init] = fetchFn.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("https://gateway.test/internal/org/members/m1/link-user");
    expect(JSON.parse(init.body as string)).toEqual({ kcSub: "kc-sub-1" });
  });

  it("getUnit() calls GET /internal/org/units/{id}, URI-encoded", async () => {
    const unit = { id: "u/1", typeKey: "company", parentId: null, code: "ACME", name: "Acme", isActive: true };
    const fetchFn = vi.fn().mockResolvedValue(jsonResponse(200, { data: unit }));
    const client = createInternalOrgClient(createApiClient({ baseUrl: "https://gateway.test", fetchFn }));

    const result = await client.getUnit("u/1");

    expect(result).toEqual(unit);
    const [url] = fetchFn.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("https://gateway.test/internal/org/units/u%2F1");
  });

  it("updateUnit() PUTs the input to /internal/org/units/{id}", async () => {
    const unit = { id: "u1", typeKey: "company", parentId: null, code: "ACME2", name: "Acme Two", isActive: true };
    const fetchFn = vi.fn().mockResolvedValue(jsonResponse(200, { data: unit }));
    const client = createInternalOrgClient(createApiClient({ baseUrl: "https://gateway.test", fetchFn }));

    const result = await client.updateUnit("u1", { typeKey: "company", code: "ACME2", name: "Acme Two" });

    expect(result).toEqual(unit);
    const [url, init] = fetchFn.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("https://gateway.test/internal/org/units/u1");
    expect(init.method).toBe("PUT");
  });

  it("deleteUnit() DELETEs /internal/org/units/{id}", async () => {
    const fetchFn = vi.fn().mockResolvedValue(jsonResponse(200, { data: { id: "u1" } }));
    const client = createInternalOrgClient(createApiClient({ baseUrl: "https://gateway.test", fetchFn }));

    const result = await client.deleteUnit("u1");

    expect(result).toEqual({ id: "u1" });
    const [url, init] = fetchFn.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("https://gateway.test/internal/org/units/u1");
    expect(init.method).toBe("DELETE");
  });

  it("subtree() calls GET /internal/org/units/{id}/subtree", async () => {
    const nodes = [{ id: "u1", typeKey: "company", parentId: null, code: "A", name: "A", isActive: true, depth: 0 }];
    const fetchFn = vi.fn().mockResolvedValue(jsonResponse(200, { data: nodes }));
    const client = createInternalOrgClient(createApiClient({ baseUrl: "https://gateway.test", fetchFn }));

    const result = await client.subtree("u1");

    expect(result).toEqual(nodes);
    const [url] = fetchFn.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("https://gateway.test/internal/org/units/u1/subtree");
  });

  it("memberByKcSub() calls GET /internal/org/companies/{id}/members/by-kcsub/{kcSub}", async () => {
    const state = { isMember: true, isActive: true, memberId: "m1" };
    const fetchFn = vi.fn().mockResolvedValue(jsonResponse(200, { data: state }));
    const client = createInternalOrgClient(createApiClient({ baseUrl: "https://gateway.test", fetchFn }));

    const result = await client.memberByKcSub("company-1", "kc-sub-1");

    expect(result).toEqual(state);
    const [url] = fetchFn.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("https://gateway.test/internal/org/companies/company-1/members/by-kcsub/kc-sub-1");
  });

  it("createMember() posts to /internal/org/members", async () => {
    const member = { id: "m1", companyId: "c1", code: "M1", displayName: "Jane", email: "jane@example.test", userId: null, isActive: true };
    const fetchFn = vi.fn().mockResolvedValue(jsonResponse(201, { data: member }));
    const client = createInternalOrgClient(createApiClient({ baseUrl: "https://gateway.test", fetchFn }));

    const result = await client.createMember({ companyId: "c1", code: "M1", displayName: "Jane", email: "jane@example.test" });

    expect(result).toEqual(member);
    const [url, init] = fetchFn.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("https://gateway.test/internal/org/members");
    expect(init.method).toBe("POST");
  });

  it("getMember() calls GET /internal/org/members/{id}", async () => {
    const member = { id: "m1", companyId: "c1", code: "M1", displayName: "Jane", email: "jane@example.test", userId: null, isActive: true };
    const fetchFn = vi.fn().mockResolvedValue(jsonResponse(200, { data: member }));
    const client = createInternalOrgClient(createApiClient({ baseUrl: "https://gateway.test", fetchFn }));

    const result = await client.getMember("m1");

    expect(result).toEqual(member);
    const [url] = fetchFn.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("https://gateway.test/internal/org/members/m1");
  });

  it("updateMember() PUTs to /internal/org/members/{id}", async () => {
    const member = { id: "m1", companyId: "c1", code: "M1", displayName: "Jane Doe", email: "jane@example.test", userId: null, isActive: true };
    const fetchFn = vi.fn().mockResolvedValue(jsonResponse(200, { data: member }));
    const client = createInternalOrgClient(createApiClient({ baseUrl: "https://gateway.test", fetchFn }));

    const result = await client.updateMember("m1", { code: "M1", displayName: "Jane Doe", email: "jane@example.test" });

    expect(result).toEqual(member);
    const [url, init] = fetchFn.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("https://gateway.test/internal/org/members/m1");
    expect(init.method).toBe("PUT");
  });

  it("unlinkUser() DELETEs /internal/org/members/{id}/link-user", async () => {
    const member = { id: "m1", companyId: "c1", code: "M1", displayName: "Jane", email: "jane@example.test", userId: null, isActive: true };
    const fetchFn = vi.fn().mockResolvedValue(jsonResponse(200, { data: member }));
    const client = createInternalOrgClient(createApiClient({ baseUrl: "https://gateway.test", fetchFn }));

    const result = await client.unlinkUser("m1");

    expect(result).toEqual(member);
    const [url, init] = fetchFn.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("https://gateway.test/internal/org/members/m1/link-user");
    expect(init.method).toBe("DELETE");
  });

  it("createPosition() posts to /internal/org/positions", async () => {
    const position = { id: "p1", companyId: "c1", code: "P1", title: "Manager", orgUnitId: "u1" };
    const fetchFn = vi.fn().mockResolvedValue(jsonResponse(201, { data: position }));
    const client = createInternalOrgClient(createApiClient({ baseUrl: "https://gateway.test", fetchFn }));

    const result = await client.createPosition({ companyId: "c1", code: "P1", title: "Manager", orgUnitId: "u1" });

    expect(result).toEqual(position);
    const [url, init] = fetchFn.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("https://gateway.test/internal/org/positions");
    expect(init.method).toBe("POST");
  });

  it("getPosition() calls GET /internal/org/positions/{id}", async () => {
    const position = { id: "p1", companyId: "c1", code: "P1", title: "Manager", orgUnitId: "u1" };
    const fetchFn = vi.fn().mockResolvedValue(jsonResponse(200, { data: position }));
    const client = createInternalOrgClient(createApiClient({ baseUrl: "https://gateway.test", fetchFn }));

    const result = await client.getPosition("p1");

    expect(result).toEqual(position);
    const [url] = fetchFn.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("https://gateway.test/internal/org/positions/p1");
  });

  it("listPositions() sends companyId/page/pageSize as query params", async () => {
    const page = { items: [], total: 0, page: 1, pageSize: 25, totalPages: 1 };
    const fetchFn = vi.fn().mockResolvedValue(jsonResponse(200, { data: page }));
    const client = createInternalOrgClient(createApiClient({ baseUrl: "https://gateway.test", fetchFn }));

    const result = await client.listPositions("company-1", 1, 25);

    expect(result).toEqual(page);
    const [url] = fetchFn.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("https://gateway.test/internal/org/positions?companyId=company-1&page=1&pageSize=25");
  });

  it("updatePosition() PUTs {title, orgUnitId} to /internal/org/positions/{id}", async () => {
    const position = { id: "p1", companyId: "c1", code: "P1", title: "Director", orgUnitId: "u2" };
    const fetchFn = vi.fn().mockResolvedValue(jsonResponse(200, { data: position }));
    const client = createInternalOrgClient(createApiClient({ baseUrl: "https://gateway.test", fetchFn }));

    const result = await client.updatePosition("p1", "Director", "u2");

    expect(result).toEqual(position);
    const [url, init] = fetchFn.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("https://gateway.test/internal/org/positions/p1");
    expect(init.method).toBe("PUT");
    expect(JSON.parse(init.body as string)).toEqual({ title: "Director", orgUnitId: "u2" });
  });

  it("deletePosition() DELETEs /internal/org/positions/{id}", async () => {
    const fetchFn = vi.fn().mockResolvedValue(jsonResponse(200, { data: { id: "p1" } }));
    const client = createInternalOrgClient(createApiClient({ baseUrl: "https://gateway.test", fetchFn }));

    const result = await client.deletePosition("p1");

    expect(result).toEqual({ id: "p1" });
    const [url, init] = fetchFn.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("https://gateway.test/internal/org/positions/p1");
    expect(init.method).toBe("DELETE");
  });

  it("holderOnDate() sends date as a query param on /internal/org/positions/{id}/holder", async () => {
    const assignment = { id: "a1", positionId: "p1", memberId: "m1", validFrom: "2026-01-01", validTo: null };
    const fetchFn = vi.fn().mockResolvedValue(jsonResponse(200, { data: assignment }));
    const client = createInternalOrgClient(createApiClient({ baseUrl: "https://gateway.test", fetchFn }));

    const result = await client.holderOnDate("p1", "2026-08-11");

    expect(result).toEqual(assignment);
    const [url] = fetchFn.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("https://gateway.test/internal/org/positions/p1/holder?date=2026-08-11");
  });

  it("createAndAssign() posts to /internal/org/positions:create-and-assign", async () => {
    const payload = {
      position: { id: "p1", companyId: "c1", code: "P1", title: "Manager", orgUnitId: "u1" },
      assignment: { id: "a1", positionId: "p1", memberId: "m1", validFrom: "2026-01-01", validTo: null }
    };
    const fetchFn = vi.fn().mockResolvedValue(jsonResponse(201, { data: payload }));
    const client = createInternalOrgClient(createApiClient({ baseUrl: "https://gateway.test", fetchFn }));

    const result = await client.createAndAssign({
      companyId: "c1",
      code: "P1",
      title: "Manager",
      orgUnitId: "u1",
      memberId: "m1",
      validFrom: "2026-01-01"
    });

    expect(result).toEqual(payload);
    const [url, init] = fetchFn.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("https://gateway.test/internal/org/positions:create-and-assign");
    expect(init.method).toBe("POST");
  });

  it("endAssignment() posts {validTo} to /internal/org/assignments/{id}/end", async () => {
    const assignment = { id: "a1", positionId: "p1", memberId: "m1", validFrom: "2026-01-01", validTo: "2026-08-11" };
    const fetchFn = vi.fn().mockResolvedValue(jsonResponse(200, { data: assignment }));
    const client = createInternalOrgClient(createApiClient({ baseUrl: "https://gateway.test", fetchFn }));

    const result = await client.endAssignment("a1", "2026-08-11");

    expect(result).toEqual(assignment);
    const [url, init] = fetchFn.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("https://gateway.test/internal/org/assignments/a1/end");
    expect(init.method).toBe("POST");
    expect(JSON.parse(init.body as string)).toEqual({ validTo: "2026-08-11" });
  });

  it("surfaces a KibanApiError for a non-2xx response (e.g. 404 — org's CRUD surface has no gateway mount)", async () => {
    const fetchFn = vi.fn().mockResolvedValue(jsonResponse(404, { error: { code: "NOT_FOUND", message: "not found" } }));
    const client = createInternalOrgClient(createApiClient({ baseUrl: "https://gateway.test", fetchFn }));

    await expect(client.getUnit("missing")).rejects.toMatchObject({ status: 404, code: "NOT_FOUND" });
  });
});
