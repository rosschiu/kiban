// SPDX-License-Identifier: Apache-2.0

// Runs the public SDK guide's samples (docs-snippets/guide.ts) against a mocked gateway, so the
// guide's code both compiles (typecheck includes docs-snippets/) and behaves as the page says.
import { describe, expect, it, vi } from "vitest";
import {
  apiClient,
  canIChecks,
  canSeeInbox,
  createGroupOrExplain,
  finishLogin,
  listChannels,
  memoryOnlySession,
  persistedSession,
  requireLogin,
  shareWithGroup,
  signOut,
  visibleDocuments
} from "../docs-snippets/guide.js";

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}

const allowed = { allowed: true, reason: "ALLOWED", evidence: [] };
const denied = { allowed: false, reason: "COMPANY_MEMBERSHIP_REQUIRED", evidence: [] };

/** A fake gateway answering by path; every response body is the platform envelope. */
function gateway(overrides: Record<string, () => Response> = {}): ReturnType<typeof vi.fn> {
  const routes: Record<string, () => Response> = {
    "/api/org/me/companies": () => json(200, { data: [{ id: "c1", code: "acme", name: "Acme", isActive: true }] }),
    "/api/auth/effective-access/summary": () =>
      json(200, { data: { apiVersion: 1, subjectId: "u1", companyId: "c1", moduleKey: "", featureKeys: [], roleBindings: [], objectAccess: [], rowScopes: [], fieldPolicies: [] } }),
    "/api/auth/effective-access/batch-can": () =>
      json(200, {
        data: [
          { object: { type: "docs_document", id: "doc-1" }, relation: "viewer", decision: allowed },
          { object: { type: "docs_document", id: "doc-2" }, relation: "viewer", decision: denied }
        ]
      }),
    "/api/auth/effective-access/can": () => json(200, { data: allowed }),
    "/api/auth/grants": () => json(200, { data: { status: "ok", count: 1 } }),
    "/api/org/admin/companies/c1/groups": () => json(201, { data: { id: "g1", companyId: "c1", code: "sales", name: "Sales" } }),
    "/api/notification/v1/companies/c1/channels": () =>
      json(200, {
        data: {
          items: [{ id: "ch1", companyId: "c1", key: "general", label: "General", kind: "in_app", target: null, createdAt: "2026-01-01T00:00:00Z" }],
          total: 1,
          page: 1,
          pageSize: 50,
          totalPages: 1
        }
      }),
    ...overrides
  };
  return vi.fn(async (input: string | URL | Request) => {
    const path = new URL(String(input)).pathname;
    const route = routes[path];
    if (!route) throw new Error(`unexpected request ${path}`);
    return route();
  });
}

describe("SDK guide samples", () => {
  it("builds both session flavours and an API client that sends the bearer", async () => {
    const fetchFn = gateway();
    const session = persistedSession(fetchFn as unknown as typeof fetch);
    expect(session.isAuthenticated()).toBe(false);
    expect(memoryOnlySession().getAccessToken()).toBeNull();

    const companies = await visibleDocuments(apiClient(session, fetchFn as unknown as typeof fetch));
    expect(companies).toEqual(["doc-1"]);
    const [, init] = fetchFn.mock.calls[0] as [string, RequestInit];
    expect((init.headers as Record<string, string>)["x-correlation-id"]).toBeTruthy();
  });

  it("batchCan sends the company-scoped request the guide shows", async () => {
    const fetchFn = gateway();
    const session = memoryOnlySession();
    await visibleDocuments(apiClient(session, fetchFn as unknown as typeof fetch));
    const batch = fetchFn.mock.calls.find(([url]) => String(url).endsWith("/batch-can")) as [string, RequestInit];
    const body = JSON.parse(batch[1].body as string);
    expect(body).toMatchObject({ featureKey: "docs.create", moduleKey: "docs", scope: "company", companyId: "c1" });
    expect(body.items).toHaveLength(2);
  });

  it("canI maps a denial to a plain result instead of throwing", async () => {
    let calls = 0;
    const fetchFn = gateway({
      "/api/auth/effective-access/can": () => json(200, { data: calls++ === 0 ? allowed : denied })
    });
    const result = await canIChecks(apiClient(memoryOnlySession(), fetchFn as unknown as typeof fetch), "c1");
    expect(result).toEqual({ admin: true, view: false, reason: "COMPANY_MEMBERSHIP_REQUIRED" });
  });

  it("grant then revoke post the company and one tuple each with the group userset", async () => {
    const fetchFn = gateway();
    await shareWithGroup(apiClient(memoryOnlySession(), fetchFn as unknown as typeof fetch), "c1");
    const ops = fetchFn.mock.calls.map(([, init]) => JSON.parse((init as RequestInit).body as string));
    expect(ops.map((o) => o.op)).toEqual(["grant", "revoke"]);
    expect(ops.map((o) => o.companyId)).toEqual(["c1", "c1"]);
    expect(ops[0].tuples[0]).toMatchObject({ subjectType: "group", subjectId: "group-12", subjectRelation: "member" });
  });

  it("error handling branches on the canonical code", async () => {
    const session = memoryOnlySession();
    const ok = await createGroupOrExplain(apiClient(session, gateway() as unknown as typeof fetch), session, "c1");
    expect(ok).toBe("created");

    const forbidden = gateway({
      "/api/org/admin/companies/c1/groups": () => json(403, { error: { code: "FORBIDDEN", message: "no" } })
    });
    expect(await createGroupOrExplain(apiClient(session, forbidden as unknown as typeof fetch), session, "c1")).toBe("hide");

    const conflict = gateway({
      "/api/org/admin/companies/c1/groups": () => json(409, { error: { code: "CONFLICT", message: "code taken" } })
    });
    expect(await createGroupOrExplain(apiClient(session, conflict as unknown as typeof fetch), session, "c1")).toBe("user: code taken");

    const unknown = gateway({
      "/api/org/admin/companies/c1/groups": () => json(500, { error: { code: "INTERNAL_ERROR", message: "boom" } })
    });
    await expect(createGroupOrExplain(apiClient(session, unknown as unknown as typeof fetch), session, "c1")).rejects.toMatchObject({
      status: 500
    });
  });

  it("requireLogin redirects a signed-out user to Keycloak and finishLogin exchanges the code", async () => {
    const navigate = vi.fn();
    const fetchFn = gateway({
      "/auth/realms/kiban/protocol/openid-connect/token": () =>
        json(200, { access_token: "at", refresh_token: "rt", expires_in: 300 })
    });
    const session = memoryOnlySession(fetchFn as unknown as typeof fetch, navigate);

    expect(await requireLogin(session)).toBe(false);
    const loginUrl = new URL(navigate.mock.calls[0]?.[0] as string);
    expect(loginUrl.pathname).toBe("/auth/realms/kiban/protocol/openid-connect/auth");
    expect(loginUrl.searchParams.get("code_challenge_method")).toBe("S256");

    const state = loginUrl.searchParams.get("state");
    await finishLogin(session, `http://localhost:5173/callback.html?code=abc&state=${state}`);
    expect(session.isAuthenticated()).toBe(true);
    expect(await requireLogin(session)).toBe(true);
    expect(navigate).toHaveBeenCalledTimes(1);

    signOut(session);
    expect(session.isAuthenticated()).toBe(false);
    const logoutUrl = new URL(navigate.mock.calls[1]?.[0] as string);
    expect(logoutUrl.pathname).toBe("/auth/realms/kiban/protocol/openid-connect/logout");
    expect(logoutUrl.searchParams.get("post_logout_redirect_uri")).toBe("http://localhost:5173/");
  });

  it("canSeeInbox asks for the module feature in company scope", async () => {
    const fetchFn = gateway();
    expect(await canSeeInbox(apiClient(memoryOnlySession(), fetchFn as unknown as typeof fetch), "c1")).toBe(true);
    const [, init] = fetchFn.mock.calls[0] as [string, RequestInit];
    expect(JSON.parse(init.body as string)).toMatchObject({
      featureKey: "notification.inbox.view",
      moduleKey: "notification",
      scope: "company",
      companyId: "c1"
    });
  });

  it("listChannels calls the module path through the gateway and unwraps the page", async () => {
    const fetchFn = gateway();
    const channels = await listChannels(apiClient(memoryOnlySession(), fetchFn as unknown as typeof fetch), "c1");
    expect(channels.map((c) => c.key)).toEqual(["general"]);
    const [url] = fetchFn.mock.calls[0] as [string];
    expect(String(url)).toBe("https://127.0.0.1:8443/api/notification/v1/companies/c1/channels?page=1&pageSize=50");
  });
});
