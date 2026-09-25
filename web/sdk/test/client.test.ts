// SPDX-License-Identifier: Apache-2.0

import { afterEach, describe, expect, it, vi } from "vitest";
import { createApiClient, KibanApiError } from "../src/client.js";

function jsonResponse(status: number, body: unknown, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", ...headers }
  });
}

describe("createApiClient", () => {
  it("unwraps the {data} success envelope", async () => {
    const fetchFn = vi.fn().mockResolvedValue(jsonResponse(200, { data: { hello: "world" } }));
    const client = createApiClient({ baseUrl: "https://gateway.test", fetchFn });

    const result = await client.request<{ hello: string }>("/api/platform/catalog");

    expect(result).toEqual({ hello: "world" });
    expect(fetchFn).toHaveBeenCalledTimes(1);
    const [url] = fetchFn.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("https://gateway.test/api/platform/catalog");
  });

  it("returns undefined for a 204 response without parsing a body", async () => {
    const fetchFn = vi.fn().mockResolvedValue(new Response(null, { status: 204 }));
    const client = createApiClient({ baseUrl: "https://gateway.test", fetchFn });

    const result = await client.request<undefined>("/api/x", { method: "DELETE" });

    expect(result).toBeUndefined();
  });

  it("attaches an x-correlation-id header to every request", async () => {
    const fetchFn = vi.fn().mockResolvedValue(jsonResponse(200, { data: null }));
    const client = createApiClient({ baseUrl: "https://gateway.test", fetchFn });

    await client.request("/api/x");

    const [, init] = fetchFn.mock.calls[0] as [string, RequestInit];
    const headers = init.headers as Record<string, string>;
    expect(headers["x-correlation-id"]).toBeTruthy();
    expect(typeof headers["x-correlation-id"]).toBe("string");
  });

  it("uses an injected correlation id generator", async () => {
    const fetchFn = vi.fn().mockResolvedValue(jsonResponse(200, { data: null }));
    const client = createApiClient({
      baseUrl: "https://gateway.test",
      fetchFn,
      correlationId: () => "fixed-cid"
    });

    await client.request("/api/x");

    const [, init] = fetchFn.mock.calls[0] as [string, RequestInit];
    expect((init.headers as Record<string, string>)["x-correlation-id"]).toBe("fixed-cid");
  });

  it("attaches a bearer token when getAccessToken returns one", async () => {
    const fetchFn = vi.fn().mockResolvedValue(jsonResponse(200, { data: null }));
    const client = createApiClient({
      baseUrl: "https://gateway.test",
      fetchFn,
      getAccessToken: () => "token-abc"
    });

    await client.request("/api/x");

    const [, init] = fetchFn.mock.calls[0] as [string, RequestInit];
    expect((init.headers as Record<string, string>).Authorization).toBe("Bearer token-abc");
  });

  it("omits Authorization when getAccessToken returns null", async () => {
    const fetchFn = vi.fn().mockResolvedValue(jsonResponse(200, { data: null }));
    const client = createApiClient({
      baseUrl: "https://gateway.test",
      fetchFn,
      getAccessToken: () => null
    });

    await client.request("/api/x");

    const [, init] = fetchFn.mock.calls[0] as [string, RequestInit];
    expect((init.headers as Record<string, string>).Authorization).toBeUndefined();
  });

  it("serializes a JSON body and sets content-type", async () => {
    const fetchFn = vi.fn().mockResolvedValue(jsonResponse(201, { data: { id: "1" } }));
    const client = createApiClient({ baseUrl: "https://gateway.test", fetchFn });

    await client.request("/api/x", { method: "POST", body: { name: "abc" } });

    const [, init] = fetchFn.mock.calls[0] as [string, RequestInit];
    expect(init.body).toBe(JSON.stringify({ name: "abc" }));
    expect((init.headers as Record<string, string>)["content-type"]).toBe("application/json");
  });

  it("maps the {error} envelope to a KibanApiError", async () => {
    const fetchFn = vi.fn().mockResolvedValue(
      jsonResponse(403, { error: { code: "FORBIDDEN", message: "nope", details: { reason: "x" } } })
    );
    const client = createApiClient({ baseUrl: "https://gateway.test", fetchFn });

    await expect(client.request("/api/x")).rejects.toMatchObject({
      name: "KibanApiError",
      status: 403,
      code: "FORBIDDEN",
      message: "nope",
      details: { reason: "x" }
    });
  });

  it("KibanApiError carries the correlation id used for the failing request", async () => {
    const fetchFn = vi.fn().mockResolvedValue(
      jsonResponse(500, { error: { code: "INTERNAL_ERROR", message: "boom" } })
    );
    const client = createApiClient({
      baseUrl: "https://gateway.test",
      fetchFn,
      correlationId: () => "cid-999"
    });

    try {
      await client.request("/api/x");
      expect.unreachable();
    } catch (err) {
      expect(err).toBeInstanceOf(KibanApiError);
      expect((err as KibanApiError).correlationId).toBe("cid-999");
    }
  });

  it("falls back to UNKNOWN_ERROR when the error body doesn't parse as the envelope", async () => {
    const fetchFn = vi.fn().mockResolvedValue(new Response("not json", { status: 502 }));
    const client = createApiClient({ baseUrl: "https://gateway.test", fetchFn });

    await expect(client.request("/api/x")).rejects.toMatchObject({
      status: 502,
      code: "UNKNOWN_ERROR"
    });
  });

  it("refreshes once on 401 and retries the request with the new token", async () => {
    const fetchFn = vi
      .fn()
      .mockResolvedValueOnce(jsonResponse(401, { error: { code: "AUTH_TOKEN_INVALID", message: "expired" } }))
      .mockResolvedValueOnce(jsonResponse(200, { data: { ok: true } }));
    let currentToken = "stale-token";
    const refreshAccessToken = vi.fn().mockImplementation(async () => {
      currentToken = "fresh-token";
      return currentToken;
    });
    const client = createApiClient({
      baseUrl: "https://gateway.test",
      fetchFn,
      getAccessToken: () => currentToken,
      refreshAccessToken
    });

    const result = await client.request<{ ok: boolean }>("/api/x");

    expect(result).toEqual({ ok: true });
    expect(refreshAccessToken).toHaveBeenCalledTimes(1);
    expect(fetchFn).toHaveBeenCalledTimes(2);
    const [, secondInit] = fetchFn.mock.calls[1] as [string, RequestInit];
    expect((secondInit.headers as Record<string, string>).Authorization).toBe("Bearer fresh-token");
  });

  it("refreshes before sending when the access token expires within 30 seconds", async () => {
    const fetchFn = vi.fn().mockResolvedValue(jsonResponse(200, { data: { ok: true } }));
    let currentToken = "about-to-expire";
    const refreshAccessToken = vi.fn().mockImplementation(async () => {
      currentToken = "fresh-token";
      return currentToken;
    });
    const client = createApiClient({
      baseUrl: "https://gateway.test",
      fetchFn,
      getAccessToken: () => currentToken,
      getAccessTokenExpiresAt: () => Date.now() + 10_000,
      refreshAccessToken
    });

    await client.request("/api/x");

    expect(refreshAccessToken).toHaveBeenCalledTimes(1);
    expect(fetchFn).toHaveBeenCalledTimes(1);
    const [, init] = fetchFn.mock.calls[0] as [string, RequestInit];
    expect((init.headers as Record<string, string>).Authorization).toBe("Bearer fresh-token");
  });

  it("does not refresh before sending when the access token has more than 30 seconds left", async () => {
    const fetchFn = vi.fn().mockResolvedValue(jsonResponse(200, { data: { ok: true } }));
    const refreshAccessToken = vi.fn().mockResolvedValue("fresh-token");
    const client = createApiClient({
      baseUrl: "https://gateway.test",
      fetchFn,
      getAccessToken: () => "still-good",
      getAccessTokenExpiresAt: () => Date.now() + 120_000,
      refreshAccessToken
    });

    await client.request("/api/x");

    expect(refreshAccessToken).not.toHaveBeenCalled();
  });

  it("does not retry more than once even if the retried request is also 401", async () => {
    const fetchFn = vi.fn().mockResolvedValue(
      jsonResponse(401, { error: { code: "AUTH_TOKEN_INVALID", message: "still invalid" } })
    );
    const refreshAccessToken = vi.fn().mockResolvedValue("fresh-token");
    const client = createApiClient({
      baseUrl: "https://gateway.test",
      fetchFn,
      refreshAccessToken
    });

    await expect(client.request("/api/x")).rejects.toMatchObject({ status: 401 });
    expect(refreshAccessToken).toHaveBeenCalledTimes(1);
    expect(fetchFn).toHaveBeenCalledTimes(2);
  });

  it("does not retry when refresh resolves to null (surfaces the original 401)", async () => {
    const fetchFn = vi.fn().mockResolvedValue(
      jsonResponse(401, { error: { code: "AUTH_TOKEN_MISSING", message: "no token" } })
    );
    const refreshAccessToken = vi.fn().mockResolvedValue(null);
    const client = createApiClient({ baseUrl: "https://gateway.test", fetchFn, refreshAccessToken });

    await expect(client.request("/api/x")).rejects.toMatchObject({ status: 401, code: "AUTH_TOKEN_MISSING" });
    expect(fetchFn).toHaveBeenCalledTimes(1);
  });

  it("supports query params, skipping undefined values", async () => {
    const fetchFn = vi.fn().mockResolvedValue(jsonResponse(200, { data: [] }));
    const client = createApiClient({ baseUrl: "https://gateway.test", fetchFn });

    await client.request("/api/x", { query: { page: 1, pageSize: undefined, q: "abc" } });

    const [url] = fetchFn.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("https://gateway.test/api/x?page=1&q=abc");
  });

  describe("default correlation id generator", () => {
    const originalCrypto = globalThis.crypto;

    afterEach(() => {
      vi.stubGlobal("crypto", originalCrypto);
    });

    it("uses crypto.randomUUID() when available", async () => {
      vi.stubGlobal("crypto", { randomUUID: () => "uuid-fixed" });
      const fetchFn = vi.fn().mockResolvedValue(jsonResponse(200, { data: null }));
      const client = createApiClient({ baseUrl: "https://gateway.test", fetchFn });

      await client.request("/api/x");

      const [, init] = fetchFn.mock.calls[0] as [string, RequestInit];
      expect((init.headers as Record<string, string>)["x-correlation-id"]).toBe("uuid-fixed");
    });

    it("falls back to a non-cryptographic id when crypto.randomUUID is unavailable", async () => {
      vi.stubGlobal("crypto", undefined);
      const fetchFn = vi.fn().mockResolvedValue(jsonResponse(200, { data: null }));
      const client = createApiClient({ baseUrl: "https://gateway.test", fetchFn });

      await client.request("/api/x");

      const [, init] = fetchFn.mock.calls[0] as [string, RequestInit];
      const cid = (init.headers as Record<string, string>)["x-correlation-id"];
      expect(cid).toMatch(/^cid-[a-z0-9]+-[a-z0-9]+$/);
    });
  });
});
