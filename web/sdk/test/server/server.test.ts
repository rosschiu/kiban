// SPDX-License-Identifier: Apache-2.0
// @vitest-environment node

import { generateKeyPairSync, sign } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import { createAppClient, createServiceCredentials, createTokenVerifier } from "../../src/server/index.js";

const ORIGIN = "https://kiban.test";
const ISSUER = `${ORIGIN}/realms/kiban`;

function b64url(input: Buffer | string): string {
  return Buffer.from(input).toString("base64url");
}

function makeIssuer(kid = "k1") {
  const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const jwk = publicKey.export({ format: "jwk" }) as { n: string; e: string };
  const jwks = { keys: [{ kty: "RSA", kid, alg: "RS256", use: "sig", n: jwk.n, e: jwk.e }] };
  const signToken = (claims: Record<string, unknown>, headerKid = kid): string => {
    const now = Math.floor(Date.now() / 1000);
    const header = b64url(JSON.stringify({ alg: "RS256", typ: "JWT", kid: headerKid }));
    const payload = b64url(JSON.stringify({ iss: ISSUER, aud: "kiban-api", iat: now, exp: now + 300, ...claims }));
    const sig = sign("sha256", Buffer.from(`${header}.${payload}`), privateKey);
    return `${header}.${payload}.${b64url(sig)}`;
  };
  return { jwks, signToken };
}

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}

describe("createTokenVerifier", () => {
  it("verifies a token the realm signed and rejects the rest", async () => {
    const issuer = makeIssuer();
    const fetchFn = vi.fn(async () => json(200, issuer.jwks));
    const verifier = createTokenVerifier({ gatewayOrigin: ORIGIN, fetchFn });

    const ok = await verifier.verify(issuer.signToken({ sub: "alice", azp: "kiban-frontend" }));
    expect(ok.subject).toBe("alice");
    expect(ok.clientId).toBe("kiban-frontend");
    expect(fetchFn).toHaveBeenCalledTimes(1);

    await expect(verifier.verify(issuer.signToken({ sub: "alice", aud: "other" }))).rejects.toThrow(/wrong audience/);
    await expect(verifier.verify(issuer.signToken({ sub: "alice", iss: "https://evil" }))).rejects.toThrow(/wrong issuer/);
    await expect(verifier.verify(issuer.signToken({ sub: "alice", exp: 1 }))).rejects.toThrow(/expired/);
    await expect(verifier.verify("not.a.jwt")).rejects.toThrow(/malformed/);

    const other = makeIssuer("k1");
    await expect(verifier.verify(other.signToken({ sub: "mallory" }))).rejects.toThrow(/bad signature/);
  });

  it("refetches the JWKS once for an unknown key id", async () => {
    const old = makeIssuer("k1");
    const rotated = makeIssuer("k2");
    let calls = 0;
    const fetchFn = vi.fn(async () => json(200, calls++ === 0 ? old.jwks : rotated.jwks));
    const verifier = createTokenVerifier({ gatewayOrigin: ORIGIN, fetchFn });
    await verifier.verify(old.signToken({ sub: "a" }));
    const ok = await verifier.verify(rotated.signToken({ sub: "b" }));
    expect(ok.subject).toBe("b");
    expect(fetchFn).toHaveBeenCalledTimes(2);
    await expect(verifier.verify(old.signToken({ sub: "a" }, "k9"))).rejects.toThrow(/unknown signing key/);
  });
});

describe("createServiceCredentials", () => {
  it("fetches a client-credentials token once and caches it", async () => {
    const fetchFn = vi.fn(async (_url: string, init?: RequestInit) => {
      const form = new URLSearchParams(String(init?.body));
      expect(form.get("grant_type")).toBe("client_credentials");
      expect(form.get("client_id")).toBe("app-backend");
      return json(200, { access_token: "svc-token", expires_in: 300 });
    });
    const creds = createServiceCredentials({ gatewayOrigin: ORIGIN, clientId: "app-backend", clientSecret: "s", fetchFn });
    const [a, b] = await Promise.all([creds.getAccessToken(), creds.getAccessToken()]);
    expect(a).toBe("svc-token");
    expect(b).toBe("svc-token");
    expect(fetchFn).toHaveBeenCalledTimes(1);
    const [url] = fetchFn.mock.calls[0] as [string];
    expect(url).toBe(`${ISSUER}/protocol/openid-connect/token`);
  });

  it("surfaces a refused grant", async () => {
    const fetchFn = vi.fn(async () => new Response("nope", { status: 401 }));
    const creds = createServiceCredentials({ gatewayOrigin: ORIGIN, clientId: "x", clientSecret: "y", fetchFn });
    await expect(creds.getAccessToken()).rejects.toThrow(/HTTP 401/);
  });
});

describe("createAppClient", () => {
  it("sends the right bearer to each route", async () => {
    const calls: Array<{ url: string; auth: string; body: unknown }> = [];
    const fetchFn = vi.fn(async (url: string, init?: RequestInit) => {
      const headers = init?.headers as Record<string, string>;
      calls.push({ url, auth: headers.Authorization ?? "", body: init?.body ? JSON.parse(String(init.body)) : undefined });
      if (url.endsWith("/effective-access/can")) return json(200, { data: { allowed: true, reason: "ALLOWED" } });
      if (url.includes("/members/by-subject/")) return json(200, { data: { isMember: true, isActive: true, memberId: "m-1" } });
      return json(200, { data: { status: "ok" } });
    });
    const credentials = { getAccessToken: async () => "svc-token" };
    const app = createAppClient({ gatewayOrigin: ORIGIN, appKey: "tokidesk", credentials, fetchFn });

    const d = await app.can("user-token", { featureKey: "tokidesk.ticket.view", moduleKey: "tokidesk", scope: "company", companyId: "co-1" });
    expect(d.allowed).toBe(true);
    await app.grant("co-1", [app.anchorTuple("ticket", "t-1", "co-1")]);
    await app.revoke("co-1", [{ objectType: "ticket", objectId: "t-1", relation: "viewer", subjectType: "user", subjectId: "alice" }]);
    const fact = await app.memberBySubject("co-1", "alice");
    expect(fact.memberId).toBe("m-1");
    await app.registerApp("admin-token", { key: "tokidesk", displayName: "TokiDesk", version: "1", serviceClientId: "tokidesk-backend", authzFragment: {} });

    expect(calls.map((c) => c.auth)).toEqual(["Bearer user-token", "Bearer svc-token", "Bearer svc-token", "Bearer svc-token", "Bearer admin-token"]);
    expect((calls[1]?.body as { tuples: Array<{ subjectId: string }> }).tuples[0]?.subjectId).toBe("co-1/tokidesk");
    expect((calls[2]?.body as { op: string }).op).toBe("revoke");
    expect(calls[3]?.url).toBe(`${ORIGIN}/api/org/companies/co-1/members/by-subject/alice`);
    expect(calls[4]?.url).toBe(`${ORIGIN}/api/platform/admin/apps`);
  });
});
