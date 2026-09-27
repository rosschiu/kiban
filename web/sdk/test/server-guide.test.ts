// SPDX-License-Identifier: Apache-2.0
// @vitest-environment node

import { generateKeyPairSync, sign } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import { canViewTicket, createBackend, mayRunReminders, memberIdOf, onTicketCreated, requireUser } from "../docs-snippets/server.js";

const ORIGIN = "https://kiban.test";

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}

describe("integrate page: backend track (Node)", () => {
  it("runs every sample against a mocked gateway", async () => {
    const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
    const jwk = publicKey.export({ format: "jwk" }) as { n: string; e: string };
    const now = Math.floor(Date.now() / 1000);
    const header = Buffer.from(JSON.stringify({ alg: "RS256", kid: "k1" })).toString("base64url");
    const payload = Buffer.from(JSON.stringify({ iss: `${ORIGIN}/realms/kiban`, aud: "kiban-api", sub: "alice", iat: now, exp: now + 300 })).toString("base64url");
    const userToken = `${header}.${payload}.${sign("sha256", Buffer.from(`${header}.${payload}`), privateKey).toString("base64url")}`;

    const seen: Array<{ url: string; auth: string; body: unknown }> = [];
    const fetchFn = vi.fn(async (url: string, init?: RequestInit) => {
      const headers = (init?.headers ?? {}) as Record<string, string>;
      seen.push({ url, auth: headers.Authorization ?? "", body: init?.body && headers["content-type"] === "application/json" ? JSON.parse(String(init.body)) : undefined });
      if (url.endsWith("/certs")) return json(200, { keys: [{ kty: "RSA", kid: "k1", alg: "RS256", use: "sig", n: jwk.n, e: jwk.e }] });
      if (url.endsWith("/token")) return json(200, { access_token: "svc", expires_in: 300 });
      if (url.endsWith("/effective-access/can")) return json(200, { data: { allowed: true, reason: "ALLOWED", evidence: [] } });
      if (url.includes("/members/by-subject/")) return json(200, { data: { isMember: true, isActive: true, memberId: "m-1" } });
      return json(200, { data: { status: "ok" } });
    });

    const backend = createBackend(ORIGIN, "secret", fetchFn);
    expect(await requireUser(backend, `Bearer ${userToken}`)).toBe("alice");
    await expect(requireUser(backend, undefined)).rejects.toThrow(/login required/);
    expect(await canViewTicket(backend, userToken, "co-1", "t-1")).toBe(true);
    await onTicketCreated(backend, "co-1", "t-1", "alice");
    expect(await memberIdOf(backend, "co-1", "alice")).toBe("m-1");
    expect(await mayRunReminders(backend, "co-1")).toBe(true);

    const can = seen.find((s) => s.url.endsWith("/effective-access/can"));
    expect(can?.auth).toBe(`Bearer ${userToken}`);
    const grant = seen.find((s) => s.url.endsWith("/api/auth/grants"));
    expect(grant?.auth).toBe("Bearer svc");
    expect((grant?.body as { tuples: Array<{ subjectId: string }> }).tuples[0]?.subjectId).toBe("co-1/tokidesk");
  });
});
