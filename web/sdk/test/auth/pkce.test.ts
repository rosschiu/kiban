// SPDX-License-Identifier: Apache-2.0

import { afterEach, describe, expect, it, vi } from "vitest";
import { generateCodeChallenge, generateCodeVerifier, generateRandomToken } from "../../src/auth/pkce.js";

const PKCE_UNRESERVED = /^[A-Za-z0-9\-._~]+$/;

async function expectedChallenge(verifier: string): Promise<string> {
  const data = new TextEncoder().encode(verifier);
  const digest = await crypto.subtle.digest("SHA-256", data);
  const bytes = new Uint8Array(digest);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

describe("PKCE helpers", () => {
  it("generateCodeVerifier produces an RFC 7636-compliant verifier (43-128 chars, unreserved charset)", () => {
    const verifier = generateCodeVerifier();
    expect(verifier.length).toBeGreaterThanOrEqual(43);
    expect(verifier.length).toBeLessThanOrEqual(128);
    expect(verifier).toMatch(PKCE_UNRESERVED);
  });

  it("generateCodeVerifier is not deterministic across calls", () => {
    expect(generateCodeVerifier()).not.toBe(generateCodeVerifier());
  });

  it("generateCodeChallenge computes base64url(SHA-256(verifier)) — matches an independent computation", async () => {
    const verifier = generateCodeVerifier();
    const challenge = await generateCodeChallenge(verifier);
    const expected = await expectedChallenge(verifier);
    expect(challenge).toBe(expected);
    expect(challenge).toMatch(PKCE_UNRESERVED);
    expect(challenge).not.toContain("=");
  });

  it("generateRandomToken produces a URL-safe opaque token", () => {
    const a = generateRandomToken();
    const b = generateRandomToken();
    expect(a).not.toBe(b);
    expect(a).toMatch(PKCE_UNRESERVED);
    expect(a.length).toBeGreaterThan(10);
  });
});

describe("PKCE helpers — Web Crypto API unavailable", () => {
  const originalCrypto = globalThis.crypto;

  afterEach(() => {
    vi.stubGlobal("crypto", originalCrypto);
  });

  it("generateCodeVerifier throws a descriptive error when crypto.getRandomValues is missing", () => {
    vi.stubGlobal("crypto", { subtle: originalCrypto.subtle });
    expect(() => generateCodeVerifier()).toThrow(/Web Crypto API/);
  });

  it("generateRandomToken throws a descriptive error when crypto.subtle is missing", () => {
    vi.stubGlobal("crypto", { getRandomValues: originalCrypto.getRandomValues.bind(originalCrypto) });
    expect(() => generateRandomToken()).toThrow(/Web Crypto API/);
  });

  it("generateCodeChallenge throws when the Web Crypto API is entirely unavailable", async () => {
    vi.stubGlobal("crypto", undefined);
    await expect(generateCodeChallenge("verifier")).rejects.toThrow(/Web Crypto API/);
  });
});
