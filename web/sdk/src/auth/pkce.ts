// SPDX-License-Identifier: Apache-2.0

// PKCE S256 (RFC 7636) via native WebCrypto only — no dependency.
function getCrypto(): Crypto {
  const c = (globalThis as { crypto?: Crypto }).crypto;
  if (!c?.subtle || !c.getRandomValues) {
    throw new Error(
      "Web Crypto API (crypto.subtle, crypto.getRandomValues) is unavailable in this runtime"
    );
  }
  return c;
}

function base64UrlEncode(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  const base64 = btoa(binary);
  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Random PKCE code verifier: 32 random bytes → 43-char base64url string (RFC 7636 requires
 * 43-128 chars from the unreserved charset; base64url output is a strict subset of it). */
export function generateCodeVerifier(): string {
  const bytes = new Uint8Array(32);
  getCrypto().getRandomValues(bytes);
  return base64UrlEncode(bytes);
}

/** S256 code challenge: base64url(SHA-256(ascii(verifier))). */
export async function generateCodeChallenge(verifier: string): Promise<string> {
  const data = new TextEncoder().encode(verifier);
  const digest = await getCrypto().subtle.digest("SHA-256", data);
  return base64UrlEncode(new Uint8Array(digest));
}

/** Random opaque token for `state`/`nonce` — 16 random bytes, base64url. */
export function generateRandomToken(): string {
  const bytes = new Uint8Array(16);
  getCrypto().getRandomValues(bytes);
  return base64UrlEncode(bytes);
}
