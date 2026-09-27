// SPDX-License-Identifier: Apache-2.0

/** Configuration for {@link createTokenVerifier}. */
export interface TokenVerifierConfig {
  /** Gateway origin; the realm's JWKS and issuer hang off it. */
  gatewayOrigin: string;
  /** Realm name; defaults to `kiban`. */
  realm?: string;
  /** Expected `aud` claim; defaults to `kiban-api`. */
  audience?: string;
  /** Override for `fetch` (tests). */
  fetchFn?: typeof fetch;
  /** Clock skew tolerated on `exp`/`nbf`, in seconds; defaults to 30. */
  clockSkewSeconds?: number;
}

/** The verified identity a Kiban token carries. Identity only, never authority: ask Kiban
 * for every access decision. */
export interface VerifiedToken {
  /** The subject (`sub`): the user's Keycloak id, which is the `subjectId` Kiban's tuples name. */
  subject: string;
  /** The client the token was issued to (`azp`): `kiban-frontend` for a browser login, a
   * service client id for a client-credentials token. */
  clientId?: string;
  /** Every claim, for the app's own use (display name, email). */
  claims: Record<string, unknown>;
}

/** Verifies bearer tokens Kiban's login issued, against the realm's signing keys. */
export interface TokenVerifier {
  /** Verifies signature, issuer, audience and time claims; rejects with an `Error` whose
   * message starts with `kiban: invalid token` otherwise. */
  verify(token: string): Promise<VerifiedToken>;
}

interface Jwk {
  kid?: string;
  kty: string;
  alg?: string;
  use?: string;
  n?: string;
  e?: string;
}

function base64UrlDecode(input: string): Uint8Array<ArrayBuffer> {
  const pad = input.length % 4 === 0 ? "" : "=".repeat(4 - (input.length % 4));
  const b64 = input.replace(/-/g, "+").replace(/_/g, "/") + pad;
  const bin = atob(b64);
  const out = new Uint8Array(new ArrayBuffer(bin.length));
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function invalid(reason: string): Error {
  return new Error(`kiban: invalid token: ${reason}`);
}

/** Creates a verifier for the realm's RS256 tokens. Keys are fetched on first use and
 * refetched once when a token names an unknown key id (key rotation). */
export function createTokenVerifier(config: TokenVerifierConfig): TokenVerifier {
  const fetchImpl = config.fetchFn ?? fetch;
  const realm = config.realm ?? "kiban";
  const audience = config.audience ?? "kiban-api";
  const origin = config.gatewayOrigin.replace(/\/+$/, "");
  const issuer = `${origin}/realms/${realm}`;
  const jwksUrl = `${issuer}/protocol/openid-connect/certs`;
  const skew = config.clockSkewSeconds ?? 30;
  let keys: Map<string, CryptoKey> | null = null;

  async function loadKeys(): Promise<Map<string, CryptoKey>> {
    const res = await fetchImpl(jwksUrl);
    if (!res.ok) throw new Error(`kiban: JWKS fetch failed with HTTP ${res.status}`);
    const json = (await res.json()) as { keys?: Jwk[] };
    const next = new Map<string, CryptoKey>();
    for (const k of json.keys ?? []) {
      if (k.kty !== "RSA" || (k.use && k.use !== "sig") || (k.alg && k.alg !== "RS256")) continue;
      const key = await crypto.subtle.importKey(
        "jwk",
        { kty: k.kty, n: k.n, e: k.e, alg: "RS256", ext: true },
        { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
        false,
        ["verify"]
      );
      next.set(k.kid ?? "", key);
    }
    keys = next;
    return next;
  }

  async function keyFor(kid: string): Promise<CryptoKey> {
    let set = keys ?? (await loadKeys());
    let key = set.get(kid);
    if (!key) {
      set = await loadKeys();
      key = set.get(kid);
    }
    if (!key) throw invalid("unknown signing key");
    return key;
  }

  return {
    async verify(token) {
      const parts = token.split(".");
      if (parts.length !== 3) throw invalid("malformed");
      const [h, p, s] = parts as [string, string, string];
      let header: { alg?: string; kid?: string };
      let claims: Record<string, unknown>;
      try {
        header = JSON.parse(new TextDecoder().decode(base64UrlDecode(h))) as { alg?: string; kid?: string };
        claims = JSON.parse(new TextDecoder().decode(base64UrlDecode(p))) as Record<string, unknown>;
      } catch {
        throw invalid("malformed");
      }
      if (header.alg !== "RS256") throw invalid("unsupported algorithm");
      const key = await keyFor(header.kid ?? "");
      const ok = await crypto.subtle.verify(
        { name: "RSASSA-PKCS1-v1_5" },
        key,
        base64UrlDecode(s),
        new TextEncoder().encode(`${h}.${p}`)
      );
      if (!ok) throw invalid("bad signature");
      const now = Math.floor(Date.now() / 1000);
      const exp = typeof claims.exp === "number" ? claims.exp : 0;
      const nbf = typeof claims.nbf === "number" ? claims.nbf : 0;
      if (exp && now - skew >= exp) throw invalid("expired");
      if (nbf && now + skew < nbf) throw invalid("not yet valid");
      if (claims.iss !== issuer) throw invalid("wrong issuer");
      const aud = claims.aud;
      const audOk = Array.isArray(aud) ? aud.includes(audience) : aud === audience;
      if (!audOk) throw invalid("wrong audience");
      if (typeof claims.sub !== "string" || !claims.sub) throw invalid("no subject");
      return {
        subject: claims.sub,
        clientId: typeof claims.azp === "string" ? claims.azp : undefined,
        claims
      };
    }
  };
}
