// SPDX-License-Identifier: Apache-2.0

import { afterEach, describe, expect, it, vi } from "vitest";
import { createSession, decodeIdTokenClaims } from "../../src/auth/session.js";
import { createMemoryStorage } from "../../src/storage.js";

function base64url(json: Record<string, unknown>): string {
  const binary = JSON.stringify(json)
    .split("")
    .map((c) => c.charCodeAt(0))
    .reduce((s, code) => s + String.fromCharCode(code), "");
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** A JWT-shaped (unsigned — this SDK never verifies the signature client-side) ID token, so
 * nonce-validating tests can control the `nonce` claim it carries. */
function makeIdToken(claims: Record<string, unknown>): string {
  return `${base64url({ alg: "none", typ: "JWT" })}.${base64url(claims)}.`;
}

function tokenResponse(overrides: Record<string, unknown> = {}): Response {
  return new Response(
    JSON.stringify({
      access_token: "access-1",
      refresh_token: "refresh-1",
      id_token: "id-1",
      expires_in: 300,
      ...overrides
    }),
    { status: 200, headers: { "content-type": "application/json" } }
  );
}

/** Same as tokenResponse(), but with a real ID token whose `nonce` claim matches the given
 * transaction nonce — for tests exercising a callback that must pass nonce validation. */
function tokenResponseWithNonce(nonce: string, overrides: Record<string, unknown> = {}): Response {
  return tokenResponse({ id_token: makeIdToken({ nonce }), ...overrides });
}

function baseConfig(overrides: Partial<Parameters<typeof createSession>[0]> = {}) {
  return {
    authOrigin: "https://gateway.test",
    realm: "kiban",
    clientId: "kiban-frontend",
    redirectUri: "https://app.test/oidc/callback",
    storage: createMemoryStorage(),
    navigate: vi.fn(),
    now: () => 1_000_000,
    ...overrides
  };
}

describe("createSession — login URL / PKCE transaction", () => {
  it("buildLoginUrl targets the gateway's realm auth endpoint with S256 params and records the transaction", async () => {
    const storage = createMemoryStorage();
    const session = createSession(baseConfig({ storage }));

    const url = await session.buildLoginUrl();
    const parsed = new URL(url);

    expect(parsed.origin).toBe("https://gateway.test");
    expect(parsed.pathname).toBe("/auth/realms/kiban/protocol/openid-connect/auth");
    expect(parsed.searchParams.get("response_type")).toBe("code");
    expect(parsed.searchParams.get("client_id")).toBe("kiban-frontend");
    expect(parsed.searchParams.get("redirect_uri")).toBe("https://app.test/oidc/callback");
    expect(parsed.searchParams.get("code_challenge_method")).toBe("S256");
    expect(parsed.searchParams.get("code_challenge")).toBeTruthy();
    expect(parsed.searchParams.get("state")).toBeTruthy();

    const stored = JSON.parse(storage.getItem("kiban.oidc.transaction")!);
    expect(stored.state).toBe(parsed.searchParams.get("state"));
    expect(stored.redirectUri).toBe("https://app.test/oidc/callback");
  });

  it("login() navigates to the built login URL", async () => {
    const navigate = vi.fn();
    const session = createSession(baseConfig({ navigate }));

    await session.login();

    expect(navigate).toHaveBeenCalledTimes(1);
    const [url] = navigate.mock.calls[0] as [string];
    expect(url).toContain("/auth/realms/kiban/protocol/openid-connect/auth");
  });
});

describe("createSession — handleCallback", () => {
  it("exchanges the code for tokens and stores them", async () => {
    const fetchFn = vi.fn();
    const session = createSession(baseConfig({ fetchFn }));
    const loginUrl = new URL(await session.buildLoginUrl());
    const state = loginUrl.searchParams.get("state")!;
    const nonce = loginUrl.searchParams.get("nonce")!;
    fetchFn.mockResolvedValue(tokenResponseWithNonce(nonce));

    const tokens = await session.handleCallback(`https://app.test/oidc/callback?code=abc123&state=${state}`);

    expect(tokens.accessToken).toBe("access-1");
    expect(tokens.refreshToken).toBe("refresh-1");
    expect(tokens.expiresAt).toBe(1_000_000 + 300_000);
    expect(session.getAccessToken()).toBe("access-1");
    expect(session.isAuthenticated()).toBe(true);
    expect(fetchFn).toHaveBeenCalledTimes(1);

    const [tokenUrl, init] = fetchFn.mock.calls[0] as [string, RequestInit];
    expect(tokenUrl).toBe("https://gateway.test/auth/realms/kiban/protocol/openid-connect/token");
    const body = new URLSearchParams(init.body as string);
    expect(body.get("grant_type")).toBe("authorization_code");
    expect(body.get("code")).toBe("abc123");
    expect(body.get("code_verifier")).toBeTruthy();
  });

  it("is idempotent under React StrictMode double-invocation (same code exchanged once)", async () => {
    let resolveFetch: (value: Response) => void;
    const fetchFn = vi.fn().mockReturnValue(
      new Promise<Response>((resolve) => {
        resolveFetch = resolve;
      })
    );
    const session = createSession(baseConfig({ fetchFn }));
    const loginUrl = new URL(await session.buildLoginUrl());
    const state = loginUrl.searchParams.get("state")!;
    const nonce = loginUrl.searchParams.get("nonce")!;
    const callbackUrl = `https://app.test/oidc/callback?code=strict-mode-code&state=${state}`;

    // Simulate StrictMode's mount -> unmount -> mount double-invoke: two calls with the exact
    // same callback URL, issued before the first has resolved.
    const first = session.handleCallback(callbackUrl);
    const second = session.handleCallback(callbackUrl);

    resolveFetch!(tokenResponseWithNonce(nonce));
    const [firstResult, secondResult] = await Promise.all([first, second]);

    expect(fetchFn).toHaveBeenCalledTimes(1);
    expect(firstResult).toEqual(secondResult);
    expect(firstResult.accessToken).toBe("access-1");

    // A third, later invocation with the same code also short-circuits (no re-exchange of an
    // already-consumed authorization code).
    const third = await session.handleCallback(callbackUrl);
    expect(fetchFn).toHaveBeenCalledTimes(1);
    expect(third).toEqual(firstResult);
  });

  it("rejects when state does not match the recorded transaction", async () => {
    const fetchFn = vi.fn();
    const session = createSession(baseConfig({ fetchFn }));
    await session.buildLoginUrl();

    await expect(
      session.handleCallback("https://app.test/oidc/callback?code=abc&state=wrong-state")
    ).rejects.toThrow(/state mismatch/i);
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it("rejects when no transaction was ever recorded", async () => {
    const session = createSession(baseConfig());
    await expect(
      session.handleCallback("https://app.test/oidc/callback?code=abc&state=xyz")
    ).rejects.toThrow(/no pending oidc transaction/i);
  });

  it("rejects with the IdP's error when the callback URL carries an error param", async () => {
    const fetchFn = vi.fn();
    const session = createSession(baseConfig({ fetchFn }));

    await expect(
      session.handleCallback(
        "https://app.test/oidc/callback?error=access_denied&error_description=user+cancelled"
      )
    ).rejects.toThrow(/access_denied.*user cancelled/);
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it("rejects when the callback URL carries an error param with no description", async () => {
    const session = createSession(baseConfig());

    await expect(
      session.handleCallback("https://app.test/oidc/callback?error=server_error")
    ).rejects.toThrow(/server_error/);
  });

  it("rejects when the callback URL is missing code and/or state", async () => {
    const fetchFn = vi.fn();
    const session = createSession(baseConfig({ fetchFn }));

    await expect(session.handleCallback("https://app.test/oidc/callback")).rejects.toThrow(
      /missing code and\/or state/i
    );
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it("rejects when the callback URL has code but no state", async () => {
    const session = createSession(baseConfig());
    await expect(
      session.handleCallback("https://app.test/oidc/callback?code=abc")
    ).rejects.toThrow(/missing code and\/or state/i);
  });

  it("rejects with the parsed error envelope when the token endpoint returns a non-2xx status", async () => {
    const fetchFn = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ error: "invalid_grant", error_description: "code already used" }), {
        status: 400,
        headers: { "content-type": "application/json" }
      })
    );
    const session = createSession(baseConfig({ fetchFn }));
    const loginUrl = new URL(await session.buildLoginUrl());
    const state = loginUrl.searchParams.get("state")!;

    await expect(
      session.handleCallback(`https://app.test/oidc/callback?code=bad-code&state=${state}`)
    ).rejects.toThrow(/code already used/);
  });

  it("rejects using the response statusText when a failing token response has no parseable body", async () => {
    const fetchFn = vi.fn().mockResolvedValue(new Response("not json", { status: 502, statusText: "Bad Gateway" }));
    const session = createSession(baseConfig({ fetchFn }));
    const loginUrl = new URL(await session.buildLoginUrl());
    const state = loginUrl.searchParams.get("state")!;

    await expect(
      session.handleCallback(`https://app.test/oidc/callback?code=abc&state=${state}`)
    ).rejects.toThrow(/502/);
  });

  it("rejects when the token endpoint returns 200 but no access_token", async () => {
    const fetchFn = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({}), { status: 200, headers: { "content-type": "application/json" } })
    );
    const session = createSession(baseConfig({ fetchFn }));
    const loginUrl = new URL(await session.buildLoginUrl());
    const state = loginUrl.searchParams.get("state")!;

    await expect(
      session.handleCallback(`https://app.test/oidc/callback?code=abc&state=${state}`)
    ).rejects.toThrow(/code exchange failed/i);
  });

  it("clears the pending transaction even when the exchange ultimately fails", async () => {
    const fetchFn = vi.fn().mockResolvedValue(new Response("boom", { status: 500 }));
    const storage = createMemoryStorage();
    const session = createSession(baseConfig({ fetchFn, storage }));
    const loginUrl = new URL(await session.buildLoginUrl());
    const state = loginUrl.searchParams.get("state")!;

    await expect(
      session.handleCallback(`https://app.test/oidc/callback?code=abc&state=${state}`)
    ).rejects.toThrow();
    expect(storage.getItem("kiban.oidc.transaction")).toBeNull();
  });
});

describe("createSession — nonce validation", () => {
  it("rejects when the ID token's nonce claim does not match the recorded transaction", async () => {
    const fetchFn = vi.fn().mockResolvedValue(tokenResponseWithNonce("someone-elses-nonce"));
    const session = createSession(baseConfig({ fetchFn }));
    const loginUrl = new URL(await session.buildLoginUrl());
    const state = loginUrl.searchParams.get("state")!;

    await expect(
      session.handleCallback(`https://app.test/oidc/callback?code=abc123&state=${state}`)
    ).rejects.toThrow(/nonce mismatch/i);
    expect(session.isAuthenticated()).toBe(false);
  });

  it("accepts when the ID token's nonce claim matches the recorded transaction", async () => {
    const fetchFn = vi.fn();
    const session = createSession(baseConfig({ fetchFn }));
    const loginUrl = new URL(await session.buildLoginUrl());
    const state = loginUrl.searchParams.get("state")!;
    const nonce = loginUrl.searchParams.get("nonce")!;
    fetchFn.mockResolvedValue(tokenResponseWithNonce(nonce));

    const tokens = await session.handleCallback(`https://app.test/oidc/callback?code=abc123&state=${state}`);

    expect(tokens.accessToken).toBe("access-1");
    expect(session.isAuthenticated()).toBe(true);
  });

  it("does not treat a missing ID token as a nonce mismatch (nothing to compare)", async () => {
    const fetchFn = vi.fn().mockResolvedValue(tokenResponse({ id_token: undefined }));
    const session = createSession(baseConfig({ fetchFn }));
    const loginUrl = new URL(await session.buildLoginUrl());
    const state = loginUrl.searchParams.get("state")!;

    const tokens = await session.handleCallback(`https://app.test/oidc/callback?code=abc123&state=${state}`);

    expect(tokens.accessToken).toBe("access-1");
    expect(session.isAuthenticated()).toBe(true);
  });

  it("rejects when the ID token is not a decodable JWT at all (nonce claim unreadable)", async () => {
    const fetchFn = vi.fn().mockResolvedValue(tokenResponse({ id_token: "not-a-jwt" }));
    const session = createSession(baseConfig({ fetchFn }));
    const loginUrl = new URL(await session.buildLoginUrl());
    const state = loginUrl.searchParams.get("state")!;

    await expect(
      session.handleCallback(`https://app.test/oidc/callback?code=abc123&state=${state}`)
    ).rejects.toThrow(/nonce mismatch/i);
  });
});

describe("createSession — default navigate() (no navigate hook injected)", () => {
  const originalLocation = globalThis.location;

  afterEach(() => {
    vi.stubGlobal("location", originalLocation);
  });

  it("uses location.assign when available", async () => {
    const assign = vi.fn();
    vi.stubGlobal("location", { assign });
    const session = createSession(baseConfig({ navigate: undefined }));

    await session.login();

    expect(assign).toHaveBeenCalledTimes(1);
    expect(assign.mock.calls[0][0]).toContain("/auth/realms/kiban/protocol/openid-connect/auth");
  });

  it("falls back to setting location.href when location.assign is unavailable", async () => {
    const loc: { href: string } = { href: "" };
    vi.stubGlobal("location", loc);
    const session = createSession(baseConfig({ navigate: undefined }));

    await session.login();

    expect(loc.href).toContain("/auth/realms/kiban/protocol/openid-connect/auth");
  });

  it("throws when no navigate hook is injected and no global location is available", async () => {
    vi.stubGlobal("location", undefined);
    const session = createSession(baseConfig({ navigate: undefined }));

    await expect(session.login()).rejects.toThrow(/no navigate\(\) hook provided/i);
  });
});

describe("createSession — persisted-token hydration (persistTokens)", () => {
  it("hydrates currentTokens from storage on creation when persistTokens is set", () => {
    const storage = createMemoryStorage();
    storage.setItem(
      "kiban.oidc.tokens",
      JSON.stringify({ accessToken: "hydrated-access", refreshToken: "r1", expiresAt: 5_000_000 })
    );

    const session = createSession(baseConfig({ storage, persistTokens: true }));

    expect(session.getAccessToken()).toBe("hydrated-access");
    expect(session.isAuthenticated()).toBe(true);
  });

  it("does not hydrate from storage when persistTokens is not set, even if a stale entry exists", () => {
    const storage = createMemoryStorage();
    storage.setItem(
      "kiban.oidc.tokens",
      JSON.stringify({ accessToken: "stale-access", refreshToken: "r1", expiresAt: 5_000_000 })
    );

    const session = createSession(baseConfig({ storage }));

    expect(session.getAccessToken()).toBeNull();
    expect(session.isAuthenticated()).toBe(false);
  });

  it("hydrates to null (not throw) when the persisted tokens entry is malformed JSON", () => {
    const storage = createMemoryStorage();
    storage.setItem("kiban.oidc.tokens", "{not valid json");

    const session = createSession(baseConfig({ storage, persistTokens: true }));

    expect(session.getAccessToken()).toBeNull();
    expect(session.isAuthenticated()).toBe(false);
    expect(storage.getItem("kiban.oidc.tokens")).toBeNull();
  });

  it("drops (does not hydrate) an expired persisted TokenSet that has no refresh token, and clears it from storage", () => {
    const storage = createMemoryStorage();
    // now() is fixed at 1_000_000 (baseConfig); this entry expired well before that, even
    // accounting for the clock-skew allowance — and nothing could refresh it.
    storage.setItem("kiban.oidc.tokens", JSON.stringify({ accessToken: "expired-access", expiresAt: 500_000 }));

    const session = createSession(baseConfig({ storage, persistTokens: true }));

    expect(session.getAccessToken()).toBeNull();
    expect(session.isAuthenticated()).toBe(false);
    expect(storage.getItem("kiban.oidc.tokens")).toBeNull();
  });

  it("hydrates an expired persisted TokenSet that still has a refresh token, and refresh() renews it", async () => {
    const storage = createMemoryStorage();
    storage.setItem(
      "kiban.oidc.tokens",
      JSON.stringify({ accessToken: "expired-access", refreshToken: "r1", expiresAt: 500_000 })
    );
    const fetchFn = vi.fn().mockResolvedValue(tokenResponse({ access_token: "access-2" }));

    const session = createSession(baseConfig({ storage, persistTokens: true, fetchFn }));

    // A reload after idle keeps the session (the shell never bounces to /login, so the deep
    // link survives); the stale access token is what the 401 path hands to refresh().
    expect(session.isAuthenticated()).toBe(true);
    expect(session.getAccessToken()).toBe("expired-access");
    expect(storage.getItem("kiban.oidc.tokens")).not.toBeNull();

    expect(await session.refresh()).toBe("access-2");
    expect(fetchFn).toHaveBeenCalledTimes(1);
    expect(session.getAccessToken()).toBe("access-2");
  });

  it("drops (does not hydrate) a persisted entry with the wrong shape (not a TokenSet)", () => {
    const storage = createMemoryStorage();
    storage.setItem("kiban.oidc.tokens", JSON.stringify({ foo: "bar" }));

    const session = createSession(baseConfig({ storage, persistTokens: true }));

    expect(session.getAccessToken()).toBeNull();
    expect(session.isAuthenticated()).toBe(false);
    expect(storage.getItem("kiban.oidc.tokens")).toBeNull();
  });

  it("drops (does not hydrate) a persisted entry that is a JSON array/primitive, not an object", () => {
    const storage = createMemoryStorage();
    storage.setItem("kiban.oidc.tokens", JSON.stringify(["not", "an", "object"]));

    const session = createSession(baseConfig({ storage, persistTokens: true }));

    expect(session.getAccessToken()).toBeNull();
    expect(session.isAuthenticated()).toBe(false);
  });

  it("hydrates a token expiring just within the clock-skew allowance as still valid", () => {
    const storage = createMemoryStorage();
    // now() is 1_000_000; expiresAt is 20s in the past — inside the 30s skew allowance.
    storage.setItem(
      "kiban.oidc.tokens",
      JSON.stringify({ accessToken: "skew-ok", refreshToken: "r1", expiresAt: 1_000_000 - 20_000 })
    );

    const session = createSession(baseConfig({ storage, persistTokens: true }));

    expect(session.getAccessToken()).toBe("skew-ok");
    expect(session.isAuthenticated()).toBe(true);
  });
});

describe("createSession — single-flight refresh", () => {
  it("issues exactly one network call for 5 concurrent refresh() calls", async () => {
    const fetchFn = vi.fn().mockResolvedValue(tokenResponse({ access_token: "access-2" }));
    const storage = createMemoryStorage();
    storage.setItem(
      "kiban.oidc.tokens",
      JSON.stringify({ accessToken: "access-1", refreshToken: "refresh-1", expiresAt: 1_200_000 })
    );
    const session = createSession(baseConfig({ fetchFn, storage, persistTokens: true }));

    const results = await Promise.all([
      session.refresh(),
      session.refresh(),
      session.refresh(),
      session.refresh(),
      session.refresh()
    ]);

    expect(fetchFn).toHaveBeenCalledTimes(1);
    expect(results.every((token) => token === "access-2")).toBe(true);
    expect(session.getAccessToken()).toBe("access-2");
  });

  it("a refresh after the in-flight one completes triggers a new network call", async () => {
    const fetchFn = vi.fn().mockResolvedValue(tokenResponse({ access_token: "access-2" }));
    const storage = createMemoryStorage();
    storage.setItem(
      "kiban.oidc.tokens",
      JSON.stringify({ accessToken: "access-1", refreshToken: "refresh-1", expiresAt: 1_200_000 })
    );
    const session = createSession(baseConfig({ fetchFn, storage, persistTokens: true }));

    await session.refresh();
    await session.refresh();

    expect(fetchFn).toHaveBeenCalledTimes(2);
  });

  it("returns null without a network call and without clearing the session when there is no refresh token", async () => {
    const fetchFn = vi.fn();
    const storage = createMemoryStorage();
    storage.setItem("kiban.oidc.tokens", JSON.stringify({ accessToken: "access-1", expiresAt: 1_200_000 }));
    const session = createSession(baseConfig({ fetchFn, storage, persistTokens: true }));

    const result = await session.refresh();

    expect(result).toBeNull();
    expect(fetchFn).not.toHaveBeenCalled();
    // Nothing to refresh with is not an IdP rejection: the still-valid access token stays.
    expect(session.isAuthenticated()).toBe(true);
    expect(session.getAccessToken()).toBe("access-1");
    expect(storage.getItem("kiban.oidc.tokens")).not.toBeNull();
  });

  it("logout() during an in-flight refresh(): the late token response is never stored or re-persisted", async () => {
    let resolveFetch: (res: Response) => void = () => {};
    const fetchFn = vi.fn().mockImplementation(() => new Promise<Response>((resolve) => { resolveFetch = resolve; }));
    const storage = createMemoryStorage();
    storage.setItem(
      "kiban.oidc.tokens",
      JSON.stringify({ accessToken: "access-1", refreshToken: "refresh-1", expiresAt: 1_200_000 })
    );
    const session = createSession(baseConfig({ fetchFn, storage, persistTokens: true }));

    const pending = session.refresh();
    session.logout();
    resolveFetch(tokenResponse({ access_token: "access-2", refresh_token: "refresh-2" }));

    expect(await pending).toBeNull();
    expect(session.getTokens()).toBeNull();
    expect(session.isAuthenticated()).toBe(false);
    expect(storage.getItem("kiban.oidc.tokens")).toBeNull();
  });

  it("clears the session when the refresh request itself fails", async () => {
    const fetchFn = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ error: "invalid_grant" }), { status: 400 })
    );
    const storage = createMemoryStorage();
    storage.setItem(
      "kiban.oidc.tokens",
      JSON.stringify({ accessToken: "access-1", refreshToken: "refresh-1", expiresAt: 1_200_000 })
    );
    const session = createSession(baseConfig({ fetchFn, storage, persistTokens: true }));

    const result = await session.refresh();

    expect(result).toBeNull();
    expect(session.isAuthenticated()).toBe(false);
    expect(storage.getItem("kiban.oidc.tokens")).toBeNull();
  });

  it("keeps the previous refresh token when the refresh response omits one", async () => {
    const fetchFn = vi.fn().mockResolvedValue(
      tokenResponse({ access_token: "access-2", refresh_token: undefined })
    );
    const storage = createMemoryStorage();
    storage.setItem(
      "kiban.oidc.tokens",
      JSON.stringify({ accessToken: "access-1", refreshToken: "refresh-original", expiresAt: 1_200_000 })
    );
    const session = createSession(baseConfig({ fetchFn, storage, persistTokens: true }));

    const result = await session.refresh();

    expect(result).toBe("access-2");
    expect(session.getTokens()?.refreshToken).toBe("refresh-original");
    const persisted = JSON.parse(storage.getItem("kiban.oidc.tokens")!);
    expect(persisted.refreshToken).toBe("refresh-original");
  });

  it("a refresh response WITH a refresh_token still overwrites the previous one", async () => {
    const fetchFn = vi.fn().mockResolvedValue(
      tokenResponse({ access_token: "access-2", refresh_token: "refresh-rotated" })
    );
    const storage = createMemoryStorage();
    storage.setItem(
      "kiban.oidc.tokens",
      JSON.stringify({ accessToken: "access-1", refreshToken: "refresh-original", expiresAt: 1_200_000 })
    );
    const session = createSession(baseConfig({ fetchFn, storage, persistTokens: true }));

    await session.refresh();

    expect(session.getTokens()?.refreshToken).toBe("refresh-rotated");
  });

  it("a network-failure rejection resolves refresh() to null WITHOUT clearing existing session state", async () => {
    const fetchFn = vi.fn().mockRejectedValue(new TypeError("Failed to fetch"));
    const storage = createMemoryStorage();
    storage.setItem(
      "kiban.oidc.tokens",
      JSON.stringify({ accessToken: "access-1", refreshToken: "refresh-original", expiresAt: 1_200_000 })
    );
    const session = createSession(baseConfig({ fetchFn, storage, persistTokens: true }));

    const result = await session.refresh();

    expect(result).toBeNull();
    // Unlike an IdP-rejected refresh (invalid_grant etc.), a network blip must not force the
    // user back through a full login — the prior token set (and its refresh token, for a later
    // retry) is left intact.
    expect(session.isAuthenticated()).toBe(true);
    expect(session.getTokens()?.refreshToken).toBe("refresh-original");
    expect(storage.getItem("kiban.oidc.tokens")).not.toBeNull();
  });
});

describe("createSession — isAuthenticated is expiry-aware", () => {
  it("returns false once a token set WITHOUT a refresh token has passed expiry (beyond the clock-skew allowance), without any refresh/logout call", async () => {
    let currentTime = 1_000_000;
    const fetchFn = vi.fn();
    const session = createSession(baseConfig({ fetchFn, now: () => currentTime }));
    const loginUrl = new URL(await session.buildLoginUrl());
    const state = loginUrl.searchParams.get("state")!;
    const nonce = loginUrl.searchParams.get("nonce")!;
    fetchFn.mockResolvedValue(tokenResponseWithNonce(nonce, { expires_in: 300, refresh_token: undefined }));

    await session.handleCallback(`https://app.test/oidc/callback?code=abc123&state=${state}`);
    expect(session.isAuthenticated()).toBe(true);

    // Advance the clock well past expiresAt (currentTime + 300_000) plus the clock-skew
    // allowance — the exact same in-memory TokenSet object is still sitting there (no refresh(),
    // no logout() was called), proving isAuthenticated() itself checks expiry, not presence.
    currentTime += 300_000 + 60_000;
    expect(session.isAuthenticated()).toBe(false);
    expect(session.getTokens()).not.toBeNull();
  });

  it("stays true past expiry while a refresh token is held (the next 401 refreshes, the host must not bounce to re-login)", async () => {
    let currentTime = 1_000_000;
    const fetchFn = vi.fn();
    const session = createSession(baseConfig({ fetchFn, now: () => currentTime }));
    const loginUrl = new URL(await session.buildLoginUrl());
    const state = loginUrl.searchParams.get("state")!;
    const nonce = loginUrl.searchParams.get("nonce")!;
    fetchFn.mockResolvedValue(tokenResponseWithNonce(nonce, { expires_in: 300 }));

    await session.handleCallback(`https://app.test/oidc/callback?code=abc123&state=${state}`);
    currentTime += 300_000 + 60_000;

    expect(session.isAuthenticated()).toBe(true);
  });

  it("returns true for a token set that has not yet expired", () => {
    const storage = createMemoryStorage();
    storage.setItem(
      "kiban.oidc.tokens",
      JSON.stringify({ accessToken: "still-good", refreshToken: "r1", expiresAt: 1_200_000 })
    );
    const session = createSession(baseConfig({ storage, persistTokens: true }));

    expect(session.isAuthenticated()).toBe(true);
  });
});

describe("createSession — logout", () => {
  it("clears state and navigates to the RP-initiated logout endpoint with id_token_hint", async () => {
    const fetchFn = vi.fn();
    const navigate = vi.fn();
    const storage = createMemoryStorage();
    const session = createSession(baseConfig({ fetchFn, navigate, storage }));
    const loginUrl = new URL(await session.buildLoginUrl());
    const state = loginUrl.searchParams.get("state")!;
    const nonce = loginUrl.searchParams.get("nonce")!;
    const idToken = makeIdToken({ nonce });
    fetchFn.mockResolvedValue(tokenResponse({ id_token: idToken }));
    await session.handleCallback(`https://app.test/oidc/callback?code=abc123&state=${state}`);

    session.logout();

    expect(session.isAuthenticated()).toBe(false);
    expect(session.getTokens()).toBeNull();
    expect(navigate).toHaveBeenCalledTimes(1);
    const [logoutUrl] = navigate.mock.calls[0] as [string];
    const parsed = new URL(logoutUrl);
    expect(parsed.pathname).toBe("/auth/realms/kiban/protocol/openid-connect/logout");
    expect(parsed.searchParams.get("id_token_hint")).toBe(idToken);
    // Defaults to the app's origin ROOT, not the login callback path — logout must
    // not land back on `/oidc/callback` (that route unconditionally attempts code exchange and
    // errors on a code/state-less logout redirect).
    expect(parsed.searchParams.get("post_logout_redirect_uri")).toBe("https://app.test/");
    expect(parsed.searchParams.get("client_id")).toBe("kiban-frontend");
  });

  it("postLogoutRedirectUri defaults to the redirectUri's origin root, not the callback path", () => {
    const navigate = vi.fn();
    const session = createSession(
      baseConfig({ navigate, redirectUri: "https://app.test/some/nested/callback?x=1" })
    );

    session.logout();

    const [logoutUrl] = navigate.mock.calls[0] as [string];
    expect(new URL(logoutUrl).searchParams.get("post_logout_redirect_uri")).toBe("https://app.test/");
  });

  it("postLogoutRedirectUri is still overridable via config", () => {
    const navigate = vi.fn();
    const session = createSession(
      baseConfig({ navigate, postLogoutRedirectUri: "https://app.test/signed-out" })
    );

    session.logout();

    const [logoutUrl] = navigate.mock.calls[0] as [string];
    expect(new URL(logoutUrl).searchParams.get("post_logout_redirect_uri")).toBe("https://app.test/signed-out");
  });

  it("logout() is safe to call when never authenticated", () => {
    const navigate = vi.fn();
    const session = createSession(baseConfig({ navigate }));

    expect(() => session.logout()).not.toThrow();
    expect(navigate).toHaveBeenCalledTimes(1);
    const [logoutUrl] = navigate.mock.calls[0] as [string];
    expect(new URL(logoutUrl).searchParams.has("id_token_hint")).toBe(false);
  });
});

describe("createSession — token persistence never uses localStorage", () => {
  it("with persistTokens, tokens are written to the injected storage adapter, not any global localStorage", async () => {
    const fetchFn = vi.fn();
    const storage = createMemoryStorage();
    const session = createSession(baseConfig({ fetchFn, storage, persistTokens: true }));
    const loginUrl = new URL(await session.buildLoginUrl());
    const state = loginUrl.searchParams.get("state")!;
    const nonce = loginUrl.searchParams.get("nonce")!;
    fetchFn.mockResolvedValue(tokenResponseWithNonce(nonce));

    await session.handleCallback(`https://app.test/oidc/callback?code=abc123&state=${state}`);

    expect(storage.getItem("kiban.oidc.tokens")).toBeTruthy();
  });

  it("without persistTokens (default), nothing is written for tokens at all", async () => {
    const fetchFn = vi.fn();
    const storage = createMemoryStorage();
    const session = createSession(baseConfig({ fetchFn, storage }));
    const loginUrl = new URL(await session.buildLoginUrl());
    const state = loginUrl.searchParams.get("state")!;
    const nonce = loginUrl.searchParams.get("nonce")!;
    fetchFn.mockResolvedValue(tokenResponseWithNonce(nonce));

    await session.handleCallback(`https://app.test/oidc/callback?code=abc123&state=${state}`);

    expect(storage.getItem("kiban.oidc.tokens")).toBeNull();
    expect(session.getAccessToken()).toBe("access-1");
  });
});

describe("decodeIdTokenClaims", () => {
  it("returns the payload claims of a JWT-shaped token without verifying it", () => {
    expect(decodeIdTokenClaims(makeIdToken({ nonce: "n-1", name: "Alice", email: "a@example.test" }))).toEqual({
      nonce: "n-1",
      name: "Alice",
      email: "a@example.test"
    });
  });

  it("returns undefined for a token with no decodable JSON payload segment", () => {
    expect(decodeIdTokenClaims("not-a-jwt")).toBeUndefined();
    expect(decodeIdTokenClaims("a.!!!.c")).toBeUndefined();
  });
});
