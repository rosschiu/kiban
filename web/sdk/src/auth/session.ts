// SPDX-License-Identifier: Apache-2.0

// OIDC authorization-code + PKCE session against the gateway's Keycloak proxy
// (`/auth/realms/<realm>/protocol/openid-connect/...` — never a direct Keycloak origin).
// Guarantees: PKCE S256, single-flight refresh, StrictMode-safe idempotent code exchange, tokens never in localStorage (memory + optional
// sessionStorage persistence flag), RP-initiated logout with id_token_hint.
import { generateCodeChallenge, generateCodeVerifier, generateRandomToken } from "./pkce.js";
import { defaultSessionStorage, type StorageAdapter } from "../storage.js";

const TRANSACTION_KEY = "kiban.oidc.transaction";
const TOKENS_KEY = "kiban.oidc.tokens";

/** The token triple a successful login/refresh/handleCallback resolves to. */
export interface TokenSet {
  accessToken: string;
  refreshToken?: string;
  idToken?: string;
  /** Epoch milliseconds. */
  expiresAt: number;
}

/** Construction options for {@link createSession}. */
export interface SessionConfig {
  /** Gateway origin, e.g. `https://127.0.0.1:8443`. All OIDC endpoints are relative to this —
   * the SDK never talks to Keycloak directly. */
  authOrigin: string;
  /** Keycloak realm name. */
  realm: string;
  /** Public OIDC client id. */
  clientId: string;
  /** Where the browser lands after a successful login. Must be registered as a redirect URI on
   * the client; same-origin/return-path sanitization is the host app's concern, not the
   * SDK's. */
  redirectUri: string;
  /** Where the browser lands after RP-initiated logout. Defaults to the app ORIGIN ROOT (derived
   * from `redirectUri`'s origin, e.g. `https://app.test/`) — never `redirectUri` itself, which
   * is the login callback route and cannot handle a logout redirect (no code/state params). */
  postLogoutRedirectUri?: string;
  /** Defaults to `"openid"`. */
  scope?: string;
  /** Injectable for tests; defaults to global fetch. */
  fetchFn?: typeof fetch;
  /** Injectable transaction/token storage; defaults to `sessionStorage` (or an in-memory
   * fallback when unavailable). Never defaults to `localStorage`. */
  storage?: StorageAdapter;
  /** Also persist the current TokenSet to `storage` (survives a page refresh) in addition to
   * keeping it in memory. Still never localStorage — `storage` here is the same
   * sessionStorage-or-injected adapter used for the PKCE transaction. Defaults to false
   * (memory-only, the safer default). A persisted entry is only hydrated back if it still has
   * the right shape and is still usable: not expired (a small clock-skew allowance applies), or
   * expired but carrying a refresh token (the next 401 refreshes it); anything else is dropped
   * rather than trusted. */
  persistTokens?: boolean;
  /** Navigation hook for `login()`/`logout()`; defaults to `window.location.assign`. Injectable
   * so tests never actually navigate. */
  navigate?: (url: string) => void;
  /** Clock injection for tests. */
  now?: () => number;
}

interface OidcTransaction {
  verifier: string;
  state: string;
  nonce: string;
  redirectUri: string;
}

interface TokenResponseBody {
  access_token: string;
  refresh_token?: string;
  id_token?: string;
  expires_in?: number;
  error?: string;
  error_description?: string;
}

/** OIDC/PKCE session handle returned by {@link createSession}. */
export interface Session {
  /** Redirects the browser to Keycloak's authorization endpoint (PKCE S256). */
  login(): Promise<void>;
  /** Builds the login redirect URL and records the PKCE transaction, without navigating —
   * useful for tests and for hosts that want to control navigation themselves. */
  buildLoginUrl(): Promise<string>;
  /** Handles the OIDC callback URL (must contain `code` and `state`). Idempotent: a second
   * invocation with the same `code` (React StrictMode double-effect) returns the same result
   * instead of re-exchanging an already-consumed authorization code. */
  handleCallback(callbackUrl: string): Promise<TokenSet>;
  /** Current access token, or null when signed out. Synchronous — never triggers a refresh;
   * pair with an ApiClient's `refreshAccessToken` hook (this session's `refresh`) for
   * 401-triggered refresh. */
  getAccessToken(): string | null;
  /** Refreshes the access token using the stored refresh token. Single-flight: concurrent
   * callers share one in-flight network call. Resolves to the new access token, or null if
   * refresh is impossible or fails. Only an IdP-rejected refresh (invalid/expired/revoked
   * refresh token) clears the session; a network-failure rejection resolves to null but leaves
   * the existing session state (including the refresh token) intact for a later retry. A
   * successful refresh response that omits `refresh_token` keeps the previous one instead of
   * discarding it. */
  refresh(): Promise<string | null>;
  /** Clears session state (tokens; the host app's own SessionContext, if any, is its own
   * responsibility to clear) and redirects to Keycloak's RP-initiated logout endpoint. A
   * `refresh()` still in flight at that moment is abandoned: its result is never stored. */
  logout(): void;
  /** Current TokenSet (all three tokens + expiry), or null when signed out. Synchronous, like
   * `getAccessToken()`. */
  getTokens(): TokenSet | null;
  /** True when there is a current TokenSet that is still usable: its access token has not passed
   * expiry (with a small clock-skew allowance), OR it carries a refresh token (an expired access
   * token is refreshed by the next 401 — only an IdP-rejected refresh or `logout()` ends the
   * session). Presence alone is not enough: an expired set without a refresh token is not
   * authenticated. Synchronous, like `getAccessToken()`; never triggers a refresh. */
  isAuthenticated(): boolean;
}

function defaultNavigate(url: string): void {
  const loc = (globalThis as { location?: { assign?: (u: string) => void; href?: string } }).location;
  if (loc?.assign) {
    loc.assign(url);
  } else if (loc) {
    loc.href = url;
  } else {
    throw new Error("No navigate() hook provided and no global `location` is available");
  }
}

function realmUrl(authOrigin: string, realm: string, path: string): string {
  const base = authOrigin.endsWith("/") ? authOrigin : `${authOrigin}/`;
  return new URL(`auth/realms/${encodeURIComponent(realm)}/protocol/openid-connect/${path}`, base).toString();
}

function base64UrlDecode(segment: string): string {
  const padded = segment.replace(/-/g, "+").replace(/_/g, "/");
  const pad = padded.length % 4 === 0 ? "" : "=".repeat(4 - (padded.length % 4));
  return atob(padded + pad);
}

/** Decodes an ID token's payload claims WITHOUT verifying its signature — signature trust stays
 * with the gateway/services, so use the result for display only (name/email/picture), never for
 * an authorization decision. Returns undefined when the token has no decodable JSON payload
 * segment. */
export function decodeIdTokenClaims(idToken: string): Record<string, unknown> | undefined {
  const parts = idToken.split(".");
  const payloadSegment = parts[1];
  if (parts.length < 2 || payloadSegment === undefined) return undefined;
  try {
    return JSON.parse(base64UrlDecode(payloadSegment)) as Record<string, unknown>;
  } catch {
    return undefined;
  }
}

/** The session's own nonce check: the `nonce` claim of {@link decodeIdTokenClaims}, or undefined
 * when absent or not a string. */
function decodeIdTokenNonce(idToken: string): string | undefined {
  const nonce = decodeIdTokenClaims(idToken)?.nonce;
  return typeof nonce === "string" ? nonce : undefined;
}

/** Clock-skew allowance shared by hydration validation and isAuthenticated: a token that
 * expired within the last 30s is still treated as live (a refresh started right at expiry
 * should not read as "logged out" for that window). */
const CLOCK_SKEW_MS = 30_000;

function isNotExpired(expiresAt: number, nowMs: number): boolean {
  return expiresAt > nowMs - CLOCK_SKEW_MS;
}

/** A TokenSet is usable when its access token is not expired (using the injected clock +
 * CLOCK_SKEW_MS) or it carries a refresh token — the 401 path refreshes an expired access token,
 * so only an expired set WITHOUT a refresh token is dead. */
function isUsable(tokens: TokenSet, nowMs: number): boolean {
  return isNotExpired(tokens.expiresAt, nowMs) || typeof tokens.refreshToken === "string";
}

/** Structural validation for a persisted TokenSet before it is trusted: must be
 * a plain object with a non-empty string accessToken and a finite numeric expiresAt, and be
 * usable per {@link isUsable}. Anything else is treated as absent. */
function isValidUsableTokenSet(value: unknown, nowMs: number): value is TokenSet {
  if (typeof value !== "object" || value === null) return false;
  const candidate = value as Partial<TokenSet>;
  if (typeof candidate.accessToken !== "string" || candidate.accessToken.length === 0) return false;
  if (typeof candidate.expiresAt !== "number" || !Number.isFinite(candidate.expiresAt)) return false;
  if (candidate.refreshToken !== undefined && typeof candidate.refreshToken !== "string") return false;
  if (candidate.idToken !== undefined && typeof candidate.idToken !== "string") return false;
  return isUsable(candidate as TokenSet, nowMs);
}

/** Builds a {@link Session}: OIDC authorization-code + PKCE against the gateway's Keycloak
 * proxy, single-flight refresh, StrictMode-safe idempotent code exchange. */
export function createSession(config: SessionConfig): Session {
  const fetchImpl = config.fetchFn ?? fetch;
  const storage = config.storage ?? defaultSessionStorage();
  const navigate = config.navigate ?? defaultNavigate;
  const now = config.now ?? (() => Date.now());
  const scope = config.scope ?? "openid";
  // Default to the app's ORIGIN ROOT, not `redirectUri` (the login callback route) — Keycloak's
  // RP-initiated logout lands the browser on this URL directly, and a `/callback` route that
  // unconditionally attempts authorization-code handling would fail with "OIDC callback URL is
  // missing code and/or state" at the end of every logout. Still overridable via config.
  const postLogoutRedirectUri = config.postLogoutRedirectUri ?? `${new URL(config.redirectUri).origin}/`;

  let currentTokens: TokenSet | null = hydrateTokens();
  let refreshInFlight: Promise<string | null> | null = null;
  // Bumped by logout(): a refresh() that started before the bump must never store its result
  // (a late token response would otherwise re-persist a live session after logout).
  let generation = 0;
  const processedCodes = new Map<string, Promise<TokenSet>>();

  function hydrateTokens(): TokenSet | null {
    if (!config.persistTokens) return null;
    const raw = storage.getItem(TOKENS_KEY);
    if (!raw) return null;
    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch {
      storage.removeItem(TOKENS_KEY);
      return null;
    }
    // Never trust a persisted entry on its shape alone — a dead/corrupt sessionStorage entry (a
    // previous session that expired with no refresh token, a manually-edited value, a schema
    // change) must not be hydrated as a live session. Drop it instead. An expired access token
    // WITH a refresh token is kept: a page reload after a few idle minutes must not force a
    // re-login (and lose the deep link) while the refresh token is still good.
    if (!isValidUsableTokenSet(parsed, now())) {
      storage.removeItem(TOKENS_KEY);
      return null;
    }
    return parsed;
  }

  function setTokens(tokens: TokenSet): void {
    currentTokens = tokens;
    if (config.persistTokens) {
      storage.setItem(TOKENS_KEY, JSON.stringify(tokens));
    }
  }

  function clearTokens(): void {
    currentTokens = null;
    storage.removeItem(TOKENS_KEY);
  }

  function mapTokenResponse(body: TokenResponseBody, previousRefreshToken?: string): TokenSet {
    return {
      accessToken: body.access_token,
      // A refresh response is allowed to omit `refresh_token` (the IdP is telling
      // us to keep using the one we already have, not that it's gone) — keep the previous value
      // instead of discarding a still-valid refresh token.
      refreshToken: body.refresh_token ?? previousRefreshToken,
      idToken: body.id_token,
      expiresAt: now() + (body.expires_in ?? 300) * 1000
    };
  }

  async function buildLoginUrl(): Promise<string> {
    const verifier = generateCodeVerifier();
    const challenge = await generateCodeChallenge(verifier);
    const state = generateRandomToken();
    const nonce = generateRandomToken();

    const transaction: OidcTransaction = { verifier, state, nonce, redirectUri: config.redirectUri };
    storage.setItem(TRANSACTION_KEY, JSON.stringify(transaction));

    const url = new URL(realmUrl(config.authOrigin, config.realm, "auth"));
    url.searchParams.set("response_type", "code");
    url.searchParams.set("client_id", config.clientId);
    url.searchParams.set("redirect_uri", config.redirectUri);
    url.searchParams.set("scope", scope);
    url.searchParams.set("state", state);
    url.searchParams.set("nonce", nonce);
    url.searchParams.set("code_challenge", challenge);
    url.searchParams.set("code_challenge_method", "S256");
    return url.toString();
  }

  async function login(): Promise<void> {
    navigate(await buildLoginUrl());
  }

  async function exchangeCode(code: string, state: string): Promise<TokenSet> {
    const raw = storage.getItem(TRANSACTION_KEY);
    if (!raw) {
      throw new Error(
        "No pending OIDC transaction found — handleCallback() was invoked without a matching login(), or the transaction storage was cleared"
      );
    }
    const transaction = JSON.parse(raw) as OidcTransaction;
    if (transaction.state !== state) {
      storage.removeItem(TRANSACTION_KEY);
      throw new Error("OIDC state mismatch (possible CSRF or a stale transaction)");
    }

    const body = new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: transaction.redirectUri,
      client_id: config.clientId,
      code_verifier: transaction.verifier
    });

    const res = await fetchImpl(realmUrl(config.authOrigin, config.realm, "token"), {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body
    });
    storage.removeItem(TRANSACTION_KEY);

    const parsed = (await res.json().catch(() => undefined)) as TokenResponseBody | undefined;
    if (!res.ok || !parsed?.access_token) {
      throw new Error(
        `OIDC code exchange failed (${res.status}): ${parsed?.error_description ?? parsed?.error ?? res.statusText}`
      );
    }

    const tokens = mapTokenResponse(parsed);

    // Nonce validation: the ID token's `nonce` claim must match the value this
    // session generated and recorded in buildLoginUrl(); otherwise the token was not issued for
    // this login transaction (replay/CSRF). Signature trust stays with the gateway/services —
    // this is a claim compare only. Nothing to compare against when the IdP omits an ID token
    // (e.g. a scope without `openid`), so that case is not treated as a mismatch.
    if (tokens.idToken) {
      const claimNonce = decodeIdTokenNonce(tokens.idToken);
      if (claimNonce !== transaction.nonce) {
        throw new Error("OIDC nonce mismatch (ID token does not match the login transaction — possible replay/CSRF)");
      }
    }

    setTokens(tokens);
    return tokens;
  }

  async function handleCallback(callbackUrl: string): Promise<TokenSet> {
    const url = new URL(callbackUrl, "http://placeholder.invalid");
    const code = url.searchParams.get("code");
    const state = url.searchParams.get("state");
    const error = url.searchParams.get("error");
    if (error) {
      throw new Error(`OIDC callback returned an error: ${error} (${url.searchParams.get("error_description") ?? ""})`);
    }
    if (!code || !state) {
      throw new Error("OIDC callback URL is missing code and/or state");
    }

    // Idempotency (React StrictMode double-invoke): the same code must never be exchanged
    // twice. Checked/claimed synchronously (before any await) so two back-to-back calls with
    // the same code — whether concurrent or sequential — collapse into one exchange.
    const existing = processedCodes.get(code);
    if (existing) return existing;

    const promise = exchangeCode(code, state);
    processedCodes.set(code, promise);
    return promise;
  }

  function getAccessToken(): string | null {
    return currentTokens?.accessToken ?? null;
  }

  async function doRefresh(): Promise<string | null> {
    const tokens = currentTokens;
    if (!tokens?.refreshToken) {
      return null;
    }
    const body = new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: tokens.refreshToken,
      client_id: config.clientId
    });
    const startedIn = generation;
    let res: Response;
    try {
      res = await fetchImpl(realmUrl(config.authOrigin, config.realm, "token"), {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body
      });
    } catch {
      // A network-failure rejection (offline, DNS, CORS, gateway unreachable) is
      // not the IdP telling us the refresh token is invalid — the existing session state is left
      // untouched so a later refresh() attempt can retry with the same refresh token, instead of
      // being forced into a full re-login for what may be a transient blip.
      return null;
    }
    const parsed = (await res.json().catch(() => undefined)) as TokenResponseBody | undefined;
    // logout() ran while the request was in flight: the session is over regardless of what the
    // IdP answered — never re-persist, never touch the (already cleared) state.
    if (generation !== startedIn) return null;
    if (!res.ok || !parsed?.access_token) {
      // Unlike a network failure, a reachable IdP that rejects the refresh token (expired,
      // revoked, invalid_grant) is authoritative — the session really is over.
      clearTokens();
      return null;
    }
    const next = mapTokenResponse(parsed, tokens.refreshToken);
    setTokens(next);
    return next.accessToken;
  }

  function refresh(): Promise<string | null> {
    if (refreshInFlight) return refreshInFlight;
    refreshInFlight = doRefresh().finally(() => {
      refreshInFlight = null;
    });
    return refreshInFlight;
  }

  function logout(): void {
    const idToken = currentTokens?.idToken;
    generation += 1;
    refreshInFlight = null;
    clearTokens();
    storage.removeItem(TRANSACTION_KEY);
    processedCodes.clear();

    const url = new URL(realmUrl(config.authOrigin, config.realm, "logout"));
    url.searchParams.set("post_logout_redirect_uri", postLogoutRedirectUri);
    url.searchParams.set("client_id", config.clientId);
    if (idToken) url.searchParams.set("id_token_hint", idToken);
    navigate(url.toString());
  }

  function getTokens(): TokenSet | null {
    return currentTokens;
  }

  function isAuthenticated(): boolean {
    // Presence alone is not enough — an expired TokenSet (past expiresAt, minus the shared
    // clock-skew allowance) with no refresh token is not an authenticated session even though the
    // object is still sitting in memory. An expired set WITH a refresh token still is: the next
    // 401 refreshes it, and a host that treated it as signed out would bounce the user to a
    // re-login (losing the current URL) for a session the IdP still honours.
    return currentTokens !== null && isUsable(currentTokens, now());
  }

  return {
    login,
    buildLoginUrl,
    handleCallback,
    getAccessToken,
    refresh,
    logout,
    getTokens,
    isAuthenticated
  };
}
