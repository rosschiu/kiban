// SPDX-License-Identifier: Apache-2.0

// Envelope-aware fetch wrapper. Base origin is always the gateway (which forwards the path
// opaquely) — never a direct module/Keycloak origin. Native fetch/crypto only — zero runtime
// dependencies.
import type { ApiDataEnvelope, ApiErrorEnvelope } from "./types.js";

/** Thrown for every non-2xx response once the error envelope has been parsed (or a transport/
 * parse failure prevented that). `code` is the platform's canonical error code
 * (see `ApiErrorCode`) when the body parsed, else `"UNKNOWN_ERROR"`. */
export class KibanApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly details?: unknown;
  readonly correlationId?: string;

  constructor(status: number, code: string, message: string, details?: unknown, correlationId?: string) {
    super(message);
    this.name = "KibanApiError";
    this.status = status;
    this.code = code;
    this.details = details;
    this.correlationId = correlationId;
  }
}

/** Per-call overrides for {@link ApiClient.request}. */
export interface RequestOptions {
  method?: string;
  /** JSON-serializable request body. Sent as `application/json`. */
  body?: unknown;
  headers?: Record<string, string>;
  signal?: AbortSignal;
  /** Query params appended to the URL (undefined values are skipped). */
  query?: Record<string, string | number | boolean | undefined>;
}

/** Construction options for {@link createApiClient}. */
export interface ApiClientConfig {
  /** Gateway origin, e.g. `https://127.0.0.1:8443`. No trailing slash required. */
  baseUrl: string;
  /** Returns the current bearer token, or null/undefined when signed out. */
  getAccessToken?: () => string | null | undefined;
  /** Called on a 401 response. Should perform (or await an in-flight) token refresh and
   * return the new access token, or null/undefined if refresh failed. The client retries
   * the request exactly once when this resolves to a token — never more (avoids refresh
   * loops on a persistently-401ing endpoint). Session single-flight refresh coordination
   * lives in auth/session.ts; this hook just needs to return a fresh token. */
  refreshAccessToken?: () => Promise<string | null | undefined>;
  /** Returns the current access token's expiry as epoch milliseconds (a Session's
   * `getTokens()?.expiresAt`). When set together with `refreshAccessToken`, a token that
   * expires within the next 30 seconds is refreshed before the request is sent, so a request
   * never reaches a service with a token that dies in flight (a module that forwards the bearer
   * to another service would otherwise answer 503, which no 401 retry can recover). */
  getAccessTokenExpiresAt?: () => number | null | undefined;
  /** Injectable for tests; defaults to global fetch. */
  fetchFn?: typeof fetch;
  /** Injectable correlation id generator; defaults to crypto.randomUUID(). */
  correlationId?: () => string;
}

/** The SDK's shared, envelope-aware fetch wrapper — every typed client (`org`, `capabilities`,
 * `effectiveAccess`, `superadmin`, module clients) is built on top of one `ApiClient`
 * instance. */
export interface ApiClient {
  readonly baseUrl: string;
  /** Issues one request: attaches the bearer + correlation id, JSON-encodes `options.body`,
   * unwraps the `{data}`/`{error}` envelope, retries once on 401 via `refreshAccessToken`. */
  request<T>(path: string, options?: RequestOptions): Promise<T>;
}

/** A token this close to expiry is refreshed before use (Keycloak's default access-token
 * lifespan is 300 s; the gateway and the services each verify with their own clock). */
const EXPIRY_REFRESH_WINDOW_MS = 30_000;

function defaultCorrelationId(): string {
  const g = globalThis as { crypto?: { randomUUID?: () => string } };
  if (g.crypto?.randomUUID) return g.crypto.randomUUID();
  // Fallback (older runtimes without crypto.randomUUID): not cryptographically strong,
  // only used as a request-tracing id, never a security token.
  return `cid-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`;
}

function buildUrl(baseUrl: string, path: string, query?: RequestOptions["query"]): string {
  const url = new URL(path, baseUrl.endsWith("/") ? baseUrl : `${baseUrl}/`);
  if (query) {
    for (const [key, value] of Object.entries(query)) {
      if (value !== undefined) url.searchParams.set(key, String(value));
    }
  }
  return url.toString();
}

/** Creates the envelope-aware fetch wrapper: base origin, bearer attach, x-correlation-id,
 * `{data}`/`{error}` envelope unwrap → KibanApiError, single 401-refresh-and-retry. */
export function createApiClient(config: ApiClientConfig): ApiClient {
  const fetchImpl = config.fetchFn ?? fetch;
  const genCorrelationId = config.correlationId ?? defaultCorrelationId;

  async function request<T>(path: string, options: RequestOptions = {}, isRetry = false): Promise<T> {
    const url = buildUrl(config.baseUrl, path, options.query);
    const correlationId = genCorrelationId();
    const headers: Record<string, string> = {
      "x-correlation-id": correlationId,
      ...options.headers
    };
    let token = config.getAccessToken?.();
    if (token && !isRetry && config.refreshAccessToken && config.getAccessTokenExpiresAt) {
      const expiresAt = config.getAccessTokenExpiresAt();
      if (typeof expiresAt === "number" && expiresAt - Date.now() < EXPIRY_REFRESH_WINDOW_MS) {
        token = (await config.refreshAccessToken()) ?? token;
      }
    }
    if (token) headers.Authorization = `Bearer ${token}`;

    let body: string | undefined;
    if (options.body !== undefined) {
      headers["content-type"] = "application/json";
      body = JSON.stringify(options.body);
    }

    const res = await fetchImpl(url, {
      method: options.method ?? "GET",
      headers,
      body,
      signal: options.signal
    });

    if (res.status === 401 && !isRetry && config.refreshAccessToken) {
      const newToken = await config.refreshAccessToken();
      if (newToken) {
        return request<T>(path, options, true);
      }
    }

    if (res.status === 204) {
      return undefined as T;
    }

    const contentType = res.headers.get("content-type") ?? "";
    const parsed: unknown = contentType.includes("application/json") ? await res.json().catch(() => undefined) : undefined;

    if (!res.ok) {
      const errBody = (parsed as ApiErrorEnvelope | undefined)?.error;
      throw new KibanApiError(
        res.status,
        errBody?.code ?? "UNKNOWN_ERROR",
        errBody?.message ?? (res.statusText || "Request failed"),
        errBody?.details,
        correlationId
      );
    }

    return (parsed as ApiDataEnvelope<T> | undefined)?.data as T;
  }

  return { baseUrl: config.baseUrl, request };
}
