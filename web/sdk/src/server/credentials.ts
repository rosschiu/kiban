// SPDX-License-Identifier: Apache-2.0

import { stripTrailingSlashes } from "./origin";

/** Configuration for {@link createServiceCredentials}: the app's confidential service client
 * (one of `KIBAN_SERVICE_CLIENTS`) and the gateway it authenticates against. */
export interface ServiceCredentialsConfig {
  /** Gateway origin, e.g. `https://kiban.example`. */
  gatewayOrigin: string;
  /** Realm name; defaults to `kiban`. */
  realm?: string;
  /** The service client id. */
  clientId: string;
  /** The service client secret (from the Keycloak admin console). */
  clientSecret: string;
  /** Override for `fetch` (tests). */
  fetchFn?: typeof fetch;
}

/** A service token source: obtains the app's own access token by the client-credentials grant
 * and caches it until shortly before it expires. */
export interface ServiceCredentials {
  /** Returns a valid access token for the service client, fetching a new one when needed. */
  getAccessToken(): Promise<string>;
}

/** A token this close to expiry is replaced before use. */
const EXPIRY_WINDOW_MS = 30_000;

/** Creates a cached client-credentials token source for the app's service client. */
export function createServiceCredentials(config: ServiceCredentialsConfig): ServiceCredentials {
  const fetchImpl = config.fetchFn ?? fetch;
  const realm = config.realm ?? "kiban";
  const tokenUrl = `${stripTrailingSlashes(config.gatewayOrigin)}/realms/${realm}/protocol/openid-connect/token`;
  let token: string | null = null;
  let expiresAt = 0;
  let inflight: Promise<string> | null = null;

  async function fetchToken(): Promise<string> {
    const body = new URLSearchParams({
      grant_type: "client_credentials",
      client_id: config.clientId,
      client_secret: config.clientSecret
    });
    const res = await fetchImpl(tokenUrl, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: body.toString()
    });
    if (!res.ok) {
      throw new Error(`kiban: service token request failed with HTTP ${res.status}`);
    }
    const json = (await res.json()) as { access_token?: string; expires_in?: number };
    if (!json.access_token) {
      throw new Error("kiban: service token response carried no access_token");
    }
    token = json.access_token;
    expiresAt = Date.now() + (json.expires_in ?? 300) * 1000;
    return token;
  }

  return {
    async getAccessToken() {
      if (token && expiresAt - Date.now() > EXPIRY_WINDOW_MS) return token;
      if (!inflight) {
        inflight = fetchToken().finally(() => {
          inflight = null;
        });
      }
      return inflight;
    }
  };
}
