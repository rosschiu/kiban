// SPDX-License-Identifier: Apache-2.0

import { afterEach, describe, expect, it, vi } from "vitest";
import { readShellEnv } from "../../src/lib/env";

describe("readShellEnv", () => {
  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it("falls back to the page's own origin when no VITE_KIBAN_* vars are set", () => {
    // Same-origin is correct wherever the bundle is served: by the gateway itself (static.go)
    // or by the Vite dev server (which proxies /auth + /api to the gateway) — a build-time
    // hardcode broke login on the first host that wasn't the one it was built for.
    const env = readShellEnv();
    expect(env.gatewayOrigin).toBe(window.location.origin);
    expect(env.realm).toBe("kiban");
    expect(env.clientId).toBe("kiban-frontend");
    expect(env.redirectUri).toBe(`${window.location.origin}/callback`);
  });

  it("honors explicit overrides", () => {
    vi.stubEnv("VITE_KIBAN_GATEWAY_ORIGIN", "https://gateway.example");
    vi.stubEnv("VITE_KIBAN_REALM", "custom-realm");
    vi.stubEnv("VITE_KIBAN_CLIENT_ID", "custom-client");
    vi.stubEnv("VITE_KIBAN_REDIRECT_URI", "https://gateway.example/callback");

    const env = readShellEnv();
    expect(env).toEqual({
      gatewayOrigin: "https://gateway.example",
      realm: "custom-realm",
      clientId: "custom-client",
      redirectUri: "https://gateway.example/callback",
    });
  });
});
