// SPDX-License-Identifier: Apache-2.0

// Runtime config, read from Vite env vars (VITE_* — inlined at build time).
// The shell always talks to the gateway origin only — never Keycloak or a module directly.
export interface ShellEnv {
  gatewayOrigin: string;
  realm: string;
  clientId: string;
  redirectUri: string;
}

export function readShellEnv(): ShellEnv {
  const env = import.meta.env;
  // Default: the page's own origin. Whichever way the bundle is served — by the gateway itself
  // (static.go) or by the Vite dev server (which proxies /auth + /api to the gateway,
  // vite.config.ts) — same-origin is the gateway, so a build-time hardcode would only ever be
  // wrong on any host other than the one it was built for (e.g. a baked-in dev default would send
  // the OIDC redirect to https://127.0.0.1:8443).
  const gatewayOrigin = env["VITE_KIBAN_GATEWAY_ORIGIN"]
    ?? (typeof window !== "undefined" ? window.location.origin : "https://127.0.0.1:8443");
  const realm = env["VITE_KIBAN_REALM"] ?? "kiban";
  const clientId = env["VITE_KIBAN_CLIENT_ID"] ?? "kiban-frontend";
  const redirectUri = env["VITE_KIBAN_REDIRECT_URI"]
    ?? (typeof window !== "undefined" ? `${window.location.origin}/callback` : "http://localhost:5173/callback");
  return { gatewayOrigin, realm, clientId, redirectUri };
}
