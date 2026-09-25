// SPDX-License-Identifier: Apache-2.0

// Typed client over GET /api/platform/demo-mode (internal/gateway/platform_routes.go,
// mountDemoModeRoute) — the deployment-flag read backing the shell's demo banner.
// Unauthenticated on the server side (see that route's own doc comment); this client works
// identically whether or not the caller is signed in.
import type { ApiClient } from "./client.js";

/** The `GET /api/platform/demo-mode` response body. */
export interface DemoModeStatus {
  /** True only on the deployment the operator explicitly flagged as the public demo. */
  enabled: boolean;
}

/** Typed client over `GET /api/platform/demo-mode`. */
export interface DemoModeClient {
  /** Whether this deployment is the public demo (banner-on) or not (default: off). */
  get(): Promise<DemoModeStatus>;
}

/** Builds a {@link DemoModeClient} over `client`. */
export function createDemoModeClient(client: ApiClient): DemoModeClient {
  return {
    get: () => client.request<DemoModeStatus>("/api/platform/demo-mode")
  };
}
