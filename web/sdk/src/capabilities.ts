// SPDX-License-Identifier: Apache-2.0

// Typed client over GET /api/platform/capabilities[/{module}] (internal/registry/http.go).
import type { ApiClient } from "./client.js";
import type { Capability } from "./types.js";

/** Typed client over `GET /api/platform/capabilities[/{module}]`. */
export interface CapabilitiesClient {
  /** All modules' capability rows (registry catalog + dependency resolution). */
  list(): Promise<Capability[]>;
  /** A single module's capability row. 404 (KibanApiError, code NOT_FOUND) if unknown. */
  get(moduleKey: string): Promise<Capability>;
}

/** Builds a {@link CapabilitiesClient} over `client`. */
export function createCapabilitiesClient(client: ApiClient): CapabilitiesClient {
  return {
    list: () => client.request<Capability[]>("/api/platform/capabilities"),
    get: (moduleKey: string) =>
      client.request<Capability>(`/api/platform/capabilities/${encodeURIComponent(moduleKey)}`)
  };
}
