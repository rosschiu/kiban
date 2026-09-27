// SPDX-License-Identifier: Apache-2.0

// Reads GET /api/platform/demo-mode once per mount via the SDK (SDK only, never direct fetch —
// DemoModeClient wraps ApiClient exactly like every other typed
// SDK client this shell already uses). Fails closed to `false` on any error (network hiccup,
// non-demo deployment that doesn't mount the route yet, ...) — never shows the banner on doubt.
import { useEffect, useState } from "react";
import { createDemoModeClient } from "@rosschiu/kiban-sdk";
import { getShellSdk } from "../auth/sdk";

export function useDemoMode(): boolean {
  const [enabled, setEnabled] = useState(false);

  useEffect(() => {
    let cancelled = false;
    const { apiClient } = getShellSdk();
    createDemoModeClient(apiClient)
      .get()
      .then((status) => {
        if (!cancelled) setEnabled(status.enabled);
      })
      .catch(() => {
        // fail closed — no banner on error, never surfaced to the user
      });
    return () => {
      cancelled = true;
    };
  }, []);

  return enabled;
}
