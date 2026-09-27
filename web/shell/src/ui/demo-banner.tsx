// SPDX-License-Identifier: Apache-2.0

// "Public demo — resets nightly; don't store real data." Slim, dismissible-per-
// session banner, shown only when the deploy-time demo-mode flag is on (useDemoMode ->
// GET /api/platform/demo-mode). Lives inside AppShell's SidebarInset — below SiteHeader, above
// the page's <main> — so it spans only the content column and never overlaps the fixed sidebar
// or the header row above it.
import { X } from "lucide-react";
import { useEffect, useState } from "react";
import { useDemoMode } from "../hooks/use-demo-mode";
import { Button } from "./button";

const DISMISS_KEY = "kiban:demo-banner-dismissed";

export function DemoBanner() {
  const enabled = useDemoMode();
  const [dismissed, setDismissed] = useState(() => {
    if (typeof window === "undefined") return false;
    try {
      return window.sessionStorage.getItem(DISMISS_KEY) === "true";
    } catch {
      return false;
    }
  });

  // Re-check in case another tab/component wrote the key after this one mounted (defensive —
  // sessionStorage is per-tab already, so this mainly guards a second DemoBanner instance in
  // the same tab, which never happens today but costs nothing to keep safe).
  useEffect(() => {
    if (dismissed) return;
    try {
      if (window.sessionStorage.getItem(DISMISS_KEY) === "true") setDismissed(true);
    } catch {
      // sessionStorage unavailable (privacy mode, etc.) — banner just stays visible for the tab
    }
  }, [dismissed]);

  if (!enabled || dismissed) return null;

  function dismiss() {
    setDismissed(true);
    try {
      window.sessionStorage.setItem(DISMISS_KEY, "true");
    } catch {
      // best effort only — the banner still hides for this render even if persistence fails
    }
  }

  return (
    <div
      data-slot="demo-banner"
      role="status"
      className="flex items-center justify-between gap-3 border-b border-amber-200 bg-amber-50 px-4 py-1.5 text-xs text-amber-800 dark:border-amber-900/50 dark:bg-amber-950/40 dark:text-amber-200"
    >
      <span>Public demo — resets nightly; don&apos;t store real data.</span>
      <Button
        type="button"
        variant="ghost"
        size="sm"
        className="h-6 shrink-0 gap-1 px-2 text-xs text-amber-800 hover:bg-amber-100 hover:text-amber-900 dark:text-amber-200 dark:hover:bg-amber-900/40"
        onClick={dismiss}
        aria-label="Dismiss demo banner"
      >
        <X className="size-3.5" aria-hidden="true" />
      </Button>
    </div>
  );
}
