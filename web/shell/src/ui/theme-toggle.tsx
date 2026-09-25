// SPDX-License-Identifier: Apache-2.0

import { defaultLocalStorage, type StorageAdapter } from "@rosschiu/kiban-sdk";
import { Moon, Sun } from "lucide-react";
import { useEffect, useState } from "react";
import { Button } from "./button";

const STORAGE_KEY = "kiban.theme";

type Theme = "light" | "dark";

function applyTheme(theme: Theme): void {
  document.documentElement.classList.toggle("dark", theme === "dark");
}

function readInitialTheme(storage: StorageAdapter): Theme {
  const stored = storage.getItem(STORAGE_KEY);
  if (stored === "light" || stored === "dark") return stored;
  return typeof window !== "undefined" && window.matchMedia?.("(prefers-color-scheme: dark)").matches ? "dark" : "light";
}

export interface ThemeToggleProps {
  /** Reuses the SDK's browser-storage-with-memory-fallback adapter (auth/context.ts's same
   * pattern) by default rather than touching `window.localStorage` directly — robust in any host
   * where localStorage is unavailable/throws (SSR, sandboxed test environments). Injectable so
   * tests can seed/observe persistence without depending on a real browser storage engine. */
  storage?: StorageAdapter;
}

/** Dark-mode toggle for the class-strategy dark tokens. */
export function ThemeToggle({ storage = defaultLocalStorage() }: ThemeToggleProps = {}) {
  const [theme, setTheme] = useState<Theme>(() => readInitialTheme(storage));

  useEffect(() => {
    applyTheme(theme);
    storage.setItem(STORAGE_KEY, theme);
  }, [theme, storage]);

  return (
    <Button
      type="button"
      variant="ghost"
      size="icon"
      aria-label={theme === "dark" ? "Switch to light mode" : "Switch to dark mode"}
      onClick={() => setTheme((current) => (current === "dark" ? "light" : "dark"))}
    >
      {theme === "dark" ? <Sun className="size-4" aria-hidden="true" /> : <Moon className="size-4" aria-hidden="true" />}
    </Button>
  );
}
