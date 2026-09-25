// SPDX-License-Identifier: Apache-2.0

// Minimal injectable key-value storage contract shared by auth/session.ts (transaction +
// optional token persistence — sessionStorage, NEVER localStorage) and auth/context.ts
// (activeCompanyId + preferences — localStorage, client-persisted). Kept storage-engine-agnostic
// so tests can inject an in-memory fake and non-browser hosts can inject anything else.
/** Minimal key-value storage contract — same shape as `Storage` (localStorage/sessionStorage)
 * but engine-agnostic, so tests can inject {@link createMemoryStorage} and non-browser hosts can
 * inject anything else. */
export interface StorageAdapter {
  /** Reads `key`, or null if unset. */
  getItem(key: string): string | null;
  /** Writes `key`. */
  setItem(key: string, value: string): void;
  /** Deletes `key`, if present. */
  removeItem(key: string): void;
}

/** In-memory adapter: default fallback when no browser storage is available (SSR, tests). */
export function createMemoryStorage(): StorageAdapter {
  const map = new Map<string, string>();
  return {
    getItem: (key) => map.get(key) ?? null,
    setItem: (key, value) => {
      map.set(key, value);
    },
    removeItem: (key) => {
      map.delete(key);
    }
  };
}

function browserStorage(kind: "sessionStorage" | "localStorage"): StorageAdapter | undefined {
  const g = globalThis as { [k: string]: unknown };
  const candidate = g[kind] as Storage | undefined;
  if (!candidate) return undefined;
  return {
    getItem: (key) => candidate.getItem(key),
    setItem: (key, value) => candidate.setItem(key, value),
    removeItem: (key) => candidate.removeItem(key)
  };
}

/** Real `window.sessionStorage` when present, else an in-memory fallback. */
export function defaultSessionStorage(): StorageAdapter {
  return browserStorage("sessionStorage") ?? createMemoryStorage();
}

/** Real `window.localStorage` when present, else an in-memory fallback. */
export function defaultLocalStorage(): StorageAdapter {
  return browserStorage("localStorage") ?? createMemoryStorage();
}
