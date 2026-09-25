// SPDX-License-Identifier: Apache-2.0

// App-side session state: activeCompanyId + preferences. Client-persisted only (localStorage
// adapter, injectable) — this is a UX convenience layer on top of auth/session.ts, not an
// authorization source (never trusted server-side). Server-persisted user preferences are a
// possible future identity-service endpoint; this module is the
// client-only placeholder that endpoint will eventually back.
import { defaultLocalStorage, type StorageAdapter } from "../storage.js";

/** Construction options for {@link createSessionContext}. */
export interface SessionContextConfig {
  /** Injectable storage; defaults to `localStorage` (or an in-memory fallback when
   * unavailable). */
  storage?: StorageAdapter;
  /** Prefix for the two keys this module owns. Defaults to `"kiban."`. */
  storageKeyPrefix?: string;
}

/** Free-form, JSON-serializable client-side user preferences (theme, list density, ...). */
export type Preferences = Record<string, unknown>;

/** Client-persisted UX state: the active company switcher selection + preferences. NOT an
 * authorization source — never trusted server-side, see this file's own header comment. */
export interface SessionContext {
  /** Current active-company selection, or null if none set. */
  getActiveCompanyId(): string | null;
  /** Sets (or clears, with null) the active-company selection. */
  setActiveCompanyId(companyId: string | null): void;
  /** All stored preferences. */
  getPreferences(): Preferences;
  /** One stored preference by key. */
  getPreference<T = unknown>(key: string): T | undefined;
  /** Sets one preference by key. */
  setPreference(key: string, value: unknown): void;
  /** Clears both activeCompanyId and preferences (call on logout). */
  clear(): void;
  /** Subscribe to any change made through this instance. Returns an unsubscribe function. */
  subscribe(listener: () => void): () => void;
}

/** Builds a {@link SessionContext} backed by `config.storage` (defaults to localStorage, or an
 * in-memory fallback when unavailable). */
export function createSessionContext(config: SessionContextConfig = {}): SessionContext {
  const storage = config.storage ?? defaultLocalStorage();
  const prefix = config.storageKeyPrefix ?? "kiban.";
  const activeCompanyKey = `${prefix}activeCompanyId`;
  const preferencesKey = `${prefix}preferences`;
  const listeners = new Set<() => void>();

  function notify(): void {
    for (const listener of listeners) listener();
  }

  function getActiveCompanyId(): string | null {
    return storage.getItem(activeCompanyKey);
  }

  function setActiveCompanyId(companyId: string | null): void {
    if (companyId === null) {
      storage.removeItem(activeCompanyKey);
    } else {
      storage.setItem(activeCompanyKey, companyId);
    }
    notify();
  }

  function getPreferences(): Preferences {
    const raw = storage.getItem(preferencesKey);
    if (!raw) return {};
    try {
      return JSON.parse(raw) as Preferences;
    } catch {
      return {};
    }
  }

  function getPreference<T = unknown>(key: string): T | undefined {
    return getPreferences()[key] as T | undefined;
  }

  function setPreference(key: string, value: unknown): void {
    const preferences = getPreferences();
    preferences[key] = value;
    storage.setItem(preferencesKey, JSON.stringify(preferences));
    notify();
  }

  function clear(): void {
    storage.removeItem(activeCompanyKey);
    storage.removeItem(preferencesKey);
    notify();
  }

  function subscribe(listener: () => void): () => void {
    listeners.add(listener);
    return () => listeners.delete(listener);
  }

  return {
    getActiveCompanyId,
    setActiveCompanyId,
    getPreferences,
    getPreference,
    setPreference,
    clear,
    subscribe
  };
}
