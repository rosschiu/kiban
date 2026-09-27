// SPDX-License-Identifier: Apache-2.0

// Sidebar unread-badge counts, one hook call per
// `localModuleRegistry` entry that declares `useUnreadCount` (modules/registry.ts). The registry
// is a module-level constant — its keys and which entries declare `useUnreadCount` never change
// across renders — so looping over `Object.entries` here calls the SAME hooks in the SAME order
// on every render of this component, satisfying the Rules of Hooks despite the loop shape. This
// is the one place in the shell that does this; see modules/registry.ts's `useUnreadCount` doc
// comment for the same reasoning from the registration side.
import { localModuleRegistry } from "../modules/registry";

export function useNavBadges(activeCompanyId: string | null): Readonly<Record<string, number>> {
  const badges: Record<string, number> = {};

  for (const [moduleKey, registered] of Object.entries(localModuleRegistry)) {
    // eslint-disable-next-line react-hooks/rules-of-hooks -- registry is a static, module-level
    // constant; see file doc comment above.
    const count = registered.useUnreadCount?.(activeCompanyId);
    if (typeof count === "number" && count > 0) {
      badges[moduleKey] = count;
    }
  }

  return badges;
}
