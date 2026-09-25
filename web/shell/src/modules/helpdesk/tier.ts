// SPDX-License-Identifier: Apache-2.0

// The tier-visible-contrast hook: fetches the caller's OWN company-wide helpdesk tier
// (member/agent/admin) once per company, so the module's internal sub-nav and per-page actions
// can differ VISIBLY between a plain member, an agent, and an admin (a reporter never sees the
// All-tickets nav). The shell's
// route-level resolver can only gate on the generic "<moduleKey>.access" synthesized key
// (no install path exists yet to load a module's fragment-
// declared feature keys as grantable-from-the-frontend), so fine-grained tier is computed HERE,
// inside the module's own tree, from a dedicated GET .../me read.
import { useEffect, useState } from "react";
import { getShellSdk } from "../../auth/sdk";
import { createHelpdeskClient, type HelpdeskTier } from "./api";

export function useHelpdeskTier(companyId: string | null | undefined): HelpdeskTier | null {
  const [tier, setTier] = useState<HelpdeskTier | null>(null);

  useEffect(() => {
    if (!companyId) {
      setTier(null);
      return;
    }
    let cancelled = false;
    const client = createHelpdeskClient(getShellSdk().apiClient);
    client
      .myTier(companyId)
      .then((t) => {
        if (!cancelled) setTier(t);
      })
      .catch(() => {
        if (!cancelled) setTier(null);
      });
    return () => {
      cancelled = true;
    };
  }, [companyId]);

  return tier;
}
