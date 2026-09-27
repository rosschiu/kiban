// SPDX-License-Identifier: Apache-2.0

// TanStack Query key-factory conventions: namespaced factories per domain with an `all` root;
// company-scoped keys nest the company id. No `tanstack` dependency here — this module only
// produces the plain array-shaped keys; the host app wires them into `useQuery`/`useMutation`.
/** Namespaced TanStack Query key factories, one sub-object per client domain (`capabilities`,
 * `superadmin`, `effectiveAccess`, `org`) — each with an `all` root and `list`/`detail`-style
 * leaves so a mutation can invalidate a whole domain (`queryKeys.org.all`) or one entry. */
export const queryKeys = {
  capabilities: {
    all: ["capabilities"] as const,
    /** Key for `capabilitiesClient.list()`. */
    list: () => [...queryKeys.capabilities.all, "list"] as const,
    /** Key for `capabilitiesClient.get(moduleKey)`. */
    detail: (moduleKey: string) => [...queryKeys.capabilities.all, "detail", moduleKey] as const
  },

  superadmin: {
    all: ["superadmin"] as const,
    /** Key for `superadminClient.catalog()`. */
    catalog: () => [...queryKeys.superadmin.all, "catalog"] as const
  },

  effectiveAccess: {
    all: ["effectiveAccess"] as const,
    /** Key for `effectiveAccessClient.can(request)`. */
    can: (request: unknown) => [...queryKeys.effectiveAccess.all, "can", request] as const,
    /** Key for `effectiveAccessClient.batchCan(request)`. */
    batchCan: (request: unknown) => [...queryKeys.effectiveAccess.all, "batchCan", request] as const,
    /** Key for `effectiveAccessClient.summary(companyId?)`. */
    summary: (companyId?: string) => [...queryKeys.effectiveAccess.all, "summary", companyId ?? null] as const
  },

  org: {
    all: ["org"] as const,
    // meCompanies has no id/company parameter — it always answers for the caller (gateway-
    // injected kcSub), so its key is just the fixed leaf below.
    /** Key for `orgClient.meCompanies()`. */
    meCompanies: () => [...queryKeys.org.all, "meCompanies"] as const,
    units: {
      /** Key for the org-units list. */
      all: () => [...queryKeys.org.all, "units"] as const,
      /** Key for `orgClient.getUnit(id)`. */
      detail: (id: string) => [...queryKeys.org.all, "units", id] as const,
      /** Key for `orgClient.subtree(id)`. */
      subtree: (id: string) => [...queryKeys.org.all, "units", id, "subtree"] as const
    },
    members: {
      /** Key for the members list, scoped to one company. */
      all: (companyId: string) => [...queryKeys.org.all, "members", companyId] as const,
      /** Key for `orgClient.listMembers(companyId, page?, pageSize?)`. */
      list: (companyId: string, page?: number, pageSize?: number) =>
        [...queryKeys.org.all, "members", companyId, "list", page ?? null, pageSize ?? null] as const,
      /** Key for `orgClient.getMember(id)`. */
      detail: (id: string) => [...queryKeys.org.all, "members", "detail", id] as const
    },
    positions: {
      /** Key for the positions list, scoped to one company. */
      all: (companyId: string) => [...queryKeys.org.all, "positions", companyId] as const,
      /** Key for `orgClient.listPositions(companyId, page?, pageSize?)`. */
      list: (companyId: string, page?: number, pageSize?: number) =>
        [...queryKeys.org.all, "positions", companyId, "list", page ?? null, pageSize ?? null] as const,
      /** Key for `orgClient.getPosition(id)`. */
      detail: (id: string) => [...queryKeys.org.all, "positions", "detail", id] as const,
      /** Key for `orgClient.holderOnDate(id, date)`. */
      holder: (id: string, date: string) => [...queryKeys.org.all, "positions", "detail", id, "holder", date] as const
    }
  }
};
