// SPDX-License-Identifier: Apache-2.0

import { createApiClient, type ApiClient } from "../client.js";
import type {
  EffectiveAccessBatchItem,
  EffectiveAccessBatchResult,
  EffectiveAccessDecision,
  EffectiveAccessRequest,
  MemberDirectoryEntry,
  OrgAssignment,
  OrgGroupMember,
  OrgMeCompany,
  Page
} from "../types.js";
import type { ServiceCredentials } from "./credentials.js";

/** One relation tuple: `objectType:objectId#relation@subjectType:subjectId`. */
export interface Tuple {
  /** An object type the app's fragment declares (or `company_module` for the app's company anchor). */
  objectType: string;
  /** The object id. */
  objectId: string;
  /** The relation. */
  relation: string;
  /** `user` for a login subject, `company_module` for the anchor, or a userset's type. */
  subjectType: string;
  /** The subject id. */
  subjectId: string;
  /** For a userset subject, the relation on the subject type. */
  subjectRelation?: string;
}

/** Org's answer to "is this subject an active member of this company". */
export interface MemberFact {
  /** Whether a member of the company is linked to the subject. */
  isMember: boolean;
  /** Whether that membership is active. */
  isActive: boolean;
  /** The member id, or null when not a member. */
  memberId: string | null;
}

/** What an app registers: its key, service client, feature keys and object types. */
export interface AppManifest {
  /** The app key (`^[a-z][a-z0-9_]{1,31}$`); its object types and features are namespaced by it. */
  key: string;
  /** Display name. */
  displayName: string;
  /** The app's version, for the catalog. */
  version: string;
  /** The service client whose token identifies the app's backend. */
  serviceClientId: string;
  /** Feature keys (`<key>.<name>`) the app asks about; any other key is refused. */
  features?: string[];
  /** The authorization fragment's relations section: one entry per object type. */
  authzFragment: Record<string, unknown>;
}

/** Configuration for {@link createAppClient}. */
export interface AppClientConfig {
  /** Gateway origin. */
  gatewayOrigin: string;
  /** The app key the manifest registered. */
  appKey: string;
  /** The app's service token source. */
  credentials: ServiceCredentials;
  /** Override for `fetch` (tests). */
  fetchFn?: typeof fetch;
}

/** The app's backend view of Kiban: decisions, tuples, members, registration. */
export interface AppClient {
  /** Asks Kiban whether the user behind `userBearer` may use a feature (Kiban answers for that
   * bearer only). Pass the bearer the user presented to the app, unchanged. */
  can(userBearer: string, request: EffectiveAccessRequest): Promise<EffectiveAccessDecision>;
  /** Asks for the app's own service account (a background job). */
  canService(request: EffectiveAccessRequest): Promise<EffectiveAccessDecision>;
  /** Writes tuples on the app's own object types in a company. Every object must carry its
   * anchor ({@link AppClient.anchorTuple}) in the same or an earlier call. */
  grant(companyId: string, tuples: Tuple[]): Promise<void>;
  /** Removes tuples the app wrote. */
  revoke(companyId: string, tuples: Tuple[]): Promise<void>;
  /** The `company_module` anchor tuple binding an object of the app to a company. */
  anchorTuple(objectType: string, objectId: string, companyId: string): Tuple;
  /** Asks org whether a subject is an active member of a company. */
  memberBySubject(companyId: string, subject: string): Promise<MemberFact>;
  /** Up to 100 object-relation questions for the user in one call: one round trip for a page
   * of controls. `request` carries the feature, module and company; `items` the objects. */
  batchCan(userBearer: string, request: EffectiveAccessRequest, items: EffectiveAccessBatchItem[]): Promise<EffectiveAccessBatchResult[]>;
  /** `batchCan` for the app's own service account. */
  batchCanService(request: EffectiveAccessRequest, items: EffectiveAccessBatchItem[]): Promise<EffectiveAccessBatchResult[]>;
  /** The companies the user behind `userBearer` may see: active memberships in active companies. */
  meCompanies(userBearer: string): Promise<OrgMeCompany[]>;
  /** One page of the company's active members, as the app's service account (which must be a
   * member of the company); `q` filters on a substring of display name or email. */
  memberDirectory(companyId: string, q?: string, page?: number, pageSize?: number): Promise<Page<MemberDirectoryEntry>>;
  /** Who holds the position on `date` (`YYYY-MM-DD`, default today); a 404 means nobody. */
  positionHolder(companyId: string, positionId: string, date?: string): Promise<OrgAssignment>;
  /** The group's current members, as the app's service account. */
  groupMembers(companyId: string, groupId: string): Promise<OrgGroupMember[]>;
  /** Registers (or re-registers) the app with a superadmin's bearer. */
  registerApp(superadminBearer: string, manifest: AppManifest): Promise<void>;
  /** The underlying client, authenticated as the service account, for any other route. */
  readonly api: ApiClient;
}

/** Creates the app's backend client. */
export function createAppClient(config: AppClientConfig): AppClient {
  const baseUrl = config.gatewayOrigin.replace(/\/+$/, "");
  const api = createApiClient({
    baseUrl,
    fetchFn: config.fetchFn,
    getAccessToken: () => null,
    refreshAccessToken: undefined
  });
  const serviceApi = createApiClient({ baseUrl, fetchFn: config.fetchFn });
  const asService = async (): Promise<Record<string, string>> => ({
    Authorization: `Bearer ${await config.credentials.getAccessToken()}`
  });
  const grants = async (op: "grant" | "revoke", companyId: string, tuples: Tuple[]): Promise<void> => {
    await api.request("/api/auth/grants", {
      method: "POST",
      headers: await asService(),
      body: { op, companyId, tuples }
    });
  };

  return {
    api: serviceApi,
    can: (userBearer, request) =>
      api.request<EffectiveAccessDecision>("/api/auth/effective-access/can", {
        method: "POST",
        headers: { Authorization: `Bearer ${userBearer}` },
        body: request
      }),
    canService: async (request) =>
      api.request<EffectiveAccessDecision>("/api/auth/effective-access/can", {
        method: "POST",
        headers: await asService(),
        body: request
      }),
    grant: (companyId, tuples) => grants("grant", companyId, tuples),
    revoke: (companyId, tuples) => grants("revoke", companyId, tuples),
    anchorTuple: (objectType, objectId, companyId) => ({
      objectType,
      objectId,
      relation: "company_module",
      subjectType: "company_module",
      subjectId: `${companyId}/${config.appKey}`
    }),
    batchCan: (userBearer, request, items) =>
      api.request<EffectiveAccessBatchResult[]>("/api/auth/effective-access/batch-can", {
        method: "POST",
        headers: { Authorization: `Bearer ${userBearer}` },
        body: { ...request, items }
      }),
    batchCanService: async (request, items) =>
      api.request<EffectiveAccessBatchResult[]>("/api/auth/effective-access/batch-can", {
        method: "POST",
        headers: await asService(),
        body: { ...request, items }
      }),
    meCompanies: (userBearer) =>
      api.request<OrgMeCompany[]>("/api/org/me/companies", { headers: { Authorization: `Bearer ${userBearer}` } }),
    memberDirectory: async (companyId, q, page, pageSize) => {
      const params = new URLSearchParams();
      if (q) params.set("q", q);
      if (page) params.set("page", String(page));
      if (pageSize) params.set("pageSize", String(pageSize));
      const qs = params.toString();
      return api.request<Page<MemberDirectoryEntry>>(
        `/api/org/companies/${encodeURIComponent(companyId)}/members${qs ? `?${qs}` : ""}`,
        { headers: await asService() }
      );
    },
    positionHolder: async (companyId, positionId, date) =>
      api.request<OrgAssignment>(
        `/api/org/companies/${encodeURIComponent(companyId)}/positions/${encodeURIComponent(positionId)}/holder?date=${date ?? new Date().toISOString().slice(0, 10)}`,
        { headers: await asService() }
      ),
    groupMembers: async (companyId, groupId) =>
      api.request<OrgGroupMember[]>(
        `/api/org/companies/${encodeURIComponent(companyId)}/groups/${encodeURIComponent(groupId)}/members`,
        { headers: await asService() }
      ),
    memberBySubject: async (companyId, subject) =>
      api.request<MemberFact>(
        `/api/org/companies/${encodeURIComponent(companyId)}/members/by-subject/${encodeURIComponent(subject)}`,
        { headers: await asService() }
      ),
    registerApp: async (superadminBearer, manifest) => {
      await api.request("/api/platform/admin/apps", {
        method: "POST",
        headers: { Authorization: `Bearer ${superadminBearer}` },
        body: manifest
      });
    }
  };
}
