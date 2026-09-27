// SPDX-License-Identifier: Apache-2.0

import { createApiClient, type ApiClient } from "../client.js";
import type { EffectiveAccessDecision, EffectiveAccessRequest } from "../types.js";
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
