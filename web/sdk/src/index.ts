// SPDX-License-Identifier: Apache-2.0

export { createApiClient, KibanApiError } from "./client.js";
export type { ApiClient, ApiClientConfig, RequestOptions } from "./client.js";

export { createCapabilitiesClient } from "./capabilities.js";
export type { CapabilitiesClient } from "./capabilities.js";

export { createDemoModeClient } from "./demoMode.js";
export type { DemoModeClient, DemoModeStatus } from "./demoMode.js";

export { createEffectiveAccessClient } from "./effectiveAccess.js";
export type { EffectiveAccessClient } from "./effectiveAccess.js";

export { createOrgClient } from "./org.js";
export type { OrgClient } from "./org.js";

// `/internal/org/...` client — not gateway-exposed; excluded from the typedoc reference.
export { createInternalOrgClient } from "./orgInternal.js";
export type {
  CreateOrgMemberInput,
  CreateOrgPositionInput,
  CreateOrgUnitInput,
  InternalOrgClient
} from "./orgInternal.js";

export { createSuperadminClient } from "./superadmin.js";
export type { PlatformRole, PlatformRoleGrant, SuperadminClient } from "./superadmin.js";

export { queryKeys } from "./queryKeys.js";

export { createCanI } from "./recipes/canI.js";
export type { CanIParams, CanIResult } from "./recipes/canI.js";

export { createGrantObjectAccess } from "./recipes/grantObjectAccess.js";
export type { GrantObjectAccessParams, GrantObjectAccessResult } from "./recipes/grantObjectAccess.js";

export type {
  ApiDataEnvelope,
  ApiErrorBody,
  ApiErrorEnvelope,
  AuthzTuple,
  Capability,
  CatalogEntry,
  Cursor,
  EffectiveAccessBatchItem,
  EffectiveAccessBatchResult,
  EffectiveAccessDecision,
  EffectiveAccessEvidence,
  EffectiveAccessObjectAccessEntry,
  EffectiveAccessObjectRef,
  EffectiveAccessRequest,
  EffectiveAccessRoleBinding,
  EffectiveAccessScope,
  EffectiveAccessReasonValue,
  EffectiveAccessSummary,
  MemberDirectoryEntry,
  OrgAssignment,
  OrgCompanyState,
  OrgGroup,
  OrgGroupMember,
  OrgGroupWithMemberCount,
  OrgMeCompany,
  OrgMember,
  OrgMembershipState,
  OrgMemberUser,
  OrgPosition,
  OrgPositionWithHolder,
  OrgUnit,
  Page
} from "./types.js";
export { ApiErrorCode, EffectiveAccessReason } from "./types.js";
export type { ApiErrorCodeValue } from "./types.js";

export type { StorageAdapter } from "./storage.js";
export { createMemoryStorage, defaultLocalStorage, defaultSessionStorage } from "./storage.js";

export { createSession, decodeIdTokenClaims } from "./auth/session.js";
export type { Session, SessionConfig, TokenSet } from "./auth/session.js";

export { createSessionContext } from "./auth/context.js";
export type { Preferences, SessionContext, SessionContextConfig } from "./auth/context.js";

export { generateCodeChallenge, generateCodeVerifier, generateRandomToken } from "./auth/pkce.js";
