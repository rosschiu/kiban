// SPDX-License-Identifier: Apache-2.0

// Wire shapes shared across the SDK. Hand-typed for v1 (generated-from-OpenAPI types are not
// used yet). Field names/shapes below are taken directly from the Go source of truth
// (internal/errenv, internal/registry) rather than guessed.

/** `{"error":{"code","message","details"?}}` — internal/errenv.APIError. */
export interface ApiErrorBody {
  code: string;
  message: string;
  details?: unknown;
}

/** Top-level error envelope wire shape. */
export interface ApiErrorEnvelope {
  error: ApiErrorBody;
}

/** Top-level success envelope wire shape: `{"data": T}`. */
export interface ApiDataEnvelope<T> {
  data: T;
}

/** Offset-pagination wire shape (page/pageSize, default 1/25, clamp 1..100). */
export interface Page<T> {
  items: T[];
  total: number;
  page: number;
  pageSize: number;
  totalPages: number;
}

/** Cursor-pagination wire shape (activity/audit feeds). */
export interface Cursor<T> {
  items: T[];
  nextCursor: string | null;
}

/** Canonical error codes (internal/errenv). Exact strings are contract. */
export const ApiErrorCode = {
  BadRequest: "BAD_REQUEST",
  AuthTokenMissing: "AUTH_TOKEN_MISSING",
  AuthTokenInvalid: "AUTH_TOKEN_INVALID",
  Forbidden: "FORBIDDEN",
  AuthorizationDenied: "AUTHORIZATION_DENIED",
  ModuleNotInstalled: "MODULE_NOT_INSTALLED",
  ModuleDisabled: "MODULE_DISABLED",
  ModuleDependencyMissing: "MODULE_DEPENDENCY_MISSING",
  ModuleUnavailable: "MODULE_UNAVAILABLE",
  PayloadTooLarge: "PAYLOAD_TOO_LARGE",
  NotFound: "NOT_FOUND",
  Conflict: "CONFLICT",
  ValidationError: "VALIDATION_ERROR",
  InternalError: "INTERNAL_ERROR",
  AuthorizationUnavailable: "AUTHORIZATION_UNAVAILABLE",
  // Kept in sync with internal/errenv by the contracts/wire-enums.json cross-language drift check.
  ValidationFailed: "VALIDATION_FAILED",
  IdempotencyConflict: "IDEMPOTENCY_CONFLICT",
  GroupExternallyManaged: "GROUP_EXTERNALLY_MANAGED"
} as const;

/** One of {@link ApiErrorCode}'s canonical string values. */
export type ApiErrorCodeValue = (typeof ApiErrorCode)[keyof typeof ApiErrorCode];

/** registry.Capability (internal/registry/store.go) — GET /api/platform/capabilities[/{module}]. */
export interface Capability {
  module: string;
  installed: boolean;
  enabled: boolean;
  dependencies: string[];
  missingDependencies: string[];
}

/** registry catalog entry (internal/registry/store.go) — GET /api/platform/catalog. */
export interface CatalogEntry {
  moduleKey: string;
  displayName: string;
  scopeType: string;
  mandatory: boolean;
  basePath: string;
  healthPath: string;
  port: number;
  licenseClass: string;
  manifestVersion: string;
  isActive: boolean;
  installed: boolean;
  enabled: boolean;
}

// ---- effective-access (internal/authz/http.go: canRequestWire/decisionWire) ----------------
//
// GATEWAY-EXPOSED (`POST /api/auth/effective-access/can`/`batch-can`,
// `GET /api/auth/effective-access/summary` — internal/gateway/foundation_routes.go), self-scoped
// only: the gateway bearer-validates every call, and `can`/`batch-can` forward to authz's own
// endpoint (internal/authz/http.go), which itself rejects any body naming a subject other than
// the bearer. These types are hand-typed from the real Go wire shapes (source of truth:
// internal/authz/http.go, internal/authz/summary.go).

/** decision.Scope (internal/authz/decision/decision.go). */
export type EffectiveAccessScope = "global" | "company";

/** `{type, id}` reference to an authz object, e.g. `{type:"notification_channel", id:"..."}`. */
export interface EffectiveAccessObjectRef {
  type: string;
  id: string;
}

/** canRequestWire (internal/authz/http.go). No actor field — the actor is always the caller's
 * bearer subject; the SDK never accepts or sends an actor override. */
export interface EffectiveAccessRequest {
  featureKey: string;
  moduleKey?: string;
  scope: EffectiveAccessScope;
  companyId?: string;
  requiredPlatformRole?: string;
  allowPlatformOperatorCompanyScope?: boolean;
  requiredCompanyRole?: string;
  object?: EffectiveAccessObjectRef;
  relation?: string;
  requiresEligibility?: boolean;
  correlationId?: string;
}

/** One (object, relation) pair inside a `batchCan` request. */
export interface EffectiveAccessBatchItem {
  object: EffectiveAccessObjectRef;
  relation: string;
}

/** decision.Evidence (internal/authz/decision/decision.go). */
export interface EffectiveAccessEvidence {
  key: string;
  value: string;
}

/** Canonical decision.Reason values (internal/authz/decision/decision.go). Exact strings are
 * contract. */
export const EffectiveAccessReason = {
  Allowed: "ALLOWED",
  AuthUserNotFound: "AUTH_USER_NOT_FOUND",
  KeycloakDisabled: "KEYCLOAK_DISABLED",
  UserLifecycleDisabled: "USER_LIFECYCLE_DISABLED",
  CompanyInactive: "COMPANY_INACTIVE",
  CompanyMembershipRequired: "COMPANY_MEMBERSHIP_REQUIRED",
  CompanyAccessBlocked: "COMPANY_ACCESS_BLOCKED",
  ModuleDisabled: "MODULE_DISABLED",
  PlatformRoleRequired: "PLATFORM_ROLE_REQUIRED",
  CompanyRoleRequired: "COMPANY_ROLE_REQUIRED",
  EngineDenied: "ENGINE_DENIED",
  BusinessEligibilityDenied: "BUSINESS_ELIGIBILITY_DENIED",
  DependencyUnavailable: "DEPENDENCY_UNAVAILABLE"
} as const;

/** One of {@link EffectiveAccessReason}'s canonical string values. */
export type EffectiveAccessReasonValue = (typeof EffectiveAccessReason)[keyof typeof EffectiveAccessReason];

/** decisionWire (internal/authz/http.go). */
export interface EffectiveAccessDecision {
  allowed: boolean;
  reason: EffectiveAccessReasonValue | string;
  evidence: EffectiveAccessEvidence[];
}

/** One decision inside a `batchCan` response, echoing the request item it answers. */
export interface EffectiveAccessBatchResult {
  object: EffectiveAccessObjectRef;
  relation: string;
  decision: EffectiveAccessDecision;
}

/** One roleBindings entry (internal/authz/summary.go's summaryRoleBindings): either the global
 * platform role, or (when a companyId was requested) a company-scoped relation the caller holds
 * directly. companyId is only present on the "company"-scoped shape. */
export interface EffectiveAccessRoleBinding {
  scope: "global" | "company";
  role: string;
  companyId?: string;
}

/** One objectAccess entry (internal/authz/summary.go's summaryObjectAccess) — direct tuples
 * naming the caller, grouped by object. A display composition, not an enforcement surface (the
 * real gate stays `can`/`batchCan`). */
export interface EffectiveAccessObjectAccessEntry {
  objectType: string;
  objectId: string;
  relations: string[];
}

/** GET /api/auth/effective-access/summary's response shape (internal/authz/summary.go's
 * handleSummary — the EffectiveAccessSummary contract, apiVersion 1). `moduleKey` is always ""
 * (the summary composes across ALL modules at once); `rowScopes`/`fieldPolicies` are always
 * empty arrays in this v1 (segment-rule compilation and field-policy evaluation are not built
 * yet). */
export interface EffectiveAccessSummary {
  apiVersion: number;
  subjectId: string;
  companyId: string;
  moduleKey: string;
  featureKeys: string[];
  roleBindings: EffectiveAccessRoleBinding[];
  objectAccess: EffectiveAccessObjectAccessEntry[];
  rowScopes: unknown[];
  fieldPolicies: unknown[];
}

// ---- authz grants (internal/authz/http.go: tupleWire/grantsRequestWire) --------------------
// GATEWAY-EXPOSED (`POST /api/auth/grants` — internal/gateway/
// foundation_routes.go), behind the superadmin guard (RequireSuperadmin): only a caller
// holding `auth.platform_administration.access` may call this route. The request carries the
// company (`companyId`) the tuples are bound to; authz's handleGrants refuses a missing one.

/** store.Tuple (internal/authz/store) as the grants endpoint's wire shape. */
export interface AuthzTuple {
  objectType: string;
  objectId: string;
  relation: string;
  subjectType: string;
  subjectId: string;
  subjectRelation?: string;
}

// ---- org (internal/org/http.go: unitView/memberView/positionView/assignmentView) -----------
// NOT gateway-exposed: org's CRUD surface is entirely `/internal/org/...`; there is no `/api/...`
// mount for these types' own routes in internal/gateway (unlike registry, which gets its own
// fixed `/api/platform/*` mount) — see this package's README "Known gaps" section. Exceptions:
// `GET /api/org/me/companies` (OrgMeCompany), the member directory, and the admin
// position/group routes below.

/** An org-taxonomy unit (company, department, ...) — internal/org's `org_unit` row. */
export interface OrgUnit {
  id: string;
  typeKey: string;
  parentId: string | null;
  code: string;
  name: string;
  isActive: boolean;
}

/** The Keycloak-linked identity behind an {@link OrgMember}, when linked. */
export interface OrgMemberUser {
  kcSub: string;
  email: string;
  preferredUsername: string;
  lifecycle: string;
}

/** A company's member row — the org-triangle's person-in-a-company fact, independent of
 * whether a Keycloak user is linked yet. */
export interface OrgMember {
  id: string;
  companyId: string;
  code: string;
  displayName: string;
  email: string;
  userId: string | null;
  isActive: boolean;
  user?: OrgMemberUser;
}

/** The reduced, least-disclosure member-picker view (`GET /api/org/companies/{companyId}
 * /members` — gateway-exposed, unlike OrgMember's own internal-only endpoints above): no kcSub,
 * no code, no lifecycle. The share-with/assign-to picker source for modules like docs/helpdesk. */
export interface MemberDirectoryEntry {
  id: string;
  displayName: string;
  email: string;
  hasLinkedUser: boolean;
}

/** A named seat in a company's org structure (the position mechanism behind position-based access). */
export interface OrgPosition {
  id: string;
  companyId: string;
  code: string;
  title: string;
  orgUnitId: string;
}

/** A member's tenure in a position, validity-windowed (`validTo: null` = current holder). */
export interface OrgAssignment {
  id: string;
  positionId: string;
  memberId: string;
  validFrom: string;
  validTo: string | null;
}

/** The admin position-list row — a position plus its CURRENT assignment
 * (assignmentId/memberId/holderDisplayName, all null when the position has no holder today) —
 * the fields the Positions admin page needs to render "who holds this seat" and END a tenure
 * without a second round trip. */
export interface OrgPositionWithHolder extends OrgPosition {
  assignmentId: string | null;
  memberId: string | null;
  holderDisplayName: string | null;
}

/** A company-scoped named set of members. source is "kiban" for every group the open mechanism
 * itself can create; any other value (an externally-sourced group) means
 * membership is read-only through every human/API surface — isKibanManaged mirrors that check
 * server-side so the UI never has to reimplement the source string comparison. */
export interface OrgGroup {
  id: string;
  companyId: string;
  code: string;
  name: string;
  source: string;
  externalRef: string | null;
  isActive: boolean;
  isKibanManaged: boolean;
}

/** The admin group-list row — a group plus its current member count, so the
 * Groups admin page never needs a second round trip per row. */
export interface OrgGroupWithMemberCount extends OrgGroup {
  memberCount: number;
}

/** One membership row in an {@link OrgGroup} — who added whom, and when. */
export interface OrgGroupMember {
  groupId: string;
  memberId: string;
  addedBy: string;
  addedAt: string;
  memberDisplayName: string;
  memberEmail: string | null;
}

/** Whether a company org-unit exists and is active — internal/org's company-facts read. */
export interface OrgCompanyState {
  exists: boolean;
  isActive: boolean;
}

/** Whether a given kcSub is an active member of a company — internal/org's company-facts read. */
export interface OrgMembershipState {
  isMember: boolean;
  isActive: boolean;
  memberId: string | null;
}

/** GET /api/org/me/companies's response item (internal/org/http.go's handleMeCompanies) — the
 * company-switcher source: companies where the caller has an active membership in an active
 * company. */
export interface OrgMeCompany {
  id: string;
  code: string;
  name: string;
  isActive: boolean;
}
