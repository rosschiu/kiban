// SPDX-License-Identifier: Apache-2.0

/**
 * `@rosschiu/kiban-sdk/server`: the app's backend beside Kiban. Authenticate as the app's
 * service client, verify the user tokens Kiban's login issued, ask for decisions, write tuples
 * on the app's own object types, look members up.
 *
 * @packageDocumentation
 */
export { createServiceCredentials } from "./credentials.js";
export type { ServiceCredentials, ServiceCredentialsConfig } from "./credentials.js";
export { createTokenVerifier } from "./verifier.js";
export type { TokenVerifier, TokenVerifierConfig, VerifiedToken } from "./verifier.js";
export { createAppClient } from "./appClient.js";
export type { AppClient, AppClientConfig, AppManifest, MemberFact, Tuple } from "./appClient.js";
export { KibanApiError } from "../client.js";
export type {
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
