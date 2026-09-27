// SPDX-License-Identifier: Apache-2.0

// Display-only ID token claim decoding for the NavUser footer (NavUser needs
// a name/email/avatar). Uses the SDK's `decodeIdTokenClaims()` — the same "decode, do not verify
// signature" posture the session applies to its own nonce check — and the claims are used for
// display only, never for an authz decision (every real access check still goes through the
// gateway/resolver against the bearer token itself).
import { decodeIdTokenClaims } from "@rosschiu/kiban-sdk";

export interface DecodedUserProfile {
  name: string;
  email: string;
  picture: string | null;
}

/** Decodes the ID token's payload claims for display (name/preferred_username/email/picture).
 * Returns null for a missing/malformed token rather than throwing — callers render a fallback. */
export function decodeUserProfile(idToken: string | null | undefined): DecodedUserProfile | null {
  if (!idToken) return null;
  if (idToken.split(".").length !== 3) return null;

  const claims = decodeIdTokenClaims(idToken);
  if (!claims) return null;
  const name = typeof claims.name === "string" && claims.name.trim()
    ? claims.name
    : typeof claims.preferred_username === "string"
      ? claims.preferred_username
      : "Signed in";
  const email = typeof claims.email === "string" ? claims.email : typeof claims.preferred_username === "string" ? claims.preferred_username : "";
  const picture = typeof claims.picture === "string" ? claims.picture : null;
  return { name, email, picture };
}
