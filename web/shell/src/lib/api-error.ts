// SPDX-License-Identifier: Apache-2.0

// One place that turns an SDK failure into user-facing copy. Every page's catch used to set a
// fixed "you may not have access" string, so an authz outage (503), a server bug (500) and a lost
// connection all read as a permissions problem. `fallback` is the page's own copy for the plain
// 4xx cases (404, 409, validation...), where the page knows better than a generic mapper.
import { KibanApiError } from "@rosschiu/kiban-sdk";

export function describeApiError(err: unknown, fallback: string): string {
  if (err instanceof KibanApiError) {
    if (err.status === 401) return "Your session has expired. Please log in again.";
    if (err.status === 403) return "You do not have permission to do this.";
    if (err.status === 503) return "The service is temporarily unavailable. Please try again in a moment.";
    if (err.status >= 500) {
      return `Something went wrong on the server. Please try again${err.correlationId ? ` (reference ${err.correlationId})` : ""}.`;
    }
    return fallback;
  }
  // fetch() rejects with a TypeError when the request never got a response (offline, DNS, the
  // gateway down) — the SDK client lets that propagate unwrapped.
  if (err instanceof TypeError) return "Could not reach the server. Check your connection and try again.";
  return fallback;
}

/** True for the failures a user cannot fix by asking for access: an outage, a server error, or
 * no connection. Pages that fail closed to an empty shape use this to say "could not load"
 * instead of "nothing here". */
export function isServiceFailure(err: unknown): boolean {
  return (err instanceof KibanApiError && err.status >= 500) || err instanceof TypeError;
}
