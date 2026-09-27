// SPDX-License-Identifier: Apache-2.0

import { expect, type Page } from "@playwright/test";

// The gateway serves the shell's HTML with an ENFORCED Content-Security-Policy
// (internal/gateway/static.go's shellCSP). A browser reports every blocked resource/inline
// style/connect as a console error naming the policy, so the two smoke journeys (login.spec.ts,
// walkthrough.spec.ts) watch every page's console and fail if the built shell ever trips the
// policy — the proof that the CSP is one the bundle actually satisfies, not a guess.
export function watchCSPViolations(page: Page, violations: string[]): void {
  page.on("console", (msg) => {
    if (msg.type() === "error" && /content.security.policy/i.test(msg.text())) {
      violations.push(msg.text());
    }
  });
}

export function expectNoCSPViolations(violations: string[]): void {
  expect(violations, "Content-Security-Policy violations reported by the browser").toEqual([]);
}
