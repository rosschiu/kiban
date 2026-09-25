// SPDX-License-Identifier: Apache-2.0

import "@testing-library/jest-dom/vitest";

// jsdom does not implement window.scrollTo (and throws "Not implemented" via its virtual
// console when called) — @tanstack/router-core's scroll-restoration calls it on every route
// load. Stub it as a no-op so route-loading tests don't spam "Error: Not implemented:
// window.scrollTo" — real failures would get lost in this noise.
window.scrollTo = () => {};

// jsdom does not implement window.matchMedia — hooks/use-mobile.ts (sidebar-07's
// own mobile-breakpoint hook) and ui/theme-toggle.tsx both call it unconditionally. Stub a
// desktop-width, no-op-listener MediaQueryList so both compile in tests without asserting on
// actual media-query behavior (covered instead by their own dedicated test files).
window.matchMedia ??= (query: string) =>
  ({
    matches: false,
    media: query,
    onchange: null,
    addListener: () => {},
    removeListener: () => {},
    addEventListener: () => {},
    removeEventListener: () => {},
    dispatchEvent: () => false,
  }) as MediaQueryList;
