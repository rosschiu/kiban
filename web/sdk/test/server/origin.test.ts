// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { stripTrailingSlashes } from "../../src/server/origin";

describe("stripTrailingSlashes", () => {
  it("removes every trailing slash and nothing else", () => {
    expect(stripTrailingSlashes("https://gw.test")).toBe("https://gw.test");
    expect(stripTrailingSlashes("https://gw.test/")).toBe("https://gw.test");
    expect(stripTrailingSlashes("https://gw.test///")).toBe("https://gw.test");
    expect(stripTrailingSlashes("https://gw.test/a/b//")).toBe("https://gw.test/a/b");
    expect(stripTrailingSlashes("/")).toBe("");
    expect(stripTrailingSlashes("")).toBe("");
  });
  it("stays linear on a long run of slashes", () => {
    const input = "https://gw.test" + "/".repeat(200_000) + "x";
    const t0 = performance.now();
    expect(stripTrailingSlashes(input)).toBe(input);
    expect(performance.now() - t0).toBeLessThan(200);
  });
});
