// SPDX-License-Identifier: Apache-2.0

// Cross-language drift pin. contracts/wire-enums.json is the golden BOTH this
// vitest test and internal/contracts/wire_enums_test.go (Go) compare against — either side
// diverging (a code/reason added, removed, or renamed on only one side) fails its OWN suite.
// See contracts/wire-enums.json's own "_comment" for the update procedure.
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { ApiErrorCode, EffectiveAccessReason } from "../src/types.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const goldenPath = path.resolve(here, "..", "..", "..", "contracts", "wire-enums.json");

interface Golden {
  apiErrorCodes: Record<string, string>;
  effectiveAccessReasons: Record<string, string>;
}

function loadGolden(): Golden {
  return JSON.parse(readFileSync(goldenPath, "utf-8")) as Golden;
}

describe("wire-enums golden — ApiErrorCode", () => {
  it("matches contracts/wire-enums.json exactly", () => {
    const golden = loadGolden().apiErrorCodes;
    expect(ApiErrorCode).toEqual(golden);
  });
});

describe("wire-enums golden — EffectiveAccessReason", () => {
  it("matches contracts/wire-enums.json exactly", () => {
    const golden = loadGolden().effectiveAccessReasons;
    expect(EffectiveAccessReason).toEqual(golden);
  });
});
