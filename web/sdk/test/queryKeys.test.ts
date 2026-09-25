// SPDX-License-Identifier: Apache-2.0

// Behavioral tests on the queryKeys factory's shapes/stability: every leaf key must be array-shaped, nest under its domain's `all`
// root (so a broad invalidation of `all` invalidates every descendant key under TanStack Query's
// prefix-matching), and be stable/deterministic for the same arguments — these are the load-
// bearing properties consumers rely on, not incidental structure.
import { describe, expect, it } from "vitest";
import { queryKeys } from "../src/queryKeys.js";

describe("queryKeys — capabilities", () => {
  it("all is a stable root", () => {
    expect(queryKeys.capabilities.all).toEqual(["capabilities"]);
  });

  it("list() nests under all", () => {
    expect(queryKeys.capabilities.list()).toEqual(["capabilities", "list"]);
  });

  it("detail() nests under all and includes the moduleKey", () => {
    expect(queryKeys.capabilities.detail("core")).toEqual(["capabilities", "detail", "core"]);
  });

  it("detail() is deterministic for the same moduleKey and distinct for different ones", () => {
    expect(queryKeys.capabilities.detail("core")).toEqual(queryKeys.capabilities.detail("core"));
    expect(queryKeys.capabilities.detail("core")).not.toEqual(queryKeys.capabilities.detail("registry"));
  });
});

describe("queryKeys — superadmin", () => {
  it("all is a stable root", () => {
    expect(queryKeys.superadmin.all).toEqual(["superadmin"]);
  });

  it("catalog() nests under all", () => {
    expect(queryKeys.superadmin.catalog()).toEqual(["superadmin", "catalog"]);
  });
});

describe("queryKeys — effectiveAccess", () => {
  it("all is a stable root", () => {
    expect(queryKeys.effectiveAccess.all).toEqual(["effectiveAccess"]);
  });

  it("can() nests under all and embeds the request for cache-key uniqueness per request shape", () => {
    const request = { featureKey: "core.company.view", scope: "global" as const };
    expect(queryKeys.effectiveAccess.can(request)).toEqual(["effectiveAccess", "can", request]);
  });

  it("batchCan() nests under all, distinct from can()", () => {
    const request = { featureKey: "core.company.view", scope: "global" as const };
    expect(queryKeys.effectiveAccess.batchCan(request)).toEqual(["effectiveAccess", "batchCan", request]);
    expect(queryKeys.effectiveAccess.batchCan(request)).not.toEqual(queryKeys.effectiveAccess.can(request));
  });

  it("summary() nests under all, keyed on companyId (null when omitted)", () => {
    expect(queryKeys.effectiveAccess.summary("company-1")).toEqual(["effectiveAccess", "summary", "company-1"]);
    expect(queryKeys.effectiveAccess.summary()).toEqual(["effectiveAccess", "summary", null]);
  });
});

describe("queryKeys — org", () => {
  it("all is a stable root", () => {
    expect(queryKeys.org.all).toEqual(["org"]);
  });

  it("meCompanies() is a fixed leaf under all (no id/company parameter — always the caller)", () => {
    expect(queryKeys.org.meCompanies()).toEqual(["org", "meCompanies"]);
  });

  it("units.all()/detail()/subtree() nest under org.all", () => {
    expect(queryKeys.org.units.all()).toEqual(["org", "units"]);
    expect(queryKeys.org.units.detail("u1")).toEqual(["org", "units", "u1"]);
    expect(queryKeys.org.units.subtree("u1")).toEqual(["org", "units", "u1", "subtree"]);
  });

  it("members.all() is company-scoped and nests under org.all", () => {
    expect(queryKeys.org.members.all("company-1")).toEqual(["org", "members", "company-1"]);
  });

  it("members.list() defaults page/pageSize to null when omitted, and carries them when given", () => {
    expect(queryKeys.org.members.list("company-1")).toEqual(["org", "members", "company-1", "list", null, null]);
    expect(queryKeys.org.members.list("company-1", 2, 10)).toEqual(["org", "members", "company-1", "list", 2, 10]);
  });

  it("members.detail() nests under org.all, distinct from units.detail() for the same id", () => {
    expect(queryKeys.org.members.detail("x1")).toEqual(["org", "members", "detail", "x1"]);
    expect(queryKeys.org.members.detail("x1")).not.toEqual(queryKeys.org.units.detail("x1"));
  });

  it("positions.all()/list()/detail()/holder() are company- and id-scoped and nest under org.all", () => {
    expect(queryKeys.org.positions.all("company-1")).toEqual(["org", "positions", "company-1"]);
    expect(queryKeys.org.positions.list("company-1")).toEqual([
      "org",
      "positions",
      "company-1",
      "list",
      null,
      null
    ]);
    expect(queryKeys.org.positions.list("company-1", 3, 50)).toEqual([
      "org",
      "positions",
      "company-1",
      "list",
      3,
      50
    ]);
    expect(queryKeys.org.positions.detail("p1")).toEqual(["org", "positions", "detail", "p1"]);
    expect(queryKeys.org.positions.holder("p1", "2026-08-11")).toEqual([
      "org",
      "positions",
      "detail",
      "p1",
      "holder",
      "2026-08-11"
    ]);
  });
});
