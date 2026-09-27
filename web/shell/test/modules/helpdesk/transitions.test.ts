// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { availableTransitions } from "../../../src/modules/helpdesk/transitions";
import type { HelpdeskTicket } from "../../../src/modules/helpdesk/api";

function ticket(overrides: Partial<HelpdeskTicket> = {}): HelpdeskTicket {
  return {
    id: "t-1",
    companyId: "company-a",
    title: "T",
    description: "D",
    status: "open",
    reporterMemberId: "member-reporter",
    assigneeMemberId: null,
    isReporter: false,
    isAssignee: false,
    createdAt: "now",
    updatedAt: "now",
    ...overrides,
  };
}

describe("availableTransitions", () => {
  it("offers no transitions on a closed ticket to anyone", () => {
    expect(availableTransitions(ticket({ status: "closed", isReporter: true }), "admin")).toEqual([]);
    expect(availableTransitions(ticket({ status: "closed" }), "member")).toEqual([]);
  });

  it("open -> in_progress is available to the assignee", () => {
    expect(availableTransitions(ticket({ status: "open", isAssignee: true }), "agent")).toEqual([
      { to: "in_progress", label: "Start progress" },
    ]);
  });

  it("open -> in_progress is available to admin regardless of assignment", () => {
    expect(availableTransitions(ticket({ status: "open", isAssignee: false }), "admin")).toEqual([
      { to: "in_progress", label: "Start progress" },
    ]);
  });

  it("open offers nothing to a non-assignee, non-admin", () => {
    expect(availableTransitions(ticket({ status: "open", isAssignee: false }), "member")).toEqual([]);
    expect(availableTransitions(ticket({ status: "open", isAssignee: false }), "agent")).toEqual([]);
  });

  it("in_progress -> resolved is available to the assignee or admin only", () => {
    expect(availableTransitions(ticket({ status: "in_progress", isAssignee: true }), "agent")).toEqual([
      { to: "resolved", label: "Resolve" },
    ]);
    expect(availableTransitions(ticket({ status: "in_progress", isAssignee: false }), "admin")).toEqual([
      { to: "resolved", label: "Resolve" },
    ]);
    expect(availableTransitions(ticket({ status: "in_progress", isAssignee: false }), "member")).toEqual([]);
  });

  it("resolved offers close+reopen to the reporter or admin only", () => {
    expect(availableTransitions(ticket({ status: "resolved", isReporter: true }), "member")).toEqual([
      { to: "closed", label: "Close" },
      { to: "open", label: "Reopen" },
    ]);
    expect(availableTransitions(ticket({ status: "resolved", isReporter: false }), "admin")).toEqual([
      { to: "closed", label: "Close" },
      { to: "open", label: "Reopen" },
    ]);
    expect(availableTransitions(ticket({ status: "resolved", isReporter: false }), "agent")).toEqual([]);
  });

  it("treats a null tier the same as a plain member (no elevated rights)", () => {
    expect(availableTransitions(ticket({ status: "open", isAssignee: false }), null)).toEqual([]);
  });
});
