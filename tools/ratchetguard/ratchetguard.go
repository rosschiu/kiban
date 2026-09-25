// SPDX-License-Identifier: Apache-2.0

// Package ratchetguard implements the mechanical never-decrease check for coverage/ratchet.json
// (minimums may only ever increase, never decrease). It compares the
// working tree's coverage/ratchet.json against the version committed at HEAD and fails loudly if
// any scope's "min" was lowered or any scope was removed outright. Split from cmd/main.go so the
// comparison logic (Compare) is unit-testable without any git plumbing.
package ratchetguard

import (
	"encoding/json"
	"fmt"
	"sort"
)

// Entry mirrors tools/coveragegate's own ratchetEntry shape (Min/Floor) — duplicated rather than
// imported (tools/coveragegate is a `package main`, not importable) — same "every package owns
// its own small test/tooling infra" convention this codebase already follows elsewhere (see
// modules/*/service/dbtest_env_test.go's own header comment).
type Entry struct {
	Min   float64 `json:"min"`
	Floor float64 `json:"floor"`
}

// Parse decodes a coverage/ratchet.json document into its scope entries, skipping any key that
// starts with "_" (e.g. "_comment" — not a scope, matches tools/coveragegate/main.go's own
// loadRatchet convention exactly).
func Parse(data []byte) (map[string]Entry, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse ratchet json: %w", err)
	}
	out := make(map[string]Entry, len(raw))
	for k, v := range raw {
		if len(k) > 0 && k[0] == '_' {
			continue
		}
		var e Entry
		if err := json.Unmarshal(v, &e); err != nil {
			return nil, fmt.Errorf("parse ratchet entry %q: %w", k, err)
		}
		out[k] = e
	}
	return out, nil
}

// Compare returns one violation message per scope where newRatchet regressed relative to
// oldRatchet: a scope present in oldRatchet but missing from newRatchet ("removed"), or a scope
// whose "min" decreased. A scope's floor decreasing is NOT itself flagged (floor is the
// target, not a promise already made to callers the way min is — lowering min is the one that
// would let a regression slip past `make check` for a scope whose coverage was already raised),
// nor is a NEW scope appearing (adding a scope is how coverage work is tracked, never a
// regression). Sorted by scope name for deterministic output.
func Compare(oldRatchet, newRatchet map[string]Entry) []string {
	var violations []string
	for scope, oldEntry := range oldRatchet {
		newEntry, ok := newRatchet[scope]
		if !ok {
			violations = append(violations, fmt.Sprintf("scope %q was REMOVED from coverage/ratchet.json (had min=%.1f) — removing a scope's gate is a min-decrease in disguise", scope, oldEntry.Min))
			continue
		}
		if newEntry.Min < oldEntry.Min {
			violations = append(violations, fmt.Sprintf("scope %q min DECREASED: %.4f -> %.4f — coverage/ratchet.json minimums may only ever increase", scope, oldEntry.Min, newEntry.Min))
		}
	}
	sort.Strings(violations)
	return violations
}
