// SPDX-License-Identifier: Apache-2.0

// Package testauditgolden is a shared helper for golden tests of audit
// event PAYLOAD SHAPE (keys + JSON value types, never values themselves — an audit payload
// routinely carries real member/company/document IDs and titles that must never be pinned
// verbatim into a checked-in fixture). Shape drifting (a field renamed, removed, or changing
// type) is exactly the drift this helper exists to catch; the VALUES are free to vary run to run
// without failing the test.
//
// Update procedure (same convention as internal/authz/engine's base-model snapshot): run the failing test with UPDATE_AUDIT_GOLDENS=1 to rewrite the
// golden file, review the diff, then commit both the production/test change and the golden
// together.
package testauditgolden

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"
)

// Shape reduces a JSON payload to its "keys + types" fingerprint: one line per top-level key,
// sorted, "<key>:<jsonType>". Nested objects/arrays are recorded by their own JSON type only
// (never recursed) — the payloads pinned so far are all flat maps of scalars/IDs, so one level
// is sufficient and keeps the golden format simple; a future payload with real nested structure
// worth pinning can extend this without changing the file format (still "<key>:<type>" lines).
func Shape(rawPayload []byte) (string, error) {
	var m map[string]any
	if err := json.Unmarshal(rawPayload, &m); err != nil {
		return "", fmt.Errorf("testauditgolden: unmarshal payload: %w", err)
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	lines := make([]string, 0, len(keys))
	for _, k := range keys {
		lines = append(lines, k+":"+jsonType(m[k]))
	}
	return strings.Join(lines, "\n") + "\n", nil
}

func jsonType(v any) string {
	switch v.(type) {
	case nil:
		return "null"
	case bool:
		return "bool"
	case float64:
		return "number"
	case string:
		return "string"
	case []any:
		return "array"
	case map[string]any:
		return "object"
	default:
		return fmt.Sprintf("unknown(%T)", v)
	}
}

// Matches is the pure comparison AssertGolden wraps — split out (same reason
// internal/testsec.MissingSpecs and tools/ratchetguard.Compare are split from their own
// *testing.T-side-effecting callers: a failing subtest
// unconditionally marks every ancestor *testing.T failed, so a test proving "this mismatch is
// detected" cannot call the T-fataling wrapper directly).
func Matches(want, got string) bool {
	return want == got
}

// AssertGolden compares got (typically Shape's output) against the file at path. With
// UPDATE_AUDIT_GOLDENS=1 in the environment, it (re)writes the golden instead of comparing —
// review the diff before committing, same as every other golden test in this codebase.
func AssertGolden(t *testing.T, path, got string) {
	t.Helper()
	if os.Getenv("UPDATE_AUDIT_GOLDENS") == "1" {
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatalf("write golden %s: %v", path, err)
		}
		t.Logf("wrote %s — review the diff before committing", path)
		return
	}
	wantBytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden %s: %v (run with UPDATE_AUDIT_GOLDENS=1 to create it)", path, err)
	}
	want := string(wantBytes)
	if !Matches(want, got) {
		t.Fatalf("audit payload shape drifted from golden %s.\n--- golden ---\n%s--- got ---\n%s"+
			"If this is a deliberate payload shape change, re-run with UPDATE_AUDIT_GOLDENS=1 and review the diff before committing.",
			path, want, got)
	}
}
