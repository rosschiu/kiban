// SPDX-License-Identifier: Apache-2.0

// A golden snapshot of the base authz model's type+relation set (drift insurance —
// internal/authz/fragment.Load starts every effective-model build from BaseModel and
// forbids a module fragment from redefining a base type; modvalidate enforces the same rule at
// module-install time). model_test.go's own "real model loads and validates" subtest already
// asserts a SUBSET of types is present (drawn from internal/authz/harness/model.fga) — this file is
// the COMPLETE, exact set: any addition, removal, or rename of a type or relation in model.json
// changes testdata/base_model_snapshot.golden and must be updated deliberately (an accidental
// drift — e.g. a merge that silently drops a relation — fails this test with a diff), never
// silently pass model_test.go's own partial check.
package engine

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

const baseModelSnapshotPath = "testdata/base_model_snapshot.golden"

// baseModelSnapshotLines renders m as one "type.relation" line per relation, sorted, so the
// golden diff is stable regardless of map iteration order or model.json's own key order.
func baseModelSnapshotLines(m Model) []string {
	lines := make([]string, 0, 64)
	for typ, relations := range m {
		for relation := range relations {
			lines = append(lines, typ+"."+relation)
		}
	}
	sort.Strings(lines)
	return lines
}

// TestBaseModel_TypeRelationSnapshot is the golden test: BaseModel's current type+relation set
// must match testdata/base_model_snapshot.golden exactly. To update deliberately after an
// intentional model.json change, run this test with UPDATE_BASE_MODEL_SNAPSHOT=1 to rewrite the
// golden, then review the diff before committing — the same "update deliberately, review the
// diff" convention as any other golden test in this codebase.
func TestBaseModel_TypeRelationSnapshot(t *testing.T) {
	got := baseModelSnapshotLines(BaseModel)
	gotText := strings.Join(got, "\n") + "\n"

	if os.Getenv("UPDATE_BASE_MODEL_SNAPSHOT") == "1" {
		if err := os.WriteFile(baseModelSnapshotPath, []byte(gotText), 0o644); err != nil {
			t.Fatalf("write golden: %v", err)
		}
		t.Logf("wrote %s (%d type.relation entries) — review the diff before committing", baseModelSnapshotPath, len(got))
		return
	}

	wantBytes, err := os.ReadFile(baseModelSnapshotPath)
	if err != nil {
		t.Fatalf("read golden %s: %v (run with UPDATE_BASE_MODEL_SNAPSHOT=1 to create it)", baseModelSnapshotPath, err)
	}
	want := strings.Split(strings.TrimRight(string(wantBytes), "\n"), "\n")

	if len(want) != len(got) {
		t.Fatalf("base model type+relation count changed: golden has %d, BaseModel has %d — if this change is deliberate, re-run with UPDATE_BASE_MODEL_SNAPSHOT=1 and review the diff before committing.\ngolden path: %s",
			len(want), len(got), filepath.Clean(baseModelSnapshotPath))
	}
	for i := range want {
		if want[i] != got[i] {
			t.Fatalf("base model type+relation set drifted at entry %d: golden=%q, BaseModel=%q — if this change is deliberate, re-run with UPDATE_BASE_MODEL_SNAPSHOT=1 and review the diff before committing.\ngolden path: %s",
				i, want[i], got[i], filepath.Clean(baseModelSnapshotPath))
		}
	}
}
