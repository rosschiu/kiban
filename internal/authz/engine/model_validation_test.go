// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"strings"
	"testing"
)

// TestExprUnmarshalErrors and TestLoadModelValidation cover model.go's remaining error/edge
// branches: the subset-wall's malformed-payload checks (each construct's own json.Unmarshal
// failure and required-field checks), the "exactly 1 key" rule with >1 key (which also drives
// sortedKeys, used only in that error message), LoadModel's empty-model rejection, and
// validateSelfRefs' three constructs (computedUserset/tupleToUserset/nested union) rejecting a
// same-type relation reference that doesn't exist.

func TestExprUnmarshalErrors(t *testing.T) {
	cases := []struct {
		name    string
		json    string
		wantErr string
	}{
		{"this not a bool", `{"thing":{"r":{"this":"yes"}}}`, `"this" must be a JSON bool`},
		{"this false has no meaning", `{"thing":{"r":{"this":false}}}`, `"this": false has no meaning`},
		{"computedUserset not a string", `{"thing":{"r":{"computedUserset":123}}}`, `"computedUserset" must be a string`},
		{"computedUserset empty string", `{"thing":{"r":{"computedUserset":""}}}`, `must name a relation`},
		{"tupleToUserset malformed payload", `{"thing":{"r":{"tupleToUserset":"not an object"}}}`, `"tupleToUserset":`},
		{"tupleToUserset empty tupleset", `{"thing":{"r":{"tupleToUserset":{"tupleset":"","computedUserset":"x"}}}}`, `requires non-empty tupleset`},
		{"tupleToUserset empty computedUserset", `{"thing":{"r":{"tupleToUserset":{"tupleset":"x","computedUserset":""}}}}`, `requires non-empty tupleset`},
		{"union malformed payload", `{"thing":{"r":{"union":"not an array"}}}`, `"union":`},
		{"union empty", `{"thing":{"r":{"union":[]}}}`, `must have at least one child`},
		{"relation expr not a JSON object", `{"thing":{"r":123}}`, `not a JSON object`},
		{"zero keys", `{"thing":{"r":{}}}`, `expected exactly 1 key, got 0`},
		{"two keys triggers sortedKeys in the error message", `{"thing":{"r":{"this":true,"computedUserset":"x"}}}`, `got 2 ([computedUserset this])`},
		{"unrecognized construct outside the subset", `{"thing":{"r":{"exclusion":{}}}}`, `outside the supported subset`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := LoadModel([]byte(tc.json))
			if err == nil {
				t.Fatalf("LoadModel(%s) = nil error, want error containing %q", tc.json, tc.wantErr)
			}
			if !containsStr(err.Error(), tc.wantErr) {
				t.Fatalf("LoadModel(%s) error = %q, want it to contain %q", tc.json, err.Error(), tc.wantErr)
			}
		})
	}
}

func TestLoadModelValidation(t *testing.T) {
	t.Run("empty model is rejected", func(t *testing.T) {
		_, err := LoadModel([]byte(`{}`))
		if err == nil {
			t.Fatal("LoadModel({}) = nil error, want \"model: empty\"")
		}
		if !containsStr(err.Error(), "empty") {
			t.Fatalf("LoadModel({}) error = %q, want it to contain %q", err.Error(), "empty")
		}
	})

	t.Run("computedUserset target must exist on the same type", func(t *testing.T) {
		_, err := LoadModel([]byte(`{"thing":{"r":{"computedUserset":"nosuch"}}}`))
		if err == nil {
			t.Fatal("want a self-ref validation error, got nil")
		}
		if !containsStr(err.Error(), "computedUserset") || !containsStr(err.Error(), "not defined on type") {
			t.Fatalf("error = %q, want it to name computedUserset and \"not defined on type\"", err.Error())
		}
	})

	t.Run("tupleToUserset.tupleset target must exist on the same type", func(t *testing.T) {
		_, err := LoadModel([]byte(`{"thing":{"r":{"tupleToUserset":{"tupleset":"nosuch","computedUserset":"r"}}}}`))
		if err == nil {
			t.Fatal("want a self-ref validation error, got nil")
		}
		if !containsStr(err.Error(), "tupleToUserset tupleset") || !containsStr(err.Error(), "not defined on type") {
			t.Fatalf("error = %q, want it to name the tupleset ref and \"not defined on type\"", err.Error())
		}
	})

	t.Run("a nested union child's bad self-ref is caught by recursion", func(t *testing.T) {
		_, err := LoadModel([]byte(`{"thing":{"r":{"union":[{"this":true},{"computedUserset":"nosuch"}]}}}`))
		if err == nil {
			t.Fatal("want a self-ref validation error from the nested union child, got nil")
		}
		if !containsStr(err.Error(), "computedUserset") {
			t.Fatalf("error = %q, want it to name the bad computedUserset ref found inside the union", err.Error())
		}
	})

	t.Run("a valid multi-type model with cross-references loads cleanly", func(t *testing.T) {
		m, err := LoadModel([]byte(`{
			"parent": {"admin": {"this": true}},
			"child": {
				"parent": {"this": true},
				"admin": {"tupleToUserset": {"tupleset": "parent", "computedUserset": "admin"}}
			}
		}`))
		if err != nil {
			t.Fatalf("LoadModel: unexpected error: %v", err)
		}
		if len(m) != 2 {
			t.Fatalf("want 2 types, got %d", len(m))
		}
	})
}

func TestModelMerge(t *testing.T) {
	base, err := LoadModel([]byte(`{
		"a": {"r": {"this": true}},
		"shared": {"r": {"this": true}}
	}`))
	if err != nil {
		t.Fatalf("LoadModel(base): %v", err)
	}
	other, err := LoadModel([]byte(`{
		"b": {"r": {"this": true}}
	}`))
	if err != nil {
		t.Fatalf("LoadModel(other): %v", err)
	}

	merged, err := base.Merge(other)
	if err != nil {
		t.Fatalf("Merge of disjoint models: %v", err)
	}
	for _, typ := range []string{"a", "b", "shared"} {
		if _, ok := merged[typ]; !ok {
			t.Errorf("merged model missing type %q", typ)
		}
	}
	// The original models must be unmodified (Merge returns a new Model).
	if _, ok := base["b"]; ok {
		t.Fatal("Merge must not mutate the receiver")
	}

	// A type declared on both sides is refused, never last-wins.
	dup, err := LoadModel([]byte(`{"shared": {"r2": {"this": true}}}`))
	if err != nil {
		t.Fatalf("LoadModel(dup): %v", err)
	}
	if _, err := base.Merge(dup); err == nil || !strings.Contains(err.Error(), `"shared"`) {
		t.Fatalf("Merge with a type declared twice: want an error naming \"shared\", got %v", err)
	}
}

// TestValidateTupleToUsersetTargets covers the cross-type half: a
// tupleToUserset whose computedUserset exists on no type of the effective model is refused,
// including one nested inside a union; the base model itself passes; a fragment merged onto the
// base model resolves a base relation (company_module#member).
func TestValidateTupleToUsersetTargets(t *testing.T) {
	if err := BaseModel.ValidateTupleToUsersetTargets(); err != nil {
		t.Fatalf("base model: %v", err)
	}
	frag, err := LoadModel([]byte(`{"thing":{"company_module":{"this":true},
		"viewer":{"union":[{"this":true},{"tupleToUserset":{"tupleset":"company_module","computedUserset":"member"}}]}}}`))
	if err != nil {
		t.Fatal(err)
	}
	effective, err := BaseModel.Merge(frag)
	if err != nil {
		t.Fatal(err)
	}
	if err := effective.ValidateTupleToUsersetTargets(); err != nil {
		t.Fatalf("fragment referencing company_module#member must resolve on the effective model: %v", err)
	}
	if err := frag.ValidateTupleToUsersetTargets(); err == nil {
		t.Fatal("fragment alone (no company_module#member anywhere) must fail")
	}
	bad, err := LoadModel([]byte(`{"thing":{"parent":{"this":true},
		"viewer":{"tupleToUserset":{"tupleset":"parent","computedUserset":"nonexistent"}}}}`))
	if err != nil {
		t.Fatal(err)
	}
	effective, err = BaseModel.Merge(bad)
	if err != nil {
		t.Fatal(err)
	}
	err = effective.ValidateTupleToUsersetTargets()
	if err == nil || !strings.Contains(err.Error(), `thing#viewer: tupleToUserset computedUserset "nonexistent"`) {
		t.Fatalf("want unresolved-target error, got %v", err)
	}
}
