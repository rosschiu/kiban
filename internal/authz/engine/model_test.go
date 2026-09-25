// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"os"
	"testing"
)

func TestModel(t *testing.T) {
	t.Run("real model loads and validates", func(t *testing.T) {
		data, err := os.ReadFile("model.json")
		if err != nil {
			t.Fatalf("read model.json: %v", err)
		}
		m, err := LoadModel(data)
		if err != nil {
			t.Fatalf("LoadModel(model.json): %v", err)
		}
		for _, want := range []string{
			"user", "system", "module", "company", "company_module", "module_role_binding",
			"access_bundle", "access_segment", "member_directory", "member", "project_directory",
			"project", "timesheet_entry", "submission", "document", "group",
		} {
			if _, ok := m[want]; !ok {
				t.Errorf("model.json: missing type %q from internal/authz/harness/model.fga", want)
			}
		}
	})

	t.Run("rejects intersection", func(t *testing.T) {
		expectRejected(t, `{"thing":{"viewer":{"intersection":[{"this":true},{"computedUserset":"admin"}]}}}`, "intersection")
	})
	t.Run("rejects exclusion", func(t *testing.T) {
		expectRejected(t, `{"thing":{"viewer":{"exclusion":{"base":{"this":true},"subtract":{"computedUserset":"banned"}}}}}`, "exclusion")
	})
	t.Run("rejects wildcard", func(t *testing.T) {
		expectRejected(t, `{"thing":{"viewer":{"wildcard":"user"}}}`, "wildcard")
	})
	t.Run("rejects condition", func(t *testing.T) {
		expectRejected(t, `{"thing":{"viewer":{"condition":{"name":"in_business_hours","context":{}}}}}`, "condition")
	})
}

func expectRejected(t *testing.T, badModelJSON, construct string) {
	t.Helper()
	_, err := LoadModel([]byte(badModelJSON))
	if err == nil {
		t.Fatalf("LoadModel accepted a %q construct; the subset wall must reject it", construct)
	}
	if !containsStr(err.Error(), construct) {
		t.Fatalf("LoadModel rejected the model but the error %q doesn't name the construct %q", err.Error(), construct)
	}
	t.Logf("rejected as expected: %v", err)
}

func containsStr(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
