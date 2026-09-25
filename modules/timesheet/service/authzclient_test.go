// SPDX-License-Identifier: Apache-2.0

package timesheet

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Tests of this module's own AuthzClient wrappers (relationLeg mapping, GrantRelation's tuple);
// the shared transport/error paths are tested once in modulekit.

func TestAuthzClient_GrantRelation_Success_SendsExpectedTuple(t *testing.T) {
	var got grantsRequestWire
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatal(err)
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"status": "ok"}})
	}))
	defer srv.Close()

	c := NewAuthzClient(srv.Client(), srv.URL)
	if err := c.GrantRelation(t.Context(), "Bearer tok", "company-1", "approver", "kcsub-approver", "corr-9"); err != nil {
		t.Fatalf("GrantRelation: %v", err)
	}
	if got.Op != "grant" || len(got.Tuples) != 1 {
		t.Fatalf("got = %+v", got)
	}
	tup := got.Tuples[0]
	if tup.ObjectType != "company_module" || tup.ObjectID != "company-1/timesheet" || tup.Relation != "approver" || tup.SubjectID != "kcsub-approver" {
		t.Fatalf("tuple = %+v", tup)
	}
	if got.CorrelationID != "corr-9" {
		t.Errorf("correlationId = %q, want corr-9", got.CorrelationID)
	}
}

// TestAuthzClient_ObjectRelationLeg proves relationLeg's own mapping (authz.fragment.json's
// accessRulePayload, never invented): admin-gated features carry company_module#admin,
// submissions.submit/approve carry submitter/approver respectively, entries.manage-own carries no
// relation leg (membership-gated only — the base model has no per-member relation for it).
func TestAuthzClient_ObjectRelationLeg(t *testing.T) {
	tests := []struct {
		name       string
		featureKey string
		wantType   string
		wantRel    string
	}{
		{"projects.manage carries company_module#admin", featureProjectsManage, "company_module", "admin"},
		{"config.manage carries company_module#admin", featureConfigManage, "company_module", "admin"},
		{"approvers.manage carries company_module#admin", featureApproversManage, "company_module", "admin"},
		{"submissions.submit carries company_module#submitter", featureSubmissionsSubmit, "company_module", "submitter"},
		{"submissions.approve carries company_module#approver", featureSubmissionsApprove, "company_module", "approver"},
		{"entries.manage-own carries no relation leg", featureEntriesManageOwn, "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got authzCanRequestWire
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
					t.Fatal(err)
				}
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"allowed": true, "reason": "ALLOWED"}})
			}))
			defer srv.Close()

			c := NewAuthzClient(srv.Client(), srv.URL)
			if _, _, err := c.Can(t.Context(), "Bearer tok", tt.featureKey, "company-1"); err != nil {
				t.Fatalf("Can: %v", err)
			}
			if got.Object.Type != tt.wantType || got.Relation != tt.wantRel {
				t.Fatalf("object/relation = (%q, %q), want (%q, %q)", got.Object.Type, got.Relation, tt.wantType, tt.wantRel)
			}
			if tt.wantType != "" && got.Object.ID != "company-1/timesheet" {
				t.Fatalf("object.id = %q, want %q", got.Object.ID, "company-1/timesheet")
			}
		})
	}
}
