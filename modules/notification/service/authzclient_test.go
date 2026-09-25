// SPDX-License-Identifier: Apache-2.0

package notification

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestAuthzClient_ObjectRelationLeg proves the tiered wiring: channels.manage and
// messages.send carry the company_module#admin object-relation leg (authz.fragment.json's own
// accessRulePayload), inbox.view carries none (its fragment anchors on company_module#member,
// which the base model doesn't define).
func TestAuthzClient_ObjectRelationLeg(t *testing.T) {
	tests := []struct {
		name       string
		featureKey string
		wantType   string
		wantRel    string
	}{
		{"channels.manage carries company_module#admin", featureChannelsManage, "company_module", "admin"},
		{"messages.send carries company_module#admin", featureMessagesSend, "company_module", "admin"},
		{"inbox.view carries no relation leg", featureInboxView, "", ""},
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
			if tt.wantType != "" && got.Object.ID != "company-1/notification" {
				t.Fatalf("object.id = %q, want %q", got.Object.ID, "company-1/notification")
			}
		})
	}
}
