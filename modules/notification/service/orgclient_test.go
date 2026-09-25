// SPDX-License-Identifier: Apache-2.0

package notification

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Direct tests for notification's OrgClient — other tests only exercise it indirectly through
// events_targeted_test.go's fakeMembershipChecker stand-in. Mocking org here is fine — it is genuinely
// external to this module.

func TestOrgClient_IsActiveMember_True(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/internal/org/companies/company-1/members/by-kcsub/kcsub-alice" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"isMember": true, "isActive": true}})
	}))
	defer srv.Close()

	c := NewOrgClient(srv.Client(), srv.URL)
	active, err := c.IsActiveMember(t.Context(), "company-1", "kcsub-alice")
	if err != nil || !active {
		t.Fatalf("got (%v, %v), want (true, nil)", active, err)
	}
}

func TestOrgClient_IsActiveMember_False(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"isMember": true, "isActive": false}})
	}))
	defer srv.Close()

	c := NewOrgClient(srv.Client(), srv.URL)
	active, err := c.IsActiveMember(t.Context(), "company-1", "kcsub-alice")
	if err != nil || active {
		t.Fatalf("got (%v, %v), want (false, nil)", active, err)
	}
}
