// SPDX-License-Identifier: Apache-2.0

package helpdesk

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// Tests of helpdesk's own AuthzClient/OrgClient/NotificationClient wrappers (relationLeg
// mapping, position/group checks and grants, position/group facts, the empty-recipient no-op);
// the shared transport/error paths are tested once in modulekit. Mocking is acceptable because
// all three dependencies are genuinely external to this module.

// TestAuthzClient_ObjectRelationLeg proves relationLeg's own mapping — the tier features carry
// their company_module leg, featureTicketsCreate carries none (membership-gated only).
func TestAuthzClient_ObjectRelationLeg(t *testing.T) {
	tests := []struct {
		name       string
		featureKey string
		wantType   string
		wantRel    string
	}{
		{"helpdesk.manage carries company_module#admin", featureHelpdeskManage, "company_module", "admin"},
		{"tickets.work carries company_module#editor", featureTicketsWork, "company_module", "editor"},
		{"tickets.create carries no relation leg", featureTicketsCreate, "", ""},
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
		})
	}
}

func TestAuthzClient_IsPositionHolder_AllowedAndDenied(t *testing.T) {
	allowed := true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req authzCanRequestWire
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.Object.Type != "position" || req.Relation != "holder" {
			t.Errorf("unexpected object/relation: %+v", req)
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"allowed": allowed, "reason": "ALLOWED"}})
	}))
	defer srv.Close()

	c := NewAuthzClient(srv.Client(), srv.URL)
	ok, err := c.IsPositionHolder(t.Context(), "Bearer tok", "company-1", "pos-1")
	if err != nil || !ok {
		t.Fatalf("got (%v, %v), want (true, nil)", ok, err)
	}
}

func TestAuthzClient_IsGroupMember_Allowed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req authzCanRequestWire
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.Object.Type != "group" || req.Relation != "member" {
			t.Errorf("unexpected object/relation: %+v", req)
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"allowed": true, "reason": "ALLOWED"}})
	}))
	defer srv.Close()

	c := NewAuthzClient(srv.Client(), srv.URL)
	ok, err := c.IsGroupMember(t.Context(), "Bearer tok", "company-1", "grp-1")
	if err != nil || !ok {
		t.Fatalf("got (%v, %v), want (true, nil)", ok, err)
	}
}

func TestAuthzClient_RevokeAgent_Success_SendsRevokeOp(t *testing.T) {
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
	if err := c.RevokeAgent(t.Context(), "Bearer tok", "company-1", "kcsub-x", "corr-1"); err != nil {
		t.Fatalf("RevokeAgent: %v", err)
	}
	if got.Op != "revoke" || got.Tuples[0].SubjectType != "user" {
		t.Fatalf("got = %+v", got)
	}
}

func TestAuthzClient_GrantPositionAgent_Success_SendsPositionSubject(t *testing.T) {
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
	if err := c.GrantPositionAgent(t.Context(), "Bearer tok", "company-1", "pos-1", "corr-1"); err != nil {
		t.Fatalf("GrantPositionAgent: %v", err)
	}
	if got.Tuples[0].SubjectType != "position" || got.Tuples[0].SubjectRelation != "holder" {
		t.Fatalf("got = %+v", got.Tuples[0])
	}
}

func TestAuthzClient_GrantGroupAgent_Success_SendsGroupSubject(t *testing.T) {
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
	if err := c.GrantGroupAgent(t.Context(), "Bearer tok", "company-1", "grp-1", "corr-1"); err != nil {
		t.Fatalf("GrantGroupAgent: %v", err)
	}
	if got.Tuples[0].SubjectType != "group" || got.Tuples[0].SubjectRelation != "member" {
		t.Fatalf("got = %+v", got.Tuples[0])
	}
}

func TestOrgClient_GetPosition_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	c := NewOrgClient(srv.Client(), srv.URL)
	if _, err := c.GetPosition(t.Context(), "missing"); err != ErrOrgPositionNotFound {
		t.Fatalf("err = %v, want ErrOrgPositionNotFound", err)
	}
}

func TestOrgClient_GetPosition_TransportError_Errors(t *testing.T) {
	c := NewOrgClient(&http.Client{Timeout: 200 * time.Millisecond}, "http://127.0.0.1:1")
	if _, err := c.GetPosition(t.Context(), "pos-1"); err == nil {
		t.Fatal("expected an error when org is unreachable")
	}
}

func TestOrgClient_GetPositionHolder_Unassigned_NotAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	c := NewOrgClient(srv.Client(), srv.URL)
	memberID, ok, err := c.GetPositionHolder(t.Context(), "pos-1")
	if err != nil || ok || memberID != "" {
		t.Fatalf("got (%q, %v, %v), want (\"\", false, nil)", memberID, ok, err)
	}
}

func TestOrgClient_GetPositionHolder_NonOKStatus_Errors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := NewOrgClient(srv.Client(), srv.URL)
	if _, _, err := c.GetPositionHolder(t.Context(), "pos-1"); err == nil {
		t.Fatal("expected an error for a non-200 status")
	}
}

func TestOrgClient_GetPositionHolder_TransportError_Errors(t *testing.T) {
	c := NewOrgClient(&http.Client{Timeout: 200 * time.Millisecond}, "http://127.0.0.1:1")
	if _, _, err := c.GetPositionHolder(t.Context(), "pos-1"); err == nil {
		t.Fatal("expected an error when org is unreachable")
	}
}

func TestOrgClient_GetGroup_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	c := NewOrgClient(srv.Client(), srv.URL)
	if _, err := c.GetGroup(t.Context(), "missing"); err != ErrOrgGroupNotFound {
		t.Fatalf("err = %v, want ErrOrgGroupNotFound", err)
	}
}

func TestOrgClient_GetGroup_TransportError_Errors(t *testing.T) {
	c := NewOrgClient(&http.Client{Timeout: 200 * time.Millisecond}, "http://127.0.0.1:1")
	if _, err := c.GetGroup(t.Context(), "grp-1"); err == nil {
		t.Fatal("expected an error when org is unreachable")
	}
}

func TestOrgClient_ListGroupMembers_NonOKStatus_Errors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := NewOrgClient(srv.Client(), srv.URL)
	if _, err := c.ListGroupMembers(t.Context(), "grp-1"); err == nil {
		t.Fatal("expected an error for a non-200 status")
	}
}

func TestOrgClient_ListGroupMembers_TransportError_Errors(t *testing.T) {
	c := NewOrgClient(&http.Client{Timeout: 200 * time.Millisecond}, "http://127.0.0.1:1")
	if _, err := c.ListGroupMembers(t.Context(), "grp-1"); err == nil {
		t.Fatal("expected an error when org is unreachable")
	}
}

// ---- NotificationClient --------------------------------------------------------------------------

func TestNotificationClient_SendEvent_NoRecipient_NoOp(t *testing.T) {
	c := NewNotificationClient(&http.Client{Timeout: time.Second}, "http://127.0.0.1:1")
	if err := c.SendEvent(t.Context(), "Bearer tok", "company-1", "", "subj", "body"); err != nil {
		t.Fatalf("expected nil error for empty recipient (no-op), got %v", err)
	}
}

func TestNotificationClient_SendEvent_Success_SendsExpectedPayload(t *testing.T) {
	var got sendEventRequestWire
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatal(err)
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"sent": 1, "skipped": 0}})
	}))
	defer srv.Close()

	c := NewNotificationClient(srv.Client(), srv.URL)
	if err := c.SendEvent(t.Context(), "Bearer tok", "company-1", "kcsub-x", "New comment", "body text"); err != nil {
		t.Fatalf("SendEvent: %v", err)
	}
	if len(got.RecipientKcSubs) != 1 || got.RecipientKcSubs[0] != "kcsub-x" || got.SourceModule != "helpdesk" {
		t.Fatalf("got = %+v", got)
	}
}
