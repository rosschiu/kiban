// SPDX-License-Identifier: Apache-2.0

package modulekit

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func okJSON(t *testing.T, body any) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(body)
	}
}

func TestAuthzClient_Can_Allowed_NoRelationLeg(t *testing.T) {
	var got CanRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/internal/authz/effective-access/can" || r.Method != http.MethodPost {
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer tok" {
			t.Errorf("Authorization = %q", got)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("Content-Type = %q", ct)
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatal(err)
		}
		okJSON(t, map[string]any{"data": map[string]any{"allowed": true, "reason": "ALLOWED"}})(w, r)
	}))
	defer srv.Close()

	c := NewAuthzClient(srv.Client(), srv.URL, testModule)
	allowed, reason, err := c.Can(t.Context(), "Bearer tok", "x.view", "company-1", "")
	if err != nil || !allowed || reason != "ALLOWED" {
		t.Fatalf("got (%v, %q, %v), want (true, ALLOWED, nil)", allowed, reason, err)
	}
	if got.ModuleKey != testModule || got.Scope != "company" || got.CompanyID != "company-1" || got.FeatureKey != "x.view" || got.Relation != "" || got.Object != (ObjectRef{}) {
		t.Fatalf("request = %+v", got)
	}
	if c.ModuleKey() != testModule {
		t.Fatalf("ModuleKey() = %q", c.ModuleKey())
	}
}

func TestAuthzClient_Can_Denied_WithRelationLeg(t *testing.T) {
	var got CanRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatal(err)
		}
		okJSON(t, map[string]any{"data": map[string]any{"allowed": false, "reason": "COMPANY_MEMBERSHIP_REQUIRED"}})(w, r)
	}))
	defer srv.Close()

	c := NewAuthzClient(srv.Client(), srv.URL, testModule)
	allowed, reason, err := c.Can(t.Context(), "Bearer tok", "x.manage", "company-1", "admin")
	if err != nil || allowed || reason != "COMPANY_MEMBERSHIP_REQUIRED" {
		t.Fatalf("got (%v, %q, %v), want (false, COMPANY_MEMBERSHIP_REQUIRED, nil)", allowed, reason, err)
	}
	if got.Object.Type != "company_module" || got.Object.ID != "company-1/"+testModule || got.Relation != "admin" {
		t.Fatalf("object/relation = %+v", got)
	}
}

func TestAuthzClient_Can_NonOKStatus_Errors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := NewAuthzClient(srv.Client(), srv.URL, testModule)
	_, _, err := c.Can(t.Context(), "Bearer tok", "x.view", "company-1", "")
	if err == nil || err.Error() != testModule+": authz can request: HTTP 500" {
		t.Fatalf("err = %v", err)
	}
}

func TestAuthzClient_Can_MalformedBody_Errors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("not json"))
	}))
	defer srv.Close()

	c := NewAuthzClient(srv.Client(), srv.URL, testModule)
	_, _, err := c.Can(t.Context(), "Bearer tok", "x.view", "company-1", "")
	if err == nil || !strings.HasPrefix(err.Error(), testModule+": decode authz can response: ") {
		t.Fatalf("err = %v", err)
	}
}

func TestAuthzClient_Can_TransportError_Errors(t *testing.T) {
	c := NewAuthzClient(&http.Client{Timeout: 200 * time.Millisecond}, "http://127.0.0.1:1", testModule)
	_, _, err := c.Can(t.Context(), "Bearer tok", "x.view", "company-1", "")
	if err == nil || !strings.HasPrefix(err.Error(), testModule+": authz can request: ") {
		t.Fatalf("err = %v", err)
	}
}

func TestAuthzClient_Can_BadBaseURL_Errors(t *testing.T) {
	c := NewAuthzClient(http.DefaultClient, "://bad", testModule)
	_, _, err := c.Can(t.Context(), "Bearer tok", "x.view", "company-1", "")
	if err == nil || !strings.HasPrefix(err.Error(), testModule+": build authz can request: ") {
		t.Fatalf("err = %v", err)
	}
}

func TestAuthzClient_PostJSON_UnmarshalableBody_Errors(t *testing.T) {
	c := NewAuthzClient(http.DefaultClient, "http://127.0.0.1:1", testModule)
	err := c.PostJSON(t.Context(), "Bearer tok", "/x", "authz x", func() {}, nil)
	if err == nil || !strings.HasPrefix(err.Error(), testModule+": marshal authz x request: ") {
		t.Fatalf("err = %v", err)
	}
}

func TestAuthzClient_GrantOrRevoke_Success_SendsExpectedBody(t *testing.T) {
	var got GrantsRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/internal/authz/grants" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatal(err)
		}
		okJSON(t, map[string]any{"data": map[string]any{"status": "ok"}})(w, r)
	}))
	defer srv.Close()

	c := NewAuthzClient(srv.Client(), srv.URL, testModule)
	tuples := []Tuple{{ObjectType: "company_module", ObjectID: c.CompanyModuleObjectID("company-1"), Relation: "approver", SubjectType: "user", SubjectID: "kcsub-approver"}}
	if err := c.GrantOrRevoke(t.Context(), "Bearer tok", "company-1", "grant", tuples, "corr-9"); err != nil {
		t.Fatalf("GrantOrRevoke: %v", err)
	}
	if got.Op != "grant" || got.CompanyID != "company-1" || len(got.Tuples) != 1 || got.CorrelationID != "corr-9" {
		t.Fatalf("got = %+v", got)
	}
	if tup := got.Tuples[0]; tup.ObjectID != "company-1/"+testModule || tup.Relation != "approver" || tup.SubjectID != "kcsub-approver" || tup.SubjectRelation != "" {
		t.Fatalf("tuple = %+v", tup)
	}
}

func TestAuthzClient_GrantOrRevoke_NonOKStatus_Errors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := NewAuthzClient(srv.Client(), srv.URL, testModule)
	err := c.GrantOrRevoke(t.Context(), "Bearer tok", "company-1", "revoke", nil, "corr-1")
	if err == nil || err.Error() != testModule+": authz revoke request: HTTP 500" {
		t.Fatalf("err = %v", err)
	}
}

func TestAuthzClient_GrantOrRevoke_TransportError_Errors(t *testing.T) {
	c := NewAuthzClient(&http.Client{Timeout: 200 * time.Millisecond}, "http://127.0.0.1:1", testModule)
	err := c.GrantOrRevoke(t.Context(), "Bearer tok", "company-1", "grant", nil, "corr-1")
	if err == nil || !strings.HasPrefix(err.Error(), testModule+": authz grant request: ") {
		t.Fatalf("err = %v", err)
	}
}
