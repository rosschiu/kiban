// SPDX-License-Identifier: Apache-2.0

package client

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestAdminAuthorizer_EmptyBearer_DeniesWithoutCallingServer(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))
	defer srv.Close()

	a := New(srv.URL, srv.Client())
	ok, err := a.Can(t.Context(), "", "org.unit.create")
	if ok || err != ErrAuthorizationUnavailable {
		t.Fatalf("got (%v, %v), want (false, ErrAuthorizationUnavailable)", ok, err)
	}
	if called {
		t.Fatal("server must not be called for an empty bearer")
	}
}

func TestAdminAuthorizer_AllowedEnvelope_ReturnsTrue(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer abc" {
			t.Errorf("Authorization header = %q, want %q", got, "Bearer abc")
		}
		var req canRequestWire
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatal(err)
		}
		if req.FeatureKey != AdminFeatureKey || req.Scope != "global" || req.RequiredPlatformRole != AdminRequiredRole {
			t.Errorf("unexpected request wire: %+v", req)
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"allowed": true, "reason": "ALLOWED"}})
	}))
	defer srv.Close()

	a := New(srv.URL, srv.Client())
	ok, err := a.Can(t.Context(), "Bearer abc", "org.unit.create")
	if !ok || err != nil {
		t.Fatalf("got (%v, %v), want (true, nil)", ok, err)
	}
}

func TestAdminAuthorizer_DeniedEnvelope_ReturnsUnavailable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"allowed": false, "reason": "PLATFORM_ROLE_REQUIRED"}})
	}))
	defer srv.Close()

	a := New(srv.URL, srv.Client())
	ok, err := a.Can(t.Context(), "Bearer abc", "org.unit.create")
	if ok || err != ErrAuthorizationUnavailable {
		t.Fatalf("got (%v, %v), want (false, ErrAuthorizationUnavailable)", ok, err)
	}
}

func TestAdminAuthorizer_NonOKStatus_ReturnsUnavailable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	a := New(srv.URL, srv.Client())
	ok, err := a.Can(t.Context(), "Bearer abc", "org.unit.create")
	if ok || err != ErrAuthorizationUnavailable {
		t.Fatalf("got (%v, %v), want (false, ErrAuthorizationUnavailable)", ok, err)
	}
}

func TestAdminAuthorizer_MalformedBody_ReturnsUnavailable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("not json"))
	}))
	defer srv.Close()

	a := New(srv.URL, srv.Client())
	ok, err := a.Can(t.Context(), "Bearer abc", "org.unit.create")
	if ok || err != ErrAuthorizationUnavailable {
		t.Fatalf("got (%v, %v), want (false, ErrAuthorizationUnavailable)", ok, err)
	}
}

func TestAdminAuthorizer_TransportError_ReturnsUnavailable(t *testing.T) {
	a := New("http://127.0.0.1:1", &http.Client{Timeout: 200 * time.Millisecond})
	ok, err := a.Can(t.Context(), "Bearer abc", "org.unit.create")
	if ok || err != ErrAuthorizationUnavailable {
		t.Fatalf("got (%v, %v), want (false, ErrAuthorizationUnavailable)", ok, err)
	}
}

func TestAdminAuthorizer_NilHTTPClient_GetsDefault(t *testing.T) {
	a := New("http://127.0.0.1:1", nil)
	if a.client == nil {
		t.Fatal("expected a default http.Client")
	}
	if a.client.Timeout != defaultTimeout {
		t.Errorf("default timeout = %v, want %v", a.client.Timeout, defaultTimeout)
	}
}

func TestAdminAuthorizer_AllowedTrueWrongReason_ReturnsUnavailable(t *testing.T) {
	// A response claiming allowed=true but without the exact "ALLOWED" reason string must still
	// be treated as a deny — the reason string is part of the contract, not decoration.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"allowed": true, "reason": "SOMETHING_ELSE"}})
	}))
	defer srv.Close()

	a := New(srv.URL, srv.Client())
	ok, err := a.Can(t.Context(), "Bearer abc", "org.unit.create")
	if ok || err != ErrAuthorizationUnavailable {
		t.Fatalf("got (%v, %v), want (false, ErrAuthorizationUnavailable)", ok, err)
	}
}

func TestAdminAuthorizer_RequestBuildError_ReturnsUnavailable(t *testing.T) {
	// A control character in the base URL makes http.NewRequestWithContext's internal url.Parse
	// fail before any network I/O happens — exercises the request-build error branch.
	a := New("http://exa\nmple.invalid", http.DefaultClient)
	ok, err := a.Can(t.Context(), "Bearer x", "platform.module.enable")
	if ok || err != ErrAuthorizationUnavailable {
		t.Errorf("Can() = (%v, %v), want (false, ErrAuthorizationUnavailable) for a request-build error", ok, err)
	}
}

// TestAdminAuthorizer_Decide covers what the gateway's superadmin guard reads off Decide that Can
// hides: the decoded denial reason, and the correlation id forwarded in the body and header only
// when present.
func TestAdminAuthorizer_Decide(t *testing.T) {
	var gotHeader string
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Get("x-correlation-id")
		gotBody = nil
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"allowed": false, "reason": "PLATFORM_ROLE_REQUIRED"}})
	}))
	defer srv.Close()

	a := New(srv.URL, srv.Client())
	d, err := a.Decide(t.Context(), "Bearer abc", "org.unit.create", "corr-1")
	if err != nil || d.Allowed || d.Reason != "PLATFORM_ROLE_REQUIRED" {
		t.Fatalf("got (%+v, %v), want ({false PLATFORM_ROLE_REQUIRED}, nil)", d, err)
	}
	if gotHeader != "corr-1" || gotBody["correlationId"] != "corr-1" {
		t.Errorf("correlation id: header=%q body=%v, want corr-1 in both", gotHeader, gotBody["correlationId"])
	}

	if _, err := a.Decide(t.Context(), "Bearer abc", "org.unit.create", ""); err != nil {
		t.Fatal(err)
	}
	if _, present := gotBody["correlationId"]; gotHeader != "" || present {
		t.Errorf("empty correlation id: header=%q body=%v, want neither sent", gotHeader, gotBody)
	}
}

func TestDecision_Denied(t *testing.T) {
	cases := []struct {
		d    Decision
		want bool
	}{
		{Decision{Allowed: false, Reason: "PLATFORM_ROLE_REQUIRED"}, true},
		{Decision{Allowed: false, Reason: "AUTH_USER_NOT_FOUND"}, true},
		{Decision{Allowed: false, Reason: "KEYCLOAK_DISABLED"}, true},
		{Decision{Allowed: false, Reason: "USER_LIFECYCLE_DISABLED"}, true},
		{Decision{Allowed: true, Reason: "ALLOWED"}, false},
		{Decision{Allowed: true, Reason: "PLATFORM_ROLE_REQUIRED"}, false}, // contradictory envelope: uncertain
		{Decision{Allowed: false, Reason: "DEPENDENCY_UNAVAILABLE"}, false},
		{Decision{Allowed: false, Reason: ""}, false},
	}
	for _, c := range cases {
		if got := c.d.Denied(); got != c.want {
			t.Errorf("%+v.Denied() = %v, want %v", c.d, got, c.want)
		}
	}
}
