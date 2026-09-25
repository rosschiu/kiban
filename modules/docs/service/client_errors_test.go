// SPDX-License-Identifier: Apache-2.0

package docs

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// Tests of docs's own AuthzClient wrappers (object-mode can, batch-can, share grants); the
// shared transport/error paths are tested once in modulekit. Mocking authz is acceptable because
// it is genuinely external to this module.

func TestAuthzClient_CanObject_Allowed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req authzCanRequestWire
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatal(err)
		}
		if req.ModuleKey != "docs" || req.Object.Type != "docs_document" {
			t.Errorf("unexpected request: %+v", req)
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"allowed": true, "reason": "ALLOWED"}})
	}))
	defer srv.Close()

	c := NewAuthzClient(srv.Client(), srv.URL)
	allowed, reason, err := c.CanObject(t.Context(), "Bearer tok", "company-1", "doc-1", "owner")
	if err != nil || !allowed || reason != "ALLOWED" {
		t.Fatalf("got (%v, %q, %v), want (true, ALLOWED, nil)", allowed, reason, err)
	}
}

func TestAuthzClient_BatchCanObject_NonOKStatus_Errors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := NewAuthzClient(srv.Client(), srv.URL)
	_, err := c.BatchCanObject(t.Context(), "Bearer tok", "company-1", []string{"doc-1"}, "viewer")
	if err == nil {
		t.Fatal("expected an error for a non-200 status")
	}
}

func TestAuthzClient_BatchCanObject_MalformedBody_Errors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("not json"))
	}))
	defer srv.Close()

	c := NewAuthzClient(srv.Client(), srv.URL)
	_, err := c.BatchCanObject(t.Context(), "Bearer tok", "company-1", []string{"doc-1"}, "viewer")
	if err == nil {
		t.Fatal("expected an error for a malformed response body")
	}
}

func TestAuthzClient_BatchCanObject_TransportError_Errors(t *testing.T) {
	c := NewAuthzClient(&http.Client{Timeout: 200 * time.Millisecond}, "http://127.0.0.1:1")
	_, err := c.BatchCanObject(t.Context(), "Bearer tok", "company-1", []string{"doc-1"}, "viewer")
	if err == nil {
		t.Fatal("expected an error when authz is unreachable")
	}
}

// TestAuthzClient_BatchCanObject_EmptyDocIDs_NoRoundTrip covers the len(docIDs)==0 short-circuit
// branch (other tests always supply at least one docID).
func TestAuthzClient_BatchCanObject_EmptyDocIDs_NoRoundTrip(t *testing.T) {
	c := NewAuthzClient(&http.Client{}, "http://127.0.0.1:1") // unreachable — proves no request is made
	out, err := c.BatchCanObject(t.Context(), "Bearer tok", "company-1", nil, "viewer")
	if err != nil {
		t.Fatalf("expected nil error for an empty docIDs slice, got %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("out = %+v, want empty", out)
	}
}

// TestAuthzClient_BatchCanObject_MissingResult_FailsClosed covers the "response doesn't cover a
// requested docID" branch — treated as denied, never fabricated as allowed.
func TestAuthzClient_BatchCanObject_MissingResult_FailsClosed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{"data": []any{}}) // no results at all
	}))
	defer srv.Close()

	c := NewAuthzClient(srv.Client(), srv.URL)
	out, err := c.BatchCanObject(t.Context(), "Bearer tok", "company-1", []string{"doc-1"}, "viewer")
	if err != nil {
		t.Fatalf("BatchCanObject: %v", err)
	}
	if out["doc-1"] {
		t.Fatalf("out = %+v, want doc-1 to fail closed (false)", out)
	}
}

func TestAuthzClient_GrantShare_Success_SendsExpectedTuple(t *testing.T) {
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
	if err := c.GrantShare(t.Context(), "Bearer tok", "co-1", "doc-1", "viewer", "kcsub-x", "corr-1"); err != nil {
		t.Fatalf("GrantShare: %v", err)
	}
	if got.Op != "grant" || got.Tuples[0].Relation != "viewer" {
		t.Fatalf("got = %+v", got)
	}
}
