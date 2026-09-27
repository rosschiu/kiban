// SPDX-License-Identifier: Apache-2.0

package modulekit

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestOrgClient_MemberByKcSub_Member(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/internal/org/companies/company-1/members/by-kcsub/kcsub-alice" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "" {
			t.Errorf("org facts reads must not forward a bearer")
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"isMember": true, "isActive": true, "memberId": "member-1"}})
	}))
	defer srv.Close()

	c := NewOrgClient(srv.Client(), srv.URL, testModule)
	memberID, isMember, isActive, err := c.MemberByKcSub(t.Context(), "company-1", "kcsub-alice")
	if err != nil || !isMember || !isActive || memberID != "member-1" {
		t.Fatalf("got (%q, %v, %v, %v), want (member-1, true, true, nil)", memberID, isMember, isActive, err)
	}
}

func TestOrgClient_MemberByKcSub_NotMember(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"isMember": false, "isActive": false, "memberId": nil}})
	}))
	defer srv.Close()

	c := NewOrgClient(srv.Client(), srv.URL, testModule)
	memberID, isMember, isActive, err := c.MemberByKcSub(t.Context(), "company-1", "kcsub-outsider")
	if err != nil || isMember || isActive || memberID != "" {
		t.Fatalf("got (%q, %v, %v, %v), want (\"\", false, false, nil)", memberID, isMember, isActive, err)
	}
}

// A 404 on member-by-kcsub is a plain status error — no not-found sentinel on that read.
func TestOrgClient_MemberByKcSub_NonOKStatus_Errors(t *testing.T) {
	for _, code := range []int{http.StatusNotFound, http.StatusInternalServerError} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(code)
		}))
		c := NewOrgClient(srv.Client(), srv.URL, testModule)
		_, _, _, err := c.MemberByKcSub(t.Context(), "company-1", "kcsub-alice")
		srv.Close()
		if want := testModule + ": member-by-kcsub: HTTP " + strconv.Itoa(code); err == nil || err.Error() != want {
			t.Fatalf("code %d: err = %v, want %q", code, err, want)
		}
	}
}

func TestOrgClient_MemberByKcSub_MalformedBody_Errors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("not json"))
	}))
	defer srv.Close()

	c := NewOrgClient(srv.Client(), srv.URL, testModule)
	_, _, _, err := c.MemberByKcSub(t.Context(), "company-1", "kcsub-alice")
	if err == nil || !strings.HasPrefix(err.Error(), testModule+": decode member-by-kcsub response: ") {
		t.Fatalf("err = %v", err)
	}
}

func TestOrgClient_MemberByKcSub_TransportError_Errors(t *testing.T) {
	c := NewOrgClient(&http.Client{Timeout: 200 * time.Millisecond}, "http://127.0.0.1:1", testModule)
	_, _, _, err := c.MemberByKcSub(t.Context(), "company-1", "kcsub-alice")
	if err == nil || !strings.HasPrefix(err.Error(), testModule+": member-by-kcsub request: ") {
		t.Fatalf("err = %v", err)
	}
}

func TestOrgClient_GetJSON_BadBaseURL_Errors(t *testing.T) {
	c := NewOrgClient(http.DefaultClient, "://bad", testModule)
	err := c.GetJSON(t.Context(), "/x", "get-x", new(struct{}), nil)
	if err == nil || !strings.HasPrefix(err.Error(), testModule+": build get-x request: ") {
		t.Fatalf("err = %v", err)
	}
}

func TestOrgClient_GetMember_Found(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/internal/org/members/member-1" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
			"id": "member-1", "companyId": "company-1", "displayName": "Alice", "isActive": true,
			"user": map[string]any{"kcSub": "kcsub-alice"},
		}})
	}))
	defer srv.Close()

	c := NewOrgClient(srv.Client(), srv.URL, testModule)
	m, err := c.GetMember(t.Context(), "member-1")
	if err != nil {
		t.Fatalf("GetMember: %v", err)
	}
	if m != (OrgMember{ID: "member-1", CompanyID: "company-1", DisplayName: "Alice", IsActive: true, KcSub: "kcsub-alice"}) {
		t.Fatalf("got %+v", m)
	}
}

// TestOrgClient_GetMember_NoLinkedUser proves the User==nil branch (a member with no linked kcSub
// yet): empty KcSub, no error — the client-level distinction handlers branch on for their 422.
func TestOrgClient_GetMember_NoLinkedUser(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
			"id": "member-2", "companyId": "company-1", "displayName": "Unlinked", "isActive": true, "user": nil,
		}})
	}))
	defer srv.Close()

	c := NewOrgClient(srv.Client(), srv.URL, testModule)
	m, err := c.GetMember(t.Context(), "member-2")
	if err != nil {
		t.Fatalf("GetMember: %v", err)
	}
	if m.KcSub != "" {
		t.Fatalf("KcSub = %q, want empty (no linked user)", m.KcSub)
	}
}

func TestOrgClient_GetMember_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	c := NewOrgClient(srv.Client(), srv.URL, testModule)
	_, err := c.GetMember(t.Context(), "missing-member")
	if !errors.Is(err, ErrOrgMemberNotFound) {
		t.Fatalf("err = %v, want ErrOrgMemberNotFound", err)
	}
	if err.Error() != testModule+": org member not found" {
		t.Fatalf("error text = %q", err.Error())
	}
}

func TestOrgClient_GetMember_NonOKStatus_Errors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := NewOrgClient(srv.Client(), srv.URL, testModule)
	_, err := c.GetMember(t.Context(), "member-1")
	if err == nil || errors.Is(err, ErrOrgMemberNotFound) || err.Error() != testModule+": get-member: HTTP 500" {
		t.Fatalf("err = %v, want a generic status error (not ErrOrgMemberNotFound)", err)
	}
}

func TestOrgClient_GetMember_MalformedBody_Errors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("not json"))
	}))
	defer srv.Close()

	c := NewOrgClient(srv.Client(), srv.URL, testModule)
	if _, err := c.GetMember(t.Context(), "member-1"); err == nil {
		t.Fatal("expected an error for a malformed response body")
	}
}

func TestOrgClient_GetMember_TransportError_Errors(t *testing.T) {
	c := NewOrgClient(&http.Client{Timeout: 200 * time.Millisecond}, "http://127.0.0.1:1", testModule)
	if _, err := c.GetMember(t.Context(), "member-1"); err == nil {
		t.Fatal("expected an error when org is unreachable")
	}
}
