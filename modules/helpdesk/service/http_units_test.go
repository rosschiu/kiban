// SPDX-License-Identifier: Apache-2.0

package helpdesk

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// Direct unit tests for the pure request-path helpers the HTTP fixture cannot reach on its own:
// writeStoreError's mapping, canTransition's edge table, handleMyTier's authz-unavailable 503
// and GetPositionHolder's "200 with an empty memberId" branch.

func TestWriteStoreError_Mapping(t *testing.T) {
	cases := []struct {
		err      error
		status   int
		code     string
		contains string
	}{
		{&ValidationError{Field: "title", Message: "title is required"}, http.StatusBadRequest, "VALIDATION_ERROR", `"field":"title"`},
		{ErrTicketNotFound, http.StatusNotFound, "NOT_FOUND", "not found"},
		{ErrAgentNotFound, http.StatusNotFound, "NOT_FOUND", "not found"},
		{ErrIdempotencyConflict, http.StatusConflict, "IDEMPOTENCY_CONFLICT", "Idempotency-Key"},
		{errors.New("boom"), http.StatusInternalServerError, "INTERNAL_ERROR", "internal error"},
	}
	for _, c := range cases {
		rec := httptest.NewRecorder()
		writeStoreError(rec, c.err)
		if rec.Code != c.status || !strings.Contains(rec.Body.String(), `"code":"`+c.code+`"`) || !strings.Contains(rec.Body.String(), c.contains) {
			t.Fatalf("%v: code=%d body=%s", c.err, rec.Code, rec.Body.String())
		}
	}
}

func TestCanTransition_EdgeTable(t *testing.T) {
	assignee := "kcsub-agent"
	ticket := Ticket{ReporterKcSub: "kcsub-reporter", AssigneeKcSub: &assignee}
	cases := []struct {
		name        string
		subject     string
		tier        string
		from, to    string
		viaEngine   bool
		wantAllowed bool
	}{
		{"admin may do anything", "kcsub-other", "admin", StatusClosed, StatusOpen, false, true},
		{"assignee open->in_progress", assignee, "agent", StatusOpen, StatusInProgress, false, true},
		{"assignee in_progress->resolved", assignee, "agent", StatusInProgress, StatusResolved, false, true},
		{"engine-resolved assignee in_progress->resolved", "kcsub-holder", "member", StatusInProgress, StatusResolved, true, true},
		{"reporter may not start work", "kcsub-reporter", "member", StatusOpen, StatusInProgress, false, false},
		{"reporter resolved->closed", "kcsub-reporter", "member", StatusResolved, StatusClosed, false, true},
		{"reporter resolved->open", "kcsub-reporter", "member", StatusResolved, StatusOpen, false, true},
		{"assignee may not close", assignee, "agent", StatusResolved, StatusClosed, false, false},
		{"unknown edge", assignee, "agent", StatusOpen, StatusClosed, false, false},
	}
	for _, c := range cases {
		if got := canTransition(ticket, c.subject, c.tier, c.from, c.to, c.viaEngine); got != c.wantAllowed {
			t.Errorf("%s: got %v, want %v", c.name, got, c.wantAllowed)
		}
	}
}

// TestHandleMyTier_AuthzUnavailable_503 covers handleMyTier's error branch: the tier lookup's
// authz round trip fails (unreachable authz) AFTER withAuth already passed.
func TestHandleMyTier_AuthzUnavailable_503(t *testing.T) {
	svc := &Service{Authz: NewAuthzClient(&http.Client{Timeout: 200 * time.Millisecond}, "http://127.0.0.1:1")}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/helpdesk/v1/companies/x/me", nil)
	svc.handleMyTier(rec, req, requestContext{Subject: "kcsub-alice", RawBearer: "Bearer tok", CompanyID: uuid.New()})
	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), `"code":"AUTHORIZATION_UNAVAILABLE"`) {
		t.Fatalf("code=%d body=%s", rec.Code, rec.Body.String())
	}
}

// TestOrgClient_GetPositionHolder_EmptyMemberID_NotAnError: a 200 whose memberId is empty is
// treated exactly like the 404 "unassigned chair" case — ok=false, no error.
func TestOrgClient_GetPositionHolder_EmptyMemberID_NotAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"memberId": ""}})
	}))
	defer srv.Close()

	c := NewOrgClient(srv.Client(), srv.URL)
	memberID, ok, err := c.GetPositionHolder(t.Context(), "pos-1")
	if err != nil || ok || memberID != "" {
		t.Fatalf("got (%q, %v, %v), want (\"\", false, nil)", memberID, ok, err)
	}
}
