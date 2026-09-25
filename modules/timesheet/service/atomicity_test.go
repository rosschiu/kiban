// SPDX-License-Identifier: Apache-2.0

package timesheet

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/rosschiu/kiban/internal/audit"
)

// Generalizes internal/org/audit_atomicity_test.go's pattern to timesheet's approver-assign
// grant+business-write pairing. handleAssignApprover (http_handlers.go) grants TWO authz relation
// tuples FIRST (submitter for the member, approver for the approver member — both via
// AuthzClient.GrantRelation, real separate HTTP calls to authz), then calls
// Store.RecordApproverAssignment, which inserts the local index row and the audit event in the
// SAME database transaction — the same grant-then-index shape as docs's share grant and
// helpdesk's member agent-bind, here granting TWO tuples per business write rather than one.

// atomicityFakeAuthz is a minimal, dedicated test double (distinct from http_test.go's own
// newFakeAuthz, which returns only *httptest.Server with no way to inspect granted relations
// afterward) — this test needs to assert on the fake's internal state AFTER the grant, to prove
// the orphan-tuple direction is real.
type atomicityFakeAuthz struct {
	mu        sync.Mutex
	relations map[string]map[string]bool // relation -> kcSub -> granted
}

func newAtomicityFakeAuthz(t *testing.T) (*httptest.Server, *atomicityFakeAuthz) {
	t.Helper()
	fa := &atomicityFakeAuthz{relations: map[string]map[string]bool{}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path != "/internal/authz/grants" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		var req grantsRequestWire
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.CompanyID == "" { // the real endpoint requires companyId
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		fa.mu.Lock()
		for _, tup := range req.Tuples {
			if fa.relations[tup.Relation] == nil {
				fa.relations[tup.Relation] = map[string]bool{}
			}
			fa.relations[tup.Relation][tup.SubjectID] = req.Op == "grant"
		}
		fa.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"status": "ok"}})
	}))
	t.Cleanup(srv.Close)
	return srv, fa
}

func (fa *atomicityFakeAuthz) granted(relation, kcSub string) bool {
	fa.mu.Lock()
	defer fa.mu.Unlock()
	return fa.relations[relation][kcSub]
}

func brokenAuditTimesheetStore(t *testing.T) *Store {
	t.Helper()
	pool := newTestPool(t)
	auditWriter, err := audit.NewWriter("audit.timesheet__does_not_exist")
	if err != nil {
		t.Fatalf("build broken audit writer: %v", err)
	}
	return NewStore(pool, auditWriter)
}

// TestRecordApproverAssignment_AuditFailureRollsBack_ButLeavesBothGrantedTuplesOrphaned proves
// the approver-assign pairing end to end: real grants (submitter + approver) against a fake
// authz server, then a Store.RecordApproverAssignment call whose own audit append fails.
func TestRecordApproverAssignment_AuditFailureRollsBack_ButLeavesBothGrantedTuplesOrphaned(t *testing.T) {
	authzSrv, fa := newAtomicityFakeAuthz(t)
	authzClient := NewAuthzClient(&http.Client{Timeout: 5 * time.Second}, authzSrv.URL)

	companyID := uuid.New()
	memberID := uuid.New()
	approverMemberID := uuid.New()
	memberKcSub, approverKcSub := "member-sub", "approver-sub"
	ctx := t.Context()

	// Step 1, exactly as handleAssignApprover's own code does it: grant BOTH tuples first.
	if err := authzClient.GrantRelation(ctx, "Bearer admin-token", companyID.String(), "submitter", memberKcSub, "corr-atomicity-1"); err != nil {
		t.Fatalf("grant submitter: %v", err)
	}
	if err := authzClient.GrantRelation(ctx, "Bearer admin-token", companyID.String(), "approver", approverKcSub, "corr-atomicity-1"); err != nil {
		t.Fatalf("grant approver: %v", err)
	}
	if !fa.granted("submitter", memberKcSub) || !fa.granted("approver", approverKcSub) {
		t.Fatal("setup: expected both tuples to be granted before the index-write step")
	}

	// Step 2: the local index-row + audit-event write, with a store whose audit append fails.
	brokenStore := brokenAuditTimesheetStore(t)
	_, err := brokenStore.RecordApproverAssignment(ctx, "admin-sub", companyID, memberID, approverMemberID, memberKcSub, approverKcSub)
	if err == nil {
		t.Fatal("expected RecordApproverAssignment to fail when the audit append fails")
	}

	// No orphan approver_assignment ROW.
	goodStore := newTestStore(t)
	assignments, _, err := goodStore.ListApproverAssignments(ctx, companyID, 1, 100)
	if err != nil {
		t.Fatalf("list approver assignments: %v", err)
	}
	for _, a := range assignments {
		if a.MemberID == memberID {
			t.Fatalf("expected NO approver_assignment row for member %s after the audit append failed, found %+v", memberID, a)
		}
	}

	// But BOTH authz TUPLES remain granted — the same powerful-but-invisible direction proven
	// for docs's share grant and helpdesk's member agent-bind, here shown to affect TWO tuples
	// per single local-write failure rather than one.
	if !fa.granted("submitter", memberKcSub) {
		t.Fatal("expected the submitter tuple to remain live (orphaned) after the local index-write failure")
	}
	if !fa.granted("approver", approverKcSub) {
		t.Fatal("expected the approver tuple to remain live (orphaned) after the local index-write failure")
	}
}
