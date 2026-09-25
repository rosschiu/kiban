// SPDX-License-Identifier: Apache-2.0

package helpdesk

import (
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/rosschiu/kiban/internal/audit"
)

// Applies internal/org/audit_atomicity_test.go's pattern to helpdesk's two grant+business-write
// pairings: agent bind (the
// MEMBER path specifically — http.go's handleMakeMemberAgent grants the authz `editor` tuple
// FIRST, then calls Store.RecordAgent, exactly the same grant-then-index ordering as
// modules/docs/service's handleCreateShare, confirmed here rather than assumed) and ticket
// assign (Store.AssignTicket, a pure local update+audit with no external call of its own — the
// grant, if any was needed, already happened earlier via the auto-agent-grant step).
//
// Contrast (not itself tested here): helpdesk's POSITION/GROUP agent-bind paths
// (RecordAgentForPosition/RecordAgentForGroup) are the OPPOSITE ordering — index-first-then-grant, with http.go's
// handleMakePositionAgent/handleMakeGroupAgent compensating (deleting the just-inserted row) if
// the subsequent grant fails, per store.go's own doc comments on those two functions
// ("visible-but-powerless, never powerful-but-invisible"). So within this ONE module, the
// MEMBER agent-bind path is powerful-but-invisible-on-failure while the POSITION/GROUP paths are
// visible-but-powerless-on-failure (and self-healing) — two different fail-safe directions
// coexisting deliberately, not a bug.

func brokenAuditHelpdeskStore(t *testing.T) *Store {
	t.Helper()
	pool := newTestPool(t)
	auditWriter, err := audit.NewWriter("audit.helpdesk__does_not_exist")
	if err != nil {
		t.Fatalf("build broken audit writer: %v", err)
	}
	return NewStore(pool, auditWriter)
}

// TestRecordAgent_AuditFailureRollsBack_ButLeavesTheGrantedTupleOrphaned proves the MEMBER
// agent-bind pairing: a real grant against a fake authz server, then a Store.RecordAgent call
// whose own audit append fails.
func TestRecordAgent_AuditFailureRollsBack_ButLeavesTheGrantedTupleOrphaned(t *testing.T) {
	fa := newFakeAuthz(map[string]bool{"alice": true}, nil)
	authzSrv := fa.server(t)
	authzClient := NewAuthzClient(&http.Client{Timeout: 5 * time.Second}, authzSrv.URL)

	companyID := uuid.New()
	memberID := uuid.New()
	ctx := t.Context()

	// Step 1, exactly as handleMakeMemberAgent's own code does it: grant the `editor` tuple
	// FIRST, via a real (fake-server-backed) AuthzClient call.
	if err := authzClient.GrantAgent(ctx, "Bearer alice-token", companyID.String(), "bob", "corr-atomicity-1"); err != nil {
		t.Fatalf("grant agent: %v", err)
	}
	if !fa.agents["bob"] {
		t.Fatal("setup: expected the tuple to be granted before the index-write step")
	}

	// Step 2: the local index-row + audit-event write, with a store whose audit append is
	// guaranteed to fail.
	brokenStore := brokenAuditHelpdeskStore(t)
	_, err := brokenStore.RecordAgent(ctx, "alice", companyID, memberID, "bob", "alice")
	if err == nil {
		t.Fatal("expected RecordAgent to fail when the audit append fails")
	}

	// No orphan agent ROW: the local insert+audit transaction rolled back cleanly.
	goodStore := newTestStore(t)
	if _, err := goodStore.GetAgent(ctx, companyID, memberID); err != ErrAgentNotFound {
		t.Fatalf("GetAgent: got err=%v, want ErrAgentNotFound (no orphan row)", err)
	}

	// But the authz TUPLE remains granted — the same powerful-but-invisible direction proven
	// for docs's share grant, here confirmed for helpdesk's member agent-bind path too.
	if !fa.agents["bob"] {
		t.Fatal("expected the previously-granted tuple to remain live (orphaned) after the local index-write failure")
	}
}

// TestAssignTicket_AuditFailureRollsBack proves the ticket-assign half: AssignTicket has no
// external call of its own (the grant, if the assignee wasn't already an agent, already
// happened via a separate, earlier RecordAgent step) — so this is a pure single-transaction
// rollback proof, same shape as every internal/org atomicity test.
func TestAssignTicket_AuditFailureRollsBack(t *testing.T) {
	goodStore := newTestStore(t)
	ctx := t.Context()

	companyID := uuid.New()
	reporterID := uuid.New()
	ticket, err := goodStore.CreateTicket(ctx, "reporter-sub", companyID, reporterID, "reporter-sub", "broken printer", "it's broken", "")
	if err != nil {
		t.Fatalf("create ticket: %v", err)
	}

	assigneeID := uuid.New()
	brokenStore := brokenAuditHelpdeskStore(t)
	_, err = brokenStore.AssignTicket(ctx, "admin-sub", companyID, ticket.ID, assigneeID, "assignee-sub")
	if err == nil {
		t.Fatal("expected AssignTicket to fail when the audit append fails")
	}

	got, err := goodStore.GetTicket(ctx, companyID, ticket.ID)
	if err != nil {
		t.Fatalf("get ticket: %v", err)
	}
	if got.AssigneeMemberID != nil {
		t.Fatalf("expected the ticket to remain UNASSIGNED when the audit append failed, got assigneeMemberId=%v", got.AssigneeMemberID)
	}
}
