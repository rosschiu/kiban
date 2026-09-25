// SPDX-License-Identifier: Apache-2.0

package docs

import (
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/rosschiu/kiban/internal/audit"
)

// Applies internal/org/audit_atomicity_test.go's pattern (a broken audit writer targeting a
// syntactically valid but non-existent table forces a real driver error, not a mock) to docs's own grant+business-write pairing: handleCreateShare
// grants the authz tuple FIRST (a real, separate HTTP call to authz — already committed,
// unrecoverable from this module's own transaction), then calls Store.RecordShare, which inserts
// the local index row AND the audit event in the SAME database transaction.
//
// This module's actual code (http.go's handleCreateShare, store.go's RecordShare doc comment:
// "Caller MUST have already granted... before calling this") is GRANT-then-INDEX, for both
// document creation (handleCreateDocument) and share creation.
//
// The failure direction this ordering produces is POWERFUL-BUT-INVISIBLE: if the local
// insert-index-row+audit transaction fails AFTER the authz grant already succeeded, the grant is
// NOT (and structurally cannot be, from a single-module transaction) rolled back — the member
// has real access via the engine that no local row or audit event reflects. The test below
// proves BOTH halves of that explicitly: the local row never orphans forward (rollback proven,
// same as every org atomicity test), and the tuple remains live (proving the orphan-tuple
// direction is real, not hypothetical).

func brokenAuditDocsStore(t *testing.T) *Store {
	t.Helper()
	pool := newTestPool(t)
	auditWriter, err := audit.NewWriter("audit.docs__does_not_exist")
	if err != nil {
		t.Fatalf("build broken audit writer: %v", err)
	}
	return NewStore(pool, auditWriter)
}

// TestRecordShare_AuditFailureRollsBack_ButLeavesTheGrantedTupleOrphaned proves the pairing
// above end to end: a real grant against a fake authz server, then a Store.RecordShare call
// whose own audit append fails.
func TestRecordShare_AuditFailureRollsBack_ButLeavesTheGrantedTupleOrphaned(t *testing.T) {
	fa := newFakeAuthz(map[string]bool{"alice": true}, nil)
	authzSrv := fa.server(t)
	authzClient := NewAuthzClient(&http.Client{Timeout: 5 * time.Second}, authzSrv.URL)

	docID := uuid.New()
	memberID := uuid.New()
	ctx := t.Context()

	// Step 1, exactly as handleCreateShare's own code does it: grant the tuple FIRST, via a
	// real (fake-server-backed) AuthzClient call — this is the "already committed, can't be
	// undone by this module's own DB transaction" half of the pairing.
	if err := authzClient.GrantShare(ctx, "Bearer alice-token", uuid.New().String(), docID.String(), "viewer", "bob", "corr-atomicity-1"); err != nil {
		t.Fatalf("grant share: %v", err)
	}
	if !fa.hasDirect("docs_document", docID.String(), "viewer", "user:bob") {
		t.Fatal("setup: expected the tuple to be granted before the index-write step")
	}

	// Step 2: the local index-row + audit-event write, with a store whose audit append is
	// GUARANTEED to fail (broken audit writer, same technique as internal/org's own
	// audit_atomicity_test.go).
	brokenStore := brokenAuditDocsStore(t)
	_, err := brokenStore.RecordShare(ctx, "alice", uuid.New(), docID, memberID, "viewer", "bob", "")
	if err == nil {
		t.Fatal("expected RecordShare to fail when the audit append fails")
	}

	// No orphan share ROW: the local insert+audit transaction rolled back cleanly, same
	// guarantee every org atomicity test proves.
	goodStore := newTestStore(t)
	if _, err := goodStore.GetShare(ctx, docID, memberID); err == nil {
		t.Fatal("expected NO share row to exist after the audit append failed — the local transaction must have rolled back")
	} else if err != ErrShareNotFound {
		t.Fatalf("GetShare: unexpected error %v, want ErrShareNotFound", err)
	}

	// But the authz TUPLE remains granted — it was never, and structurally could never be,
	// rolled back by this module's own local transaction failing. This is the "powerful but
	// invisible" direction: real access via the engine, with no local index row or audit event
	// to show for it. Proving this is real production behavior, not a hypothetical, is the
	// point of this test.
	if !fa.hasDirect("docs_document", docID.String(), "viewer", "user:bob") {
		t.Fatal("expected the previously-granted tuple to remain live (orphaned) after the local index-write failure — this is the actual, unmitigated production behavior")
	}
}
