// SPDX-License-Identifier: Apache-2.0

// Golden tests for docs's key audit event PAYLOAD SHAPES (keys + JSON
// value types, never the values — see internal/testauditgolden's own doc comment). Covers
// docs.share.grant, docs.share.revoke, docs.document.update ("edit"). Each test drives the REAL store method against the
// live test DB (same newTestStore fixture every other test in this package uses), then reads the
// actual persisted payload back out of audit.docs__events — proving the real wire shape, not a
// hand-typed guess.
package docs

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/google/uuid"

	"github.com/rosschiu/kiban/internal/testauditgolden"
)

// fetchAuditPayload reads the most recent audit.docs__events row for the given subject+action,
// returning its raw payload JSON.
func fetchAuditPayload(t *testing.T, store *Store, subject, action string) []byte {
	t.Helper()
	var payload []byte
	err := store.pool.QueryRow(context.Background(), `
		SELECT payload FROM audit.docs__events
		WHERE subject = $1 AND action = $2
		ORDER BY occurred_at DESC LIMIT 1`, subject, action).Scan(&payload)
	if err != nil {
		t.Fatalf("fetch audit payload for subject=%s action=%s: %v", subject, action, err)
	}
	return payload
}

func TestAuditGolden_ShareGrant(t *testing.T) {
	store := newTestStore(t)
	companyID := uuid.New()
	docID := uuid.New()
	memberID := uuid.New()
	if _, err := store.CreateDocument(context.Background(), docID, "alice", companyID, "T", "B", ""); err != nil {
		t.Fatalf("create document: %v", err)
	}
	if _, err := store.RecordShare(context.Background(), "alice", companyID, docID, memberID, "viewer", "alice", ""); err != nil {
		t.Fatalf("record share: %v", err)
	}
	payload := fetchAuditPayload(t, store, "docs_document:"+docID.String(), "docs.share.grant")
	shape, err := testauditgolden.Shape(payload)
	if err != nil {
		t.Fatalf("shape: %v", err)
	}
	testauditgolden.AssertGolden(t, filepath.Join("testdata", "audit_golden_share_grant.txt"), shape)
}

func TestAuditGolden_ShareRevoke(t *testing.T) {
	store := newTestStore(t)
	companyID := uuid.New()
	docID := uuid.New()
	memberID := uuid.New()
	if _, err := store.CreateDocument(context.Background(), docID, "alice", companyID, "T", "B", ""); err != nil {
		t.Fatalf("create document: %v", err)
	}
	if _, err := store.RecordShare(context.Background(), "alice", companyID, docID, memberID, "viewer", "alice", ""); err != nil {
		t.Fatalf("record share: %v", err)
	}
	if err := store.RemoveShare(context.Background(), "alice", companyID, docID, memberID); err != nil {
		t.Fatalf("remove share: %v", err)
	}
	payload := fetchAuditPayload(t, store, "docs_document:"+docID.String(), "docs.share.revoke")
	shape, err := testauditgolden.Shape(payload)
	if err != nil {
		t.Fatalf("shape: %v", err)
	}
	testauditgolden.AssertGolden(t, filepath.Join("testdata", "audit_golden_share_revoke.txt"), shape)
}

func TestAuditGolden_DocumentUpdate(t *testing.T) {
	store := newTestStore(t)
	companyID := uuid.New()
	docID := uuid.New()
	if _, err := store.CreateDocument(context.Background(), docID, "alice", companyID, "T1", "B1", ""); err != nil {
		t.Fatalf("create document: %v", err)
	}
	if _, err := store.UpdateDocument(context.Background(), "alice", companyID, docID, "T2", "B2"); err != nil {
		t.Fatalf("update document: %v", err)
	}
	payload := fetchAuditPayload(t, store, "docs_document:"+docID.String(), "docs.document.update")
	shape, err := testauditgolden.Shape(payload)
	if err != nil {
		t.Fatalf("shape: %v", err)
	}
	testauditgolden.AssertGolden(t, filepath.Join("testdata", "audit_golden_document_update.txt"), shape)
}
