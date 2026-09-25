// SPDX-License-Identifier: Apache-2.0

package docs

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// TestValidationError_Error covers ValidationError.Error(): other tests that produce a
// *ValidationError only type-assert it, never format it.
func TestValidationError_Error(t *testing.T) {
	err := &ValidationError{Field: "title", Message: "must be 1..200 characters"}
	got := err.Error()
	if !strings.Contains(got, "title") || !strings.Contains(got, "must be 1..200 characters") {
		t.Fatalf("Error() = %q, want it to mention the field and message", got)
	}
}

func TestStore_CreateAndGetDocument(t *testing.T) {
	store := newTestStore(t)
	companyID := uuid.New()
	docID := uuid.New()

	d, err := store.CreateDocument(context.Background(), docID, "alice", companyID, "Title", "Body", "")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if d.ID != docID || d.OwnerKcSub != "alice" {
		t.Fatalf("unexpected document: %+v", d)
	}

	got, err := store.GetDocument(context.Background(), companyID, docID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Title != "Title" || got.Body != "Body" {
		t.Fatalf("unexpected fetched document: %+v", got)
	}
}

func TestStore_CreateDocument_InvalidTitle(t *testing.T) {
	store := newTestStore(t)
	_, err := store.CreateDocument(context.Background(), uuid.New(), "alice", uuid.New(), "", "body", "")
	var verr *ValidationError
	if err == nil {
		t.Fatal("expected a ValidationError for an empty title")
	}
	if !asValidationError(err, &verr) || verr.Field != "title" {
		t.Fatalf("error = %v, want a title ValidationError", err)
	}
}

func TestStore_GetDocument_NotFound(t *testing.T) {
	store := newTestStore(t)
	_, err := store.GetDocument(context.Background(), uuid.New(), uuid.New())
	if err != ErrDocumentNotFound {
		t.Fatalf("expected ErrDocumentNotFound, got %v", err)
	}
}

func TestStore_UpdateDocument(t *testing.T) {
	store := newTestStore(t)
	companyID := uuid.New()
	docID := uuid.New()
	if _, err := store.CreateDocument(context.Background(), docID, "alice", companyID, "T1", "B1", ""); err != nil {
		t.Fatalf("create: %v", err)
	}
	updated, err := store.UpdateDocument(context.Background(), "alice", companyID, docID, "T2", "B2")
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if updated.Title != "T2" || updated.Body != "B2" {
		t.Fatalf("unexpected update result: %+v", updated)
	}
}

func TestStore_UpdateDocument_NotFound(t *testing.T) {
	store := newTestStore(t)
	_, err := store.UpdateDocument(context.Background(), "alice", uuid.New(), uuid.New(), "T", "B")
	if err != ErrDocumentNotFound {
		t.Fatalf("expected ErrDocumentNotFound, got %v", err)
	}
}

func TestStore_DeleteDocument(t *testing.T) {
	store := newTestStore(t)
	companyID := uuid.New()
	docID := uuid.New()
	if _, err := store.CreateDocument(context.Background(), docID, "alice", companyID, "T", "B", ""); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := store.DeleteDocument(context.Background(), "alice", companyID, docID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := store.GetDocument(context.Background(), companyID, docID); err != ErrDocumentNotFound {
		t.Fatalf("expected ErrDocumentNotFound after delete, got %v", err)
	}
}

func TestStore_DeleteDocument_NotFound(t *testing.T) {
	store := newTestStore(t)
	if err := store.DeleteDocument(context.Background(), "alice", uuid.New(), uuid.New()); err != ErrDocumentNotFound {
		t.Fatalf("expected ErrDocumentNotFound, got %v", err)
	}
}

func TestStore_ListOwnedDocuments(t *testing.T) {
	store := newTestStore(t)
	companyID := uuid.New()
	if _, err := store.CreateDocument(context.Background(), uuid.New(), "alice", companyID, "T1", "B1", ""); err != nil {
		t.Fatalf("create 1: %v", err)
	}
	if _, err := store.CreateDocument(context.Background(), uuid.New(), "alice", companyID, "T2", "B2", ""); err != nil {
		t.Fatalf("create 2: %v", err)
	}
	if _, err := store.CreateDocument(context.Background(), uuid.New(), "bob", companyID, "T3", "B3", ""); err != nil {
		t.Fatalf("create 3: %v", err)
	}
	owned, err := store.ListOwnedDocuments(context.Background(), companyID, "alice")
	if err != nil {
		t.Fatalf("list owned: %v", err)
	}
	if len(owned) != 2 {
		t.Fatalf("expected 2 owned documents, got %d", len(owned))
	}
}

func TestStore_ShareLifecycle(t *testing.T) {
	store := newTestStore(t)
	companyID := uuid.New()
	docID := uuid.New()
	memberID := uuid.New()
	if _, err := store.CreateDocument(context.Background(), docID, "alice", companyID, "T", "B", ""); err != nil {
		t.Fatalf("create: %v", err)
	}

	sh, err := store.RecordShare(context.Background(), "alice", companyID, docID, memberID, "viewer", "alice", "")
	if err != nil {
		t.Fatalf("record share: %v", err)
	}
	if sh.Relation != "viewer" {
		t.Fatalf("unexpected relation: %q", sh.Relation)
	}

	// Upgrade to editor — same (document_id, member_id) row, relation changes.
	upgraded, err := store.RecordShare(context.Background(), "alice", companyID, docID, memberID, "editor", "alice", "")
	if err != nil {
		t.Fatalf("upgrade share: %v", err)
	}
	if upgraded.ID != sh.ID {
		t.Fatalf("expected the SAME share row on upgrade (id %s), got a new one (id %s)", sh.ID, upgraded.ID)
	}
	if upgraded.Relation != "editor" {
		t.Fatalf("expected relation=editor after upgrade, got %q", upgraded.Relation)
	}

	shares, err := store.ListShares(context.Background(), docID)
	if err != nil {
		t.Fatalf("list shares: %v", err)
	}
	if len(shares) != 1 {
		t.Fatalf("expected exactly 1 share row after upgrade (no duplicate), got %d", len(shares))
	}

	got, err := store.GetShare(context.Background(), docID, memberID)
	if err != nil {
		t.Fatalf("get share: %v", err)
	}
	if got.Relation != "editor" {
		t.Fatalf("expected relation=editor, got %q", got.Relation)
	}

	if err := store.RemoveShare(context.Background(), "alice", companyID, docID, memberID); err != nil {
		t.Fatalf("remove share: %v", err)
	}
	if _, err := store.GetShare(context.Background(), docID, memberID); err != ErrShareNotFound {
		t.Fatalf("expected ErrShareNotFound after remove, got %v", err)
	}
}

func TestStore_RemoveShare_NotFound(t *testing.T) {
	store := newTestStore(t)
	if err := store.RemoveShare(context.Background(), "alice", uuid.New(), uuid.New(), uuid.New()); err != ErrShareNotFound {
		t.Fatalf("expected ErrShareNotFound, got %v", err)
	}
}

func TestStore_SharedDocumentIDsForMember(t *testing.T) {
	store := newTestStore(t)
	companyID := uuid.New()
	docID := uuid.New()
	memberID := uuid.New()
	if _, err := store.CreateDocument(context.Background(), docID, "alice", companyID, "T", "B", ""); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := store.RecordShare(context.Background(), "alice", companyID, docID, memberID, "viewer", "alice", ""); err != nil {
		t.Fatalf("share: %v", err)
	}
	ids, err := store.SharedDocumentIDsForMember(context.Background(), companyID, memberID)
	if err != nil {
		t.Fatalf("shared ids: %v", err)
	}
	if len(ids) != 1 || ids[0] != docID {
		t.Fatalf("expected exactly [%s], got %v", docID, ids)
	}
}

func TestStore_DocumentAndModuleAudit(t *testing.T) {
	store := newTestStore(t)
	companyID := uuid.New()
	docID := uuid.New()
	memberID := uuid.New()
	if _, err := store.CreateDocument(context.Background(), docID, "alice", companyID, "T", "B", ""); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := store.RecordShare(context.Background(), "alice", companyID, docID, memberID, "viewer", "alice", ""); err != nil {
		t.Fatalf("share: %v", err)
	}
	if err := store.RemoveShare(context.Background(), "alice", companyID, docID, memberID); err != nil {
		t.Fatalf("remove share: %v", err)
	}

	docEvents, err := store.DocumentAudit(context.Background(), docID)
	if err != nil {
		t.Fatalf("document audit: %v", err)
	}
	if len(docEvents) != 3 { // create, grant, revoke
		t.Fatalf("expected 3 document audit events, got %d: %+v", len(docEvents), docEvents)
	}

	events, total, err := store.ModuleAudit(context.Background(), companyID, 1, 100)
	if err != nil {
		t.Fatalf("module audit: %v", err)
	}
	if total != 3 || len(events) != 3 {
		t.Fatalf("expected exactly this company's 3 events, got total=%d len=%d", total, len(events))
	}
	for _, e := range events {
		if e.Payload["companyId"] != companyID.String() {
			t.Fatalf("event %s carries companyId %v, want %s", e.Action, e.Payload["companyId"], companyID)
		}
	}

	otherCompany := uuid.New()
	if _, err := store.CreateDocument(context.Background(), uuid.New(), "carol", otherCompany, "Other", "", ""); err != nil {
		t.Fatalf("create other: %v", err)
	}
	events, total, err = store.ModuleAudit(context.Background(), companyID, 1, 100)
	if err != nil {
		t.Fatalf("module audit after other company: %v", err)
	}
	if total != 3 || len(events) != 3 {
		t.Fatalf("another company's event leaked into this company's audit: total=%d len=%d", total, len(events))
	}
	if _, total, _ := store.ModuleAudit(context.Background(), uuid.New(), 1, 100); total != 0 {
		t.Fatalf("unknown company sees %d events, want 0", total)
	}
}

func TestStore_GetDocumentsByIDs_Empty(t *testing.T) {
	store := newTestStore(t)
	docs, err := store.GetDocumentsByIDs(context.Background(), uuid.New(), nil)
	if err != nil {
		t.Fatalf("get by ids: %v", err)
	}
	if docs != nil {
		t.Fatalf("expected nil for an empty id list, got %v", docs)
	}
}

func TestCheckMigrationsApplied(t *testing.T) {
	pool := newTestPool(t)
	if err := CheckMigrationsApplied(context.Background(), pool); err != nil {
		t.Fatalf("expected migrations to be applied, got %v", err)
	}
}

// asValidationError is a tiny errors.As wrapper kept local to this file (avoids importing
// "errors" into store_test.go just for this one helper — matches the module's own convention of
// small, self-contained test files).
func asValidationError(err error, target **ValidationError) bool {
	verr, ok := err.(*ValidationError)
	if !ok {
		return false
	}
	*target = verr
	return true
}
