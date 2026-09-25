// SPDX-License-Identifier: Apache-2.0

// Golden tests for helpdesk's key audit event PAYLOAD SHAPES (keys +
// JSON value types, never values — see internal/testauditgolden's doc comment). Covers
// helpdesk.ticket.create, helpdesk.ticket.assign, helpdesk.ticket.status, helpdesk.comment.create,
// helpdesk.agent.grant, helpdesk.agent.revoke (ticket create/assign/status/comment and
// agent bind/remove). Each test drives the REAL store
// method against the live test DB, then reads the actual persisted payload back out of
// audit.helpdesk__events.
package helpdesk

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/google/uuid"

	"github.com/rosschiu/kiban/internal/testauditgolden"
)

func fetchAuditPayload(t *testing.T, store *Store, subject, action string) []byte {
	t.Helper()
	var payload []byte
	err := store.pool.QueryRow(context.Background(), `
		SELECT payload FROM audit.helpdesk__events
		WHERE subject = $1 AND action = $2
		ORDER BY occurred_at DESC LIMIT 1`, subject, action).Scan(&payload)
	if err != nil {
		t.Fatalf("fetch audit payload for subject=%s action=%s: %v", subject, action, err)
	}
	return payload
}

func assertGoldenShape(t *testing.T, name string, payload []byte) {
	t.Helper()
	shape, err := testauditgolden.Shape(payload)
	if err != nil {
		t.Fatalf("shape: %v", err)
	}
	testauditgolden.AssertGolden(t, filepath.Join("testdata", "audit_golden_"+name+".txt"), shape)
}

func TestAuditGolden_TicketCreate(t *testing.T) {
	store := newTestStore(t)
	companyID := uuid.New()
	ticket, err := store.CreateTicket(context.Background(), "alice", companyID, uuid.New(), "alice", "Title", "Description", "")
	if err != nil {
		t.Fatalf("create ticket: %v", err)
	}
	payload := fetchAuditPayload(t, store, "helpdesk_ticket:"+ticket.ID.String(), "helpdesk.ticket.create")
	assertGoldenShape(t, "ticket_create", payload)
}

func TestAuditGolden_TicketAssign(t *testing.T) {
	store := newTestStore(t)
	companyID := uuid.New()
	ticket, err := store.CreateTicket(context.Background(), "alice", companyID, uuid.New(), "alice", "Title", "Description", "")
	if err != nil {
		t.Fatalf("create ticket: %v", err)
	}
	assigneeID := uuid.New()
	if _, err := store.AssignTicket(context.Background(), "alice", companyID, ticket.ID, assigneeID, "bob"); err != nil {
		t.Fatalf("assign ticket: %v", err)
	}
	payload := fetchAuditPayload(t, store, "helpdesk_ticket:"+ticket.ID.String(), "helpdesk.ticket.assign")
	assertGoldenShape(t, "ticket_assign", payload)
}

func TestAuditGolden_TicketStatus(t *testing.T) {
	store := newTestStore(t)
	companyID := uuid.New()
	ticket, err := store.CreateTicket(context.Background(), "alice", companyID, uuid.New(), "alice", "Title", "Description", "")
	if err != nil {
		t.Fatalf("create ticket: %v", err)
	}
	if _, err := store.UpdateTicketStatus(context.Background(), "alice", companyID, ticket.ID, ticket.Status, "in_progress"); err != nil {
		t.Fatalf("update status: %v", err)
	}
	payload := fetchAuditPayload(t, store, "helpdesk_ticket:"+ticket.ID.String(), "helpdesk.ticket.status")
	assertGoldenShape(t, "ticket_status", payload)
}

func TestAuditGolden_CommentCreate(t *testing.T) {
	store := newTestStore(t)
	companyID := uuid.New()
	ticket, err := store.CreateTicket(context.Background(), "alice", companyID, uuid.New(), "alice", "Title", "Description", "")
	if err != nil {
		t.Fatalf("create ticket: %v", err)
	}
	if _, err := store.CreateComment(context.Background(), "alice", ticket.ID, "a comment", ""); err != nil {
		t.Fatalf("create comment: %v", err)
	}
	payload := fetchAuditPayload(t, store, "helpdesk_ticket:"+ticket.ID.String(), "helpdesk.comment.create")
	assertGoldenShape(t, "comment_create", payload)
}

func TestAuditGolden_AgentGrantAndRevoke(t *testing.T) {
	store := newTestStore(t)
	companyID := uuid.New()
	memberID := uuid.New()
	if _, err := store.RecordAgent(context.Background(), "alice", companyID, memberID, "bob", "alice"); err != nil {
		t.Fatalf("record agent: %v", err)
	}
	subject := "company_module:" + companyModuleObjectID(companyID.String())
	grantPayload := fetchAuditPayload(t, store, subject, "helpdesk.agent.grant")
	assertGoldenShape(t, "agent_grant", grantPayload)

	if err := store.RemoveAgent(context.Background(), "alice", companyID, memberID); err != nil {
		t.Fatalf("remove agent: %v", err)
	}
	revokePayload := fetchAuditPayload(t, store, subject, "helpdesk.agent.revoke")
	assertGoldenShape(t, "agent_revoke", revokePayload)
}
