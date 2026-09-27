// SPDX-License-Identifier: Apache-2.0

// Golden tests for notification's key audit event PAYLOAD SHAPES (keys + JSON value types, never
// values — see internal/testauditgolden's doc comment). Covers notification.channel.create and
// notification.message.send. Each test drives the REAL store method against the live test DB, then
// reads the actual persisted payload back out of audit.notification__events.
package notification

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
		SELECT payload FROM audit.notification__events
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

func TestAuditGolden_ChannelCreate(t *testing.T) {
	store := newTestStore(t)
	companyID := uuid.New()
	ch, err := store.CreateChannel(context.Background(), "alice", companyID, "inbox-"+companyID.String(), "Inbox", "in_app", nil)
	if err != nil {
		t.Fatalf("create channel: %v", err)
	}
	payload := fetchAuditPayload(t, store, "notification_channel:"+ch.ID.String(), "notification.channel.create")
	assertGoldenShape(t, "channel_create", payload)
}

func TestAuditGolden_MessageSend(t *testing.T) {
	store := newTestStore(t)
	companyID := uuid.New()
	ch, err := store.CreateChannel(context.Background(), "alice", companyID, "inbox-"+companyID.String(), "Inbox", "in_app", nil)
	if err != nil {
		t.Fatalf("create channel: %v", err)
	}
	if _, _, err := store.SendMessage(context.Background(), "alice", companyID, ch.ID, "Subject", "Body", ""); err != nil {
		t.Fatalf("send message: %v", err)
	}
	payload := fetchAuditPayload(t, store, "notification_channel:"+ch.ID.String(), "notification.message.send")
	assertGoldenShape(t, "message_send", payload)
}
