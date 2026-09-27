// SPDX-License-Identifier: Apache-2.0

package notification

import (
	"testing"

	"github.com/google/uuid"

	"github.com/rosschiu/kiban/internal/audit"
)

// Generalizes internal/org/audit_atomicity_test.go's pattern to notification's
// send+recipient-rows pairing (Store.SendTargetedEvent). SendTargetedEvent has no separate
// external grant call to orphan — org's IsActiveMember membership confirmation happens before
// the transaction opens and is read-only, and the channel-provision + message-insert +
// recipient_state-inserts + audit-append all happen inside the same database transaction. So this
// is a pure single-transaction rollback proof: inject a failure (a broken audit writer) and prove
// nothing survives, not the channel, not the message, not any recipient row.

func brokenAuditNotificationStore(t *testing.T) *Store {
	t.Helper()
	pool := newTestPool(t)
	auditWriter, err := audit.NewWriter("audit.notification__does_not_exist")
	if err != nil {
		t.Fatalf("build broken audit writer: %v", err)
	}
	return NewStore(pool, auditWriter, testClaimGroup, NewWebhookPolicyFromEnv())
}

// TestSendTargetedEvent_AuditFailureRollsBack_NoOrphanChannelMessageOrRecipientRows proves the
// full pairing: a confirmed recipient, then a SendTargetedEvent call whose own audit append
// fails inside the transaction that also creates the channel/message/recipient rows.
func TestSendTargetedEvent_AuditFailureRollsBack_NoOrphanChannelMessageOrRecipientRows(t *testing.T) {
	companyID := uuid.New()
	checker := &fakeMembershipChecker{members: map[string]bool{"alice": true}}
	sourceModule := "atomicityproof"
	ctx := t.Context()

	brokenStore := brokenAuditNotificationStore(t)
	sent, skipped, err := brokenStore.SendTargetedEvent(ctx, checker, "actor-sub", companyID, sourceModule, "subject", "body", []string{"alice"})
	if err == nil {
		t.Fatalf("expected SendTargetedEvent to fail when the audit append fails, got sent=%d skipped=%d", sent, skipped)
	}

	goodStore := newTestStore(t)

	// No orphan CHANNEL row: the "events-<sourceModule>" channel this call would have
	// provisioned must not exist.
	var channelCount int
	if err := goodStore.pool.QueryRow(ctx,
		`SELECT count(*) FROM notification.channel WHERE company_id = $1 AND key = $2`,
		pgFromUUID(companyID), "events-"+sourceModule,
	).Scan(&channelCount); err != nil {
		t.Fatalf("count channels: %v", err)
	}
	if channelCount != 0 {
		t.Fatalf("expected NO channel row after the audit append failed, found %d", channelCount)
	}

	// No orphan MESSAGE row (and therefore no orphan recipient_state row, since recipient_state
	// is keyed by message_id via a foreign key — but check both explicitly for a direct proof
	// rather than an inferred one).
	var messageCount int
	if err := goodStore.pool.QueryRow(ctx,
		`SELECT count(*) FROM notification.message m JOIN notification.channel c ON c.id = m.channel_id
		 WHERE c.company_id = $1 AND c.key = $2`,
		pgFromUUID(companyID), "events-"+sourceModule,
	).Scan(&messageCount); err != nil {
		t.Fatalf("count messages: %v", err)
	}
	if messageCount != 0 {
		t.Fatalf("expected NO message row after the audit append failed, found %d", messageCount)
	}

	var recipientCount int
	if err := goodStore.pool.QueryRow(ctx,
		`SELECT count(*) FROM notification.recipient_state rs
		 JOIN notification.message m ON m.id = rs.message_id
		 JOIN notification.channel c ON c.id = m.channel_id
		 WHERE c.company_id = $1 AND c.key = $2 AND rs.subject = 'alice'`,
		pgFromUUID(companyID), "events-"+sourceModule,
	).Scan(&recipientCount); err != nil {
		t.Fatalf("count recipient rows: %v", err)
	}
	if recipientCount != 0 {
		t.Fatalf("expected NO recipient_state row after the audit append failed, found %d", recipientCount)
	}
}
