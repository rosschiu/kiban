// SPDX-License-Identifier: Apache-2.0

package notification

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/rosschiu/kiban/internal/audit"
)

// TestNewStore_EmptyClaimGroupDefaultsToDefault covers NewStore's own claimGroup=="" branch (0%
// before this — every existing test passes a non-empty unique per-run claim group per
// dbtest_env_test.go's own convention). Production's cmd/main.go relies on this default when
// KIBAN_NOTIFICATION_CLAIM_GROUP is unset.
func TestNewStore_EmptyClaimGroupDefaultsToDefault(t *testing.T) {
	pool := newTestPool(t)
	auditWriter, err := audit.NewWriter("audit.notification__events")
	if err != nil {
		t.Fatalf("audit writer: %v", err)
	}
	s := NewStore(pool, auditWriter, "", NewWebhookPolicyFromEnv())
	if s.claimGroup != "default" {
		t.Fatalf("claimGroup = %q, want default", s.claimGroup)
	}
}

func TestCheckMigrationsApplied_Success(t *testing.T) {
	pool := newTestPool(t)
	if err := CheckMigrationsApplied(context.Background(), pool); err != nil {
		t.Fatalf("expected migrations applied, got: %v", err)
	}
}

func strPtr(s string) *string { return &s }

func TestCreateChannel_ValidationErrors(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	companyID := uuid.New()

	cases := []struct {
		name  string
		key   string
		label string
		kind  string
	}{
		{"bad key", "Bad Key!", "Label", "in_app"},
		{"empty label", "channel-1", "", "in_app"},
		{"bad kind", "channel-2", "Label", "sms"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := store.CreateChannel(ctx, "actor:test", companyID, tc.key, tc.label, tc.kind, nil)
			var verr *ValidationError
			if err == nil {
				t.Fatal("expected a validation error")
			}
			if !asValidationError(err, &verr) {
				t.Fatalf("expected *ValidationError, got %T: %v", err, err)
			}
		})
	}
}

func asValidationError(err error, target **ValidationError) bool {
	verr, ok := err.(*ValidationError)
	if ok {
		*target = verr
	}
	return ok
}

// TestCreateChannel_WebhookTargetRejectedBySSRFPolicy is the store-level CREATE-time
// proof: a webhook channel target resolving to a disallowed address is rejected, not persisted.
func TestCreateChannel_WebhookTargetRejectedBySSRFPolicy(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	companyID := uuid.New()

	target := "https://10.0.0.5/hook" // RFC1918 private — rejected by the default policy
	_, err := store.CreateChannel(ctx, "actor:test", companyID, "ssrf-store-test", "Label", "webhook", &target)
	var werr *WebhookPolicyError
	if !errors.As(err, &werr) {
		t.Fatalf("expected *WebhookPolicyError, got %T: %v", err, err)
	}
}

// TestCreateChannel_WebhookTargetRequired proves a webhook channel with no target is a plain
// field ValidationError, distinct from a policy rejection.
func TestCreateChannel_WebhookTargetRequired(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	companyID := uuid.New()

	_, err := store.CreateChannel(ctx, "actor:test", companyID, "no-target-chan", "Label", "webhook", nil)
	var verr *ValidationError
	if !asValidationError(err, &verr) {
		t.Fatalf("expected *ValidationError, got %T: %v", err, err)
	}
}

func TestCreateAndGetChannel(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	companyID := uuid.New()

	c, err := store.CreateChannel(ctx, "actor:admin", companyID, "billing-alerts", "Billing Alerts", "in_app", nil)
	if err != nil {
		t.Fatalf("create channel: %v", err)
	}
	if c.CompanyID != companyID || c.Key != "billing-alerts" || c.Kind != "in_app" {
		t.Fatalf("unexpected channel: %+v", c)
	}

	got, err := store.GetChannel(ctx, companyID, c.ID)
	if err != nil {
		t.Fatalf("get channel: %v", err)
	}
	if got.ID != c.ID {
		t.Fatalf("expected same channel, got %+v", got)
	}

	if _, err := store.GetChannel(ctx, companyID, uuid.New()); err != ErrChannelNotFound {
		t.Fatalf("expected ErrChannelNotFound, got %v", err)
	}
}

func TestCreateChannel_DuplicateKeyConflict(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	companyID := uuid.New()

	if _, err := store.CreateChannel(ctx, "actor:admin", companyID, "dup-key", "Label", "in_app", nil); err != nil {
		t.Fatalf("first create: %v", err)
	}
	_, err := store.CreateChannel(ctx, "actor:admin", companyID, "dup-key", "Other Label", "in_app", nil)
	if err != ErrConflict {
		t.Fatalf("expected ErrConflict, got %v", err)
	}
}

func TestListChannels_Pagination(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	companyID := uuid.New()

	for i := 0; i < 3; i++ {
		key := []string{"chan-a", "chan-b", "chan-c"}[i]
		if _, err := store.CreateChannel(ctx, "actor:admin", companyID, key, "Label", "in_app", nil); err != nil {
			t.Fatalf("create channel %d: %v", i, err)
		}
	}

	items, total, err := store.ListChannels(ctx, companyID, 1, 2)
	if err != nil {
		t.Fatalf("list channels: %v", err)
	}
	if total != 3 {
		t.Fatalf("expected total=3, got %d", total)
	}
	if len(items) != 2 {
		t.Fatalf("expected page of 2, got %d", len(items))
	}
}

func TestDeleteChannel(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	companyID := uuid.New()

	c, err := store.CreateChannel(ctx, "actor:admin", companyID, "to-delete", "Label", "in_app", nil)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := store.DeleteChannel(ctx, "actor:admin", companyID, c.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if err := store.DeleteChannel(ctx, "actor:admin", companyID, c.ID); err != ErrChannelNotFound {
		t.Fatalf("expected ErrChannelNotFound on redelete, got %v", err)
	}
}

func TestSubscribeUnsubscribe(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	companyID := uuid.New()

	c, err := store.CreateChannel(ctx, "actor:admin", companyID, "subs-test", "Label", "in_app", nil)
	if err != nil {
		t.Fatalf("create channel: %v", err)
	}

	if err := store.Subscribe(ctx, "user:alice", companyID, c.ID, "user:alice", nil); err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	// idempotent re-subscribe
	if err := store.Subscribe(ctx, "user:alice", companyID, c.ID, "user:alice", strPtr("alice@example.com")); err != nil {
		t.Fatalf("re-subscribe: %v", err)
	}
	if err := store.Unsubscribe(ctx, "user:alice", companyID, c.ID, "user:alice"); err != nil {
		t.Fatalf("unsubscribe: %v", err)
	}
	// unsubscribing something never subscribed is a no-op, not an error
	if err := store.Unsubscribe(ctx, "user:alice", companyID, c.ID, "user:alice"); err != nil {
		t.Fatalf("unsubscribe again: %v", err)
	}
}

func TestSendMessage_InAppFanOutAndInbox(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	companyID := uuid.New()

	c, err := store.CreateChannel(ctx, "actor:admin", companyID, "in-app-chan", "Label", "in_app", nil)
	if err != nil {
		t.Fatalf("create channel: %v", err)
	}
	if err := store.Subscribe(ctx, "user:alice", companyID, c.ID, "user:alice", nil); err != nil {
		t.Fatalf("subscribe alice: %v", err)
	}
	if err := store.Subscribe(ctx, "user:bob", companyID, c.ID, "user:bob", nil); err != nil {
		t.Fatalf("subscribe bob: %v", err)
	}

	m, created, err := store.SendMessage(ctx, "actor:admin", companyID, c.ID, "Hello", "World", "")
	if err != nil {
		t.Fatalf("send message: %v", err)
	}
	if !created {
		t.Fatal("expected created=true for a fresh send")
	}

	items, total, err := store.ListInbox(ctx, companyID, "user:alice", 1, 25)
	if err != nil {
		t.Fatalf("list inbox: %v", err)
	}
	if total != 1 || len(items) != 1 || items[0].ID != m.ID {
		t.Fatalf("expected alice to have exactly this message in her inbox, got total=%d items=%+v", total, items)
	}

	// mark read
	read, err := store.MarkRead(ctx, "user:alice", companyID, m.ID, "user:alice")
	if err != nil {
		t.Fatalf("mark read: %v", err)
	}
	if read.ReadAt == nil {
		t.Fatal("expected readAt to be set")
	}
	// idempotent re-mark-read
	if _, err := store.MarkRead(ctx, "user:alice", companyID, m.ID, "user:alice"); err != nil {
		t.Fatalf("re-mark read: %v", err)
	}

	// bob has an unread copy, unaffected by alice's read
	bobItems, _, err := store.ListInbox(ctx, companyID, "user:bob", 1, 25)
	if err != nil {
		t.Fatalf("list bob inbox: %v", err)
	}
	if len(bobItems) != 1 || bobItems[0].ReadAt != nil {
		t.Fatalf("expected bob's copy to still be unread, got %+v", bobItems)
	}

	// a stranger has no recipient row for this message
	if _, err := store.MarkRead(ctx, "user:eve", companyID, m.ID, "user:eve"); err != ErrRecipientNotFound {
		t.Fatalf("expected ErrRecipientNotFound for a non-subscriber, got %v", err)
	}
}

func TestSendMessage_Idempotency(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	companyID := uuid.New()

	c, err := store.CreateChannel(ctx, "actor:admin", companyID, "idem-chan", "Label", "in_app", nil)
	if err != nil {
		t.Fatalf("create channel: %v", err)
	}

	first, created1, err := store.SendMessage(ctx, "actor:admin", companyID, c.ID, "Subj", "Body", "req-1")
	if err != nil {
		t.Fatalf("first send: %v", err)
	}
	if !created1 {
		t.Fatal("expected created=true on first send")
	}

	// Replay with the IDENTICAL payload: the idempotency key is bound to the payload
	// hash, so only a same-payload reuse replays — a different payload is the conflict case
	// TestSendMessage_IdempotencyConflict proves.
	second, created2, err := store.SendMessage(ctx, "actor:admin", companyID, c.ID, "Subj", "Body", "req-1")
	if err != nil {
		t.Fatalf("replayed send: %v", err)
	}
	if created2 {
		t.Fatal("expected created=false on idempotency-key replay")
	}
	if second.ID != first.ID {
		t.Fatalf("expected the same message on replay, got %s vs %s", second.ID, first.ID)
	}
}

// TestSendMessage_IdempotencyConflict is the store-level proof: same key, DIFFERENT
// payload => ErrIdempotencyConflict, never a silent replay of the first message.
func TestSendMessage_IdempotencyConflict(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	companyID := uuid.New()

	c, err := store.CreateChannel(ctx, "actor:admin", companyID, "idem-conflict-chan", "Label", "in_app", nil)
	if err != nil {
		t.Fatalf("create channel: %v", err)
	}

	first, _, err := store.SendMessage(ctx, "actor:admin", companyID, c.ID, "Subj A", "Body A", "conflict-key")
	if err != nil {
		t.Fatalf("first send: %v", err)
	}

	_, _, err = store.SendMessage(ctx, "actor:admin", companyID, c.ID, "Subj B", "Body B", "conflict-key")
	if err != ErrIdempotencyConflict {
		t.Fatalf("expected ErrIdempotencyConflict for a payload change under the same key, got %v", err)
	}

	// the original message is untouched by the rejected conflicting attempt
	got, _, err := store.SendMessage(ctx, "actor:admin", companyID, c.ID, "Subj A", "Body A", "conflict-key")
	if err != nil {
		t.Fatalf("replay with the original payload: %v", err)
	}
	if got.ID != first.ID || got.SubjectLine != "Subj A" {
		t.Fatalf("expected the original message unchanged, got %+v", got)
	}
}

// TestSendMessage_RejectsControlCharacterSubject: a subject
// containing CR/LF — the SMTP header-injection vector buildMessage (mailer.go) has no defense
// against of its own — is rejected as a ValidationError, and nothing is written: no message row,
// no fan-out to subscriber inboxes.
func TestSendMessage_RejectsControlCharacterSubject(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	companyID := uuid.New()

	c, err := store.CreateChannel(ctx, "actor:admin", companyID, "ctl-subj-chan", "Label", "in_app", nil)
	if err != nil {
		t.Fatalf("create channel: %v", err)
	}
	if err := store.Subscribe(ctx, "user:alice", companyID, c.ID, "user:alice", nil); err != nil {
		t.Fatalf("subscribe alice: %v", err)
	}

	cases := []struct {
		name    string
		subject string
	}{
		{"CRLF header injection", "a\r\nBcc: x@y\r\n\r\ninjected"},
		{"bare LF", "a\ninjected"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := store.SendMessage(ctx, "actor:admin", companyID, c.ID, tc.subject, "Body", "")
			var verr *ValidationError
			if !asValidationError(err, &verr) {
				t.Fatalf("expected *ValidationError, got %T: %v", err, err)
			}
			if verr.Field != "subjectLine" {
				t.Fatalf("expected ValidationError on field subjectLine, got %q", verr.Field)
			}
		})
	}

	// nothing was written by either rejected attempt
	items, total, err := store.ListInbox(ctx, companyID, "user:alice", 1, 25)
	if err != nil {
		t.Fatalf("list inbox: %v", err)
	}
	if total != 0 || len(items) != 0 {
		t.Fatalf("expected no messages written after rejected subjects, got total=%d items=%+v", total, items)
	}
}

func TestSendMessage_EmailAndWebhookEnqueueDeliveryJobs(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	companyID := uuid.New()

	emailChan, err := store.CreateChannel(ctx, "actor:admin", companyID, "email-chan", "Label", "email", nil)
	if err != nil {
		t.Fatalf("create email channel: %v", err)
	}
	deleteChannelCascade(t, store, emailChan.ID)
	if err := store.Subscribe(ctx, "user:alice", companyID, emailChan.ID, "user:alice", strPtr("alice@example.com")); err != nil {
		t.Fatalf("subscribe with email: %v", err)
	}
	if _, _, err := store.SendMessage(ctx, "actor:admin", companyID, emailChan.ID, "Subj", "Body", ""); err != nil {
		t.Fatalf("send to email channel: %v", err)
	}

	target := "https://203.0.113.10/inbound" // RFC 5737 TEST-NET-3: not private/loopback/link-local, passes the SSRF policy with no real network access
	webhookChan, err := store.CreateChannel(ctx, "actor:admin", companyID, "webhook-chan", "Label", "webhook", &target)
	if err != nil {
		t.Fatalf("create webhook channel: %v", err)
	}
	deleteChannelCascade(t, store, webhookChan.ID)
	if _, _, err := store.SendMessage(ctx, "actor:admin", companyID, webhookChan.ID, "Subj", "Body", ""); err != nil {
		t.Fatalf("send to webhook channel: %v", err)
	}

	jobs, err := store.ClaimJobs(ctx, 30*time.Second, 10)
	if err != nil {
		t.Fatalf("claim jobs: %v", err)
	}
	var sawEmail, sawWebhook bool
	for _, j := range jobs {
		if j.Kind == "email" && j.Target == "alice@example.com" {
			sawEmail = true
		}
		if j.Kind == "webhook" && j.Target == target {
			sawWebhook = true
		}
	}
	if !sawEmail {
		t.Errorf("expected an email delivery job for alice, got %+v", jobs)
	}
	if !sawWebhook {
		t.Errorf("expected a webhook delivery job for the channel target, got %+v", jobs)
	}
}

// TestValidationError_Error covers ValidationError.Error() (TestCreateChannel_ValidationErrors
// above only ever type-asserts the error, never formats it).
func TestValidationError_Error(t *testing.T) {
	err := &ValidationError{Field: "kind", Message: "must be one of in_app, email, webhook"}
	got := err.Error()
	if !strings.Contains(got, "kind") || !strings.Contains(got, "must be one of in_app, email, webhook") {
		t.Fatalf("Error() = %q, want it to mention the field and message", got)
	}
}

// TestStore_Pool_ReturnsUnderlyingPool and TestNewStore_WebhookPolicyOverridesEnvDefault cover
// Store.Pool() and NewStore's webhook policy directly (every other test reaches the pool/policy
// only indirectly, through methods that use them internally).
func TestStore_Pool_ReturnsUnderlyingPool(t *testing.T) {
	pool := newTestPool(t)
	auditWriter, err := audit.NewWriter("audit.notification__events")
	if err != nil {
		t.Fatalf("audit writer: %v", err)
	}
	store := NewStore(pool, auditWriter, testClaimGroup, NewWebhookPolicyFromEnv())
	if store.Pool() != pool {
		t.Fatal("Pool() did not return the exact pool NewStore was given")
	}
}

func TestNewStore_WebhookPolicyOverridesEnvDefault(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	companyID := uuid.New()

	// The default env policy (no KIBAN_WEBHOOK_ALLOW_HTTP/ALLOWED_HOSTS set in this test binary)
	// rejects http scheme outright — proves the injected policy actually takes effect by
	// flipping that same channel-create call from rejected to accepted.
	target := "http://allowed.example.invalid/hook"
	_, err := store.CreateChannel(ctx, "actor:test", companyID, "policy-override-rejected", "Label", "webhook", &target)
	var werrBefore *WebhookPolicyError
	if !errors.As(err, &werrBefore) {
		t.Fatalf("expected the env-default policy to reject http scheme, got %T: %v", err, err)
	}

	store = NewStore(store.pool, store.audit, testClaimGroup, &WebhookPolicy{
		AllowHTTP:    true,
		AllowedHosts: map[string]struct{}{"allowed.example.invalid": {}},
		Resolver: &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			return nil, errors.New("dbtest: DNS dial not implemented in this fake resolver")
		}},
	})
	// A custom Resolver with no working Dial can't actually resolve — this override still proves
	// the field took effect (scheme/allowlist checks, which run before DNS resolution, now pass;
	// the call fails later at DNS resolution instead of the earlier "policy-rejected" error the
	// env-default policy above produced).
	_, err = store.CreateChannel(ctx, "actor:test", companyID, "policy-override-accepted", "Label", "webhook", &target)
	var werrAfter *WebhookPolicyError
	if !errors.As(err, &werrAfter) {
		t.Fatalf("expected a *WebhookPolicyError (DNS resolution failure), got %T: %v", err, err)
	}
	if werrBefore.Message == werrAfter.Message {
		t.Fatalf("expected a DIFFERENT rejection reason with the injected policy (scheme rejection before, DNS failure after), got the same: %q", werrAfter.Message)
	}
}
