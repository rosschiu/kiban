// SPDX-License-Identifier: Apache-2.0

package notification

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// TestNewWebhookSender_* and TestNoWebhookRedirects_* are direct unit tests for webhook.go, which
// is otherwise exercised only end to end via webhook_live_test.go's -tags live suite (see that
// file's own doc comment for why it doesn't run in the default suite).
func TestNewWebhookSender_NilPolicyDefaultsToEnv(t *testing.T) {
	s := NewWebhookSender(nil, "secret")
	if s.Policy == nil {
		t.Fatal("expected NewWebhookSender(nil, ...) to default Policy to NewWebhookPolicyFromEnv()")
	}
	if s.HMACSecret != "secret" {
		t.Fatalf("HMACSecret = %q, want %q", s.HMACSecret, "secret")
	}
	if s.Timeout != webhookDialTimeout {
		t.Fatalf("Timeout = %s, want webhookDialTimeout (%s)", s.Timeout, webhookDialTimeout)
	}
}

func TestNewWebhookSender_ExplicitPolicyPreserved(t *testing.T) {
	p := &WebhookPolicy{AllowHTTP: true}
	s := NewWebhookSender(p, "secret")
	if s.Policy != p {
		t.Fatal("expected NewWebhookSender to keep the explicitly-given policy, not replace it")
	}
}

func TestNoWebhookRedirects_AlwaysErrors(t *testing.T) {
	if err := noWebhookRedirects(nil, nil); err == nil {
		t.Fatal("expected noWebhookRedirects to always return an error (no redirects followed)")
	}
}

// TestWebhookSender_Deliver_PolicyRejectionIsNonRetryable is the delivery-time SSRF
// re-check, exercised at the WebhookSender.Deliver boundary (store_test.go/webhook_policy_test.go
// already cover WebhookPolicy.Validate itself directly; this proves Deliver wraps a rejection in
// ErrNonRetryableDelivery, the signal worker.go's failJob uses to mark a job dead instead of
// retrying it) — cheap and deterministic: no server needed, the default env policy rejects a
// private-IP target before any network call is attempted.
func TestWebhookSender_Deliver_PolicyRejectionIsNonRetryable(t *testing.T) {
	s := NewWebhookSender(&WebhookPolicy{}, "secret") // default policy: https-only, no allowlist
	d := JobDelivery{
		Job:         DeliveryJob{MessageID: uuid.New(), Target: "http://10.0.0.5/hook"}, // http scheme rejected outright
		SubjectLine: "Subj",
		Body:        "Body",
	}
	err := s.Deliver(context.Background(), d)
	if err == nil {
		t.Fatal("expected Deliver to reject a policy-disallowed target")
	}
	if !errors.Is(err, ErrNonRetryableDelivery) {
		t.Fatalf("expected err to wrap ErrNonRetryableDelivery, got: %v", err)
	}
}

// TestWebhookSender_BuildWebhookRequest_DeliveryIDHeaderStableAcrossAttempts proves the
// X-Kiban-Delivery-Id header carries the delivery job's own row id (stable
// across retries and crash-reclaims — FailJob/ClaimJobs never change a job's id), so building
// the request twice for the "same job" (same Job.ID, as a retry or a reclaim would present)
// yields the identical header value both times. buildWebhookRequest is exercised directly
// (rather than through Deliver, which requires Policy.Validate to approve the target first) —
// the default WebhookPolicy always rejects loopback/private addresses, so a real httptest.Server
// can't be reached this way without weakening the SSRF guard.
func TestWebhookSender_BuildWebhookRequest_DeliveryIDHeaderStableAcrossAttempts(t *testing.T) {
	jobID := uuid.New()
	s := NewWebhookSender(&WebhookPolicy{}, "secret")
	d := JobDelivery{
		Job:         DeliveryJob{ID: jobID, MessageID: uuid.New(), Target: "https://example.com/hook", Attempts: 1},
		SubjectLine: "Subj",
		Body:        "Body",
	}

	req1, err := s.buildWebhookRequest(context.Background(), d)
	if err != nil {
		t.Fatalf("buildWebhookRequest (attempt 1): %v", err)
	}
	got1 := req1.Header.Get("X-Kiban-Delivery-Id")
	if got1 == "" {
		t.Fatal("expected X-Kiban-Delivery-Id to be set")
	}
	if got1 != jobID.String() {
		t.Fatalf("X-Kiban-Delivery-Id = %q, want the job id %q", got1, jobID.String())
	}

	// Simulate a redelivery of the SAME job (retry after FailJob, or a crash-reclaim): the id
	// never changes, only bookkeeping fields like Attempts do.
	d.Job.Attempts = 2
	req2, err := s.buildWebhookRequest(context.Background(), d)
	if err != nil {
		t.Fatalf("buildWebhookRequest (attempt 2): %v", err)
	}
	got2 := req2.Header.Get("X-Kiban-Delivery-Id")
	if got2 != got1 {
		t.Fatalf("X-Kiban-Delivery-Id changed across attempts for the same job: %q != %q", got2, got1)
	}

	// A genuinely different job gets a different key — the header is per-job, not constant.
	other := d
	other.Job.ID = uuid.New()
	reqOther, err := s.buildWebhookRequest(context.Background(), other)
	if err != nil {
		t.Fatalf("buildWebhookRequest (other job): %v", err)
	}
	if got := reqOther.Header.Get("X-Kiban-Delivery-Id"); got == got1 {
		t.Fatalf("expected a different job to get a different X-Kiban-Delivery-Id, both were %q", got)
	}
}

// TestWebhookSender_Post_ReusesOneTransport: 50 deliveries over the sender's single
// transport to a keep-alive server leave goroutine and fd counts flat (a per-delivery transport
// leaked 2 fds + 3 goroutines each).
func TestWebhookSender_Post_ReusesOneTransport(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	target := ResolvedWebhookTarget{URL: u, Port: u.Port(), IPs: []netip.Addr{netip.MustParseAddr("127.0.0.1")}}
	s := NewWebhookSender(&WebhookPolicy{}, "secret")
	d := JobDelivery{Job: DeliveryJob{ID: uuid.New(), MessageID: uuid.New(), Target: srv.URL + "/hook"}, SubjectLine: "s", Body: "b"}

	post := func() {
		if err := s.post(context.Background(), target, d); err != nil {
			t.Fatalf("post: %v", err)
		}
	}
	post() // warm: the one keep-alive connection and its two loop goroutines
	settle := func() { time.Sleep(50 * time.Millisecond); runtime.GC() }
	settle()
	goroutinesBefore, fdsBefore := runtime.NumGoroutine(), openFDs(t)

	for i := 0; i < 50; i++ {
		post()
	}
	settle()
	goroutinesAfter, fdsAfter := runtime.NumGoroutine(), openFDs(t)

	if goroutinesAfter > goroutinesBefore+2 {
		t.Fatalf("goroutines grew %d -> %d over 50 deliveries", goroutinesBefore, goroutinesAfter)
	}
	if fdsAfter > fdsBefore+2 {
		t.Fatalf("open fds grew %d -> %d over 50 deliveries", fdsBefore, fdsAfter)
	}
}

// openFDs counts this process's open file descriptors (Linux /proc; skipped elsewhere).
func openFDs(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Skipf("/proc/self/fd unavailable: %v", err)
	}
	return len(entries)
}

// TestWebhookSender_Post_RefusesWithoutTransport: a sender built as a bare struct literal never
// falls through to http.DefaultTransport (whose own DNS lookup would bypass the pin).
func TestWebhookSender_Post_RefusesWithoutTransport(t *testing.T) {
	s := &WebhookSender{Policy: &WebhookPolicy{}, HMACSecret: "x"}
	err := s.post(context.Background(), ResolvedWebhookTarget{Port: "1"}, JobDelivery{Job: DeliveryJob{Target: "https://203.0.113.10/x"}})
	if err == nil || !strings.Contains(err.Error(), "no transport") {
		t.Fatalf("err = %v, want the no-transport refusal", err)
	}
}
