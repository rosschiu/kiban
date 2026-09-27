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
)

// blackholeListener accepts a TCP connection and then never sends or reads anything — simulating
// a hung/firewalled SMTP server so the test can prove Deliver's dial+conversation deadline fires
// instead of blocking forever (net/smtp.SendMail has no timeout of its own).
func blackholeListener(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			// Accept and hold the connection open, never writing the SMTP greeting the client is
			// waiting to read — this is what makes it "hung" from the client's point of view.
			t.Cleanup(func() { _ = conn.Close() })
		}
	}()
	return ln.Addr().String()
}

func TestMailer_Deliver_TimesOutOnHungServer(t *testing.T) {
	addr := blackholeListener(t)
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split host port: %v", err)
	}

	m := &Mailer{Host: host, Port: port, From: "notification@kiban.local", Timeout: 200 * time.Millisecond}
	d := JobDelivery{Job: DeliveryJob{MessageID: uuid.New(), Target: "someone@example.com"}, SubjectLine: "Subj", Body: "Body"}

	start := time.Now()
	err = m.Deliver(context.Background(), d)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected Deliver to fail against a hung server")
	}
	if elapsed > 2*time.Second {
		t.Fatalf("expected Deliver to respect its ~200ms Timeout, took %s", elapsed)
	}
}

func TestMailer_Deliver_DialFailureIsFast(t *testing.T) {
	// Port 0 on an address with nothing listening should refuse the connection quickly rather
	// than hang — a basic sanity check that Deliver doesn't introduce its own unbounded wait on
	// the ordinary "nobody's listening" path.
	m := &Mailer{Host: "127.0.0.1", Port: "1", From: "notification@kiban.local", Timeout: 2 * time.Second}
	d := JobDelivery{Job: DeliveryJob{MessageID: uuid.New(), Target: "someone@example.com"}, SubjectLine: "Subj", Body: "Body"}

	start := time.Now()
	err := m.Deliver(context.Background(), d)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected Deliver to fail with nothing listening")
	}
	if elapsed > 2*time.Second {
		t.Fatalf("expected a fast connection-refused failure, took %s", elapsed)
	}
}

func TestMailer_Deliver_ContextCancelled(t *testing.T) {
	addr := blackholeListener(t)
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split host port: %v", err)
	}

	m := &Mailer{Host: host, Port: port, From: "notification@kiban.local", Timeout: 10 * time.Second}
	d := JobDelivery{Job: DeliveryJob{MessageID: uuid.New(), Target: "someone@example.com"}, SubjectLine: "Subj", Body: "Body"}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	start := time.Now()
	err = m.Deliver(ctx, d)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected Deliver to fail when ctx is cancelled before the (longer) Timeout")
	}
	// The connection deadline and the context deadline are the same instant; the connection
	// can time out a few microseconds before the context's timer fires, so wait for it.
	<-ctx.Done()
	if !errors.Is(ctx.Err(), context.DeadlineExceeded) {
		t.Fatalf("expected ctx to have exceeded its deadline, got %v", ctx.Err())
	}
	if elapsed > 2*time.Second {
		t.Fatalf("expected Deliver to respect the shorter ctx deadline, took %s", elapsed)
	}
}

// TestMailer_BuildMessage_CRLFSubjectHeaderInjection guards SMTP header injection: a CRLF subject
// fed straight into buildMessage would terminate the header block early and push the Message-Id
// header into the body.
//
// The defense is NOT in buildMessage — subjectLine has exactly one entry point, SendMessage's
// validation, so that's where a hostile subject is rejected. buildMessage itself is intentionally
// left with no sanitizer of its own: a caller that reaches it with a raw, unvalidated subject
// cannot exist. So this test asserts at the validation layer: the same hostile subject never
// reaches buildMessage at all. TestMailer_BuildMessage_MessageIDHeaderStableAcrossAttempts (above)
// is the buildMessage-level assertion that a validator-admitted subject keeps Message-Id in the
// header block.
func TestMailer_BuildMessage_CRLFSubjectHeaderInjection(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	companyID := uuid.New()

	c, err := store.CreateChannel(ctx, "actor:admin", companyID, "crlf-subj-chan", "Label", "in_app", nil)
	if err != nil {
		t.Fatalf("create channel: %v", err)
	}

	hostileSubjects := []string{
		"a\r\nBcc: x@y\r\n\r\ninjected",
		"a\ninjected",
	}
	for _, subj := range hostileSubjects {
		_, _, err := store.SendMessage(ctx, "actor:admin", companyID, c.ID, subj, "Body", "")
		var verr *ValidationError
		if !asValidationError(err, &verr) {
			t.Fatalf("subject %q: expected *ValidationError (rejected before reaching buildMessage), got %T: %v", subj, err, err)
		}
		if verr.Field != "subjectLine" {
			t.Fatalf("subject %q: expected ValidationError on field subjectLine, got %q", subj, verr.Field)
		}
	}
}

// TestNewMailer covers NewMailer (every other test in this file builds a &Mailer{} literal
// directly to control Timeout precisely).
func TestNewMailer(t *testing.T) {
	m := NewMailer("mailpit", "1025", "notification@kiban.local")
	if m.Host != "mailpit" || m.Port != "1025" || m.From != "notification@kiban.local" {
		t.Fatalf("NewMailer did not set fields verbatim: %+v", m)
	}
	if m.Timeout != defaultSMTPTimeout {
		t.Fatalf("NewMailer: Timeout = %s, want defaultSMTPTimeout (%s)", m.Timeout, defaultSMTPTimeout)
	}
}

// TestMailer_BuildMessage_MessageIDHeaderStableAcrossAttempts is the SMTP-side proof,
// mirroring webhook_test.go's X-Kiban-Delivery-Id test: the Message-Id header is keyed on the
// delivery job's own row id, so building the message twice for the "same job" (same Job.ID, as a
// retry or crash-reclaim would present) yields the identical header both times, and a genuinely
// different job gets a different one.
func TestMailer_BuildMessage_MessageIDHeaderStableAcrossAttempts(t *testing.T) {
	jobID := uuid.New()
	m := &Mailer{Host: "mailpit", Port: "1025", From: "notification@kiban.local"}
	d := JobDelivery{
		Job:         DeliveryJob{ID: jobID, MessageID: uuid.New(), Target: "someone@example.com", Attempts: 1},
		SubjectLine: "Subj",
		Body:        "Body",
	}

	want := "Message-Id: <" + jobID.String() + "@kiban.notification>"

	msg1 := m.buildMessage(d)
	if !strings.Contains(msg1, want) {
		t.Fatalf("buildMessage (attempt 1) = %q, want it to contain %q", msg1, want)
	}

	// Simulate a redelivery of the SAME job: the id never changes, only bookkeeping fields like
	// Attempts do.
	d.Job.Attempts = 2
	msg2 := m.buildMessage(d)
	if !strings.Contains(msg2, want) {
		t.Fatalf("buildMessage (attempt 2) = %q, want it to still contain %q", msg2, want)
	}

	// A genuinely different job gets a different Message-Id.
	other := d
	other.Job.ID = uuid.New()
	msg3 := m.buildMessage(other)
	if strings.Contains(msg3, want) {
		t.Fatalf("expected a different job to get a different Message-Id, got %q again in %q", want, msg3)
	}
}
