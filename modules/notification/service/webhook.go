// SPDX-License-Identifier: Apache-2.0

package notification

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"
)

// ErrNonRetryableDelivery marks a delivery failure the worker must never retry — currently only
// a delivery-time WebhookPolicy rejection (retrying a target the policy just rejected can never
// succeed). Wrapped (errors.Is still matches) so the worker can distinguish it
// from an ordinary transient delivery error without either side needing to know the concrete
// error type.
var ErrNonRetryableDelivery = errors.New("notification: non-retryable delivery failure")

// deliveryIDHeader carries the stable per-job idempotency key on outbound webhook POSTs —
// receivers dedupe on this header.
const deliveryIDHeader = "X-Kiban-Delivery-Id"

// noWebhookRedirects rejects every redirect (no redirect following) — an attacker-controlled 3xx
// could otherwise redirect a
// validated https target to an internal address after Validate already approved the original
// host.
func noWebhookRedirects(*http.Request, []*http.Request) error {
	return errors.New("notification: webhook redirects are not followed")
}

// WebhookSender delivers a job via a signed HTTP POST. The signature is HMAC-SHA256 over the raw
// JSON body, hex-encoded, in
// X-Notification-Signature — a receiver verifies by recomputing over the exact bytes received.
//
// Every delivery re-validates the target through Policy (DNS can change between
// channel-create time and delivery time, and between one delivery attempt and the next, so the
// CREATE-time check alone is not enough) and dials only the IPs that validation just approved
// (pinnedDialContext) — never the transport's own independent DNS lookup, which would reopen the
// rebinding window Validate just closed.
//
// One http.Transport per sender (built by NewWebhookSender, reused by every Deliver): a fresh
// transport per delivery leaked its keep-alive connection and loop goroutines until the remote
// closed them. The per-delivery pin survives the sharing: Deliver stores the validated target in
// the request context and the transport's single DialContext dials only that target's IPs. A
// pooled idle connection is one a previous delivery dialed to an address the policy approved
// then; it is never re-resolved, and a target the policy now rejects never reaches the transport.
type WebhookSender struct {
	Policy     *WebhookPolicy
	HMACSecret string
	Timeout    time.Duration

	transport *http.Transport
}

// pinnedTargetKey carries the ResolvedWebhookTarget from Deliver to the shared transport's
// DialContext through the request context.
type pinnedTargetKey struct{}

// NewWebhookSender builds a sender bound to policy (nil = NewWebhookPolicyFromEnv, the
// production default).
func NewWebhookSender(policy *WebhookPolicy, hmacSecret string) *WebhookSender {
	if policy == nil {
		policy = NewWebhookPolicyFromEnv()
	}
	return &WebhookSender{Policy: policy, HMACSecret: hmacSecret, Timeout: webhookDialTimeout, transport: newWebhookTransport()}
}

// newWebhookTransport is the sender's single transport: every dial goes through the
// context-pinned dialer, and idle keep-alive connections are bounded and reaped.
func newWebhookTransport() *http.Transport {
	return &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			target, ok := ctx.Value(pinnedTargetKey{}).(ResolvedWebhookTarget)
			if !ok {
				return nil, errors.New("notification: webhook dial without a validated target")
			}
			return pinnedDialContext(target)(ctx, network, addr)
		},
		MaxIdleConnsPerHost: 2,
		IdleConnTimeout:     90 * time.Second,
	}
}

type webhookPayload struct {
	MessageID   string `json:"messageId"`
	SubjectLine string `json:"subjectLine"`
	Body        string `json:"body"`
}

// buildWebhookRequest constructs the outbound POST for d: the signed JSON body plus every
// header (Content-Type, the HMAC signature, and the per-job idempotency key), independent of
// Policy.Validate/the actual network call — split out so header construction is unit-testable
// without a reachable (and Policy-approved) target.
func (w *WebhookSender) buildWebhookRequest(ctx context.Context, d JobDelivery) (*http.Request, error) {
	body, err := json.Marshal(webhookPayload{
		MessageID:   d.Job.MessageID.String(),
		SubjectLine: d.SubjectLine,
		Body:        d.Body,
	})
	if err != nil {
		return nil, fmt.Errorf("notification: marshal webhook payload: %w", err)
	}

	mac := hmac.New(sha256.New, []byte(w.HMACSecret))
	mac.Write(body)
	signature := hex.EncodeToString(mac.Sum(nil))

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.Job.Target, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("notification: build webhook request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Notification-Signature", signature)
	// The delivery job's own id — stable across retries (FailJob resets status/lease,
	// never the row id) AND across crash-reclaims (a reclaimed job is the SAME row, same id) — so
	// a receiver can dedupe a redelivery of the same job against a prior attempt it already
	// processed. The honest guarantee here is at-least-once; this header is what makes
	// receiver-side dedupe possible, not a claim that the platform itself achieves exactly-once.
	req.Header.Set(deliveryIDHeader, d.Job.ID.String())
	return req, nil
}

func (w *WebhookSender) Deliver(ctx context.Context, d JobDelivery) error {
	target, err := w.Policy.Validate(ctx, d.Job.Target)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrNonRetryableDelivery, err)
	}

	return w.post(ctx, target, d)
}

// post sends d to the already-validated target over the shared transport — split from Deliver
// so the transport-reuse test can drive it against a local listener the policy would reject.
func (w *WebhookSender) post(ctx context.Context, target ResolvedWebhookTarget, d JobDelivery) error {
	req, err := w.buildWebhookRequest(context.WithValue(ctx, pinnedTargetKey{}, target), d)
	if err != nil {
		return err
	}

	timeout := w.Timeout
	if timeout <= 0 {
		timeout = webhookDialTimeout
	}
	if w.transport == nil {
		// Never fall through to http.DefaultTransport (its own DNS lookup would bypass the pin).
		return errors.New("notification: webhook sender has no transport (use NewWebhookSender)")
	}
	client := &http.Client{
		Timeout:       timeout,
		CheckRedirect: noWebhookRedirects,
		Transport:     w.transport,
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("notification: webhook post to %s: %w", d.Job.Target, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("notification: webhook post to %s: HTTP %d", d.Job.Target, resp.StatusCode)
	}
	return nil
}
