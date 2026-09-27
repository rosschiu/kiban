// SPDX-License-Identifier: Apache-2.0

//go:build live

package notification

import (
	"context"
	"testing"
)

// TestWebhookPolicy_Live_RejectsInComposeWebhookTarget is the live proof against the in-compose
// webhook-target (which is on the compose network): the default policy REJECTS it, proving the
// guard bites.
//
// Gated behind the `live` build tag (go test -tags live) — it depends on the compose network's
// DNS resolving the "webhook-target" service name (infra/compose.yaml's mendhak/http-https-echo
// container, profile "test"), which is only reachable from inside that network, never from a
// bare `go test` run on the host, so it belongs to the isolated test stack rather than the
// default unit suite.
//
// What it proves: webhook-target's container address is an ordinary Docker bridge-network IP —
// RFC1918 private space by Docker's own default subnet allocation — so even with
// KIBAN_WEBHOOK_ALLOW_HTTP=true (the dev scheme opt-in), WebhookPolicy.Validate still rejects it
// on the address-class check. That's the guard actually biting: scheme opt-in alone is never
// enough to reach a compose-internal target, only the separate KIBAN_WEBHOOK_ALLOWED_HOSTS
// allowlist (deliberately not exercised here, since setting it would defeat the point of this
// specific proof).
func TestWebhookPolicy_Live_RejectsInComposeWebhookTarget(t *testing.T) {
	p := &WebhookPolicy{AllowHTTP: true} // dev opt-in for scheme only — no allowlist entry
	_, err := p.Validate(context.Background(), "http://webhook-target:8080/inbound")
	if err == nil {
		t.Fatal("expected the default policy to reject the in-compose webhook-target despite KIBAN_WEBHOOK_ALLOW_HTTP=true — " +
			"its resolved address is RFC1918 private (Docker's default bridge subnet), which the address-class check always rejects")
	}
}
