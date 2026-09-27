// SPDX-License-Identifier: Apache-2.0

package notification

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"time"
)

// WebhookPolicyError marks a webhook target rejected by the SSRF guard
// — distinct from ValidationError because it maps to the shared
// errenv.CodeValidationFailed code (VALIDATION_FAILED) rather than the field-shape
// errenv.CodeValidationError, and because a delivery-time rejection is a non-retryable delivery
// failure, not a request-shape problem.
type WebhookPolicyError struct {
	Message string
}

func (e *WebhookPolicyError) Error() string {
	return "notification: webhook target rejected: " + e.Message
}

// webhookDialTimeout bounds both DNS resolution and the eventual TCP dial.
const webhookDialTimeout = 10 * time.Second

// WebhookPolicy enforces the webhook target rules, applied identically at CREATE time (webhook
// channel target) and at DELIVERY time (re-resolve — DNS can change between create and
// delivery/each delivery, so a validated hostname is re-checked, never cached past one
// resolution):
//   - scheme must be https, UNLESS the KIBAN_WEBHOOK_ALLOW_HTTP dev opt-in env is "true"
//     (default false — plaintext webhook delivery is off by default);
//   - every resolved IP must be a routable, non-internal unicast address: loopback, RFC1918,
//     link-local (incl. the 169.254.169.254 cloud metadata address), IPv6 unique-local/site-local,
//     multicast, and unspecified are all rejected;
//   - an optional operator egress allowlist, KIBAN_WEBHOOK_ALLOWED_HOSTS (comma-separated
//     hostnames, case-insensitive) — empty/unset means policy-only (no allowlist restriction
//     beyond the address-class checks above).
type WebhookPolicy struct {
	AllowHTTP    bool
	AllowedHosts map[string]struct{} // lower-cased hostnames; nil/empty = no allowlist restriction
	Resolver     *net.Resolver       // nil = net.DefaultResolver
}

// NewWebhookPolicyFromEnv builds the policy the production worker/HTTP layer uses, reading
// KIBAN_WEBHOOK_ALLOW_HTTP and KIBAN_WEBHOOK_ALLOWED_HOSTS directly (both optional — no
// config.Load Required entry, so a deployment that never sets them gets the safe https-only,
// policy-only-no-allowlist default).
func NewWebhookPolicyFromEnv() *WebhookPolicy {
	p := &WebhookPolicy{AllowHTTP: os.Getenv("KIBAN_WEBHOOK_ALLOW_HTTP") == "true"}
	if raw := os.Getenv("KIBAN_WEBHOOK_ALLOWED_HOSTS"); raw != "" {
		p.AllowedHosts = map[string]struct{}{}
		for _, h := range strings.Split(raw, ",") {
			if h = strings.ToLower(strings.TrimSpace(h)); h != "" {
				p.AllowedHosts[h] = struct{}{}
			}
		}
	}
	return p
}

func (p *WebhookPolicy) resolver() *net.Resolver {
	if p.Resolver != nil {
		return p.Resolver
	}
	return net.DefaultResolver
}

// ResolvedWebhookTarget is a validated webhook target — the parsed URL plus the exact IPs its
// host resolved to at validation time, so the caller can dial those IPs directly (closing the
// DNS-rebinding window between validation and connect: a second lookup at dial time could return
// a different, unvalidated answer).
type ResolvedWebhookTarget struct {
	URL  *url.URL
	Port string
	IPs  []netip.Addr
}

// Validate parses rawURL, enforces the scheme rule, resolves the host (or accepts a literal IP
// with no DNS lookup), and rejects the target if ANY resolved address falls in a disallowed
// class or (when set) the host isn't on the operator allowlist. Called both at webhook-channel
// CREATE time and again immediately before every delivery attempt.
func (p *WebhookPolicy) Validate(ctx context.Context, rawURL string) (ResolvedWebhookTarget, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return ResolvedWebhookTarget{}, &WebhookPolicyError{Message: "target must be a valid absolute URL"}
	}

	switch u.Scheme {
	case "https":
	case "http":
		if !p.AllowHTTP {
			return ResolvedWebhookTarget{}, &WebhookPolicyError{
				Message: "scheme must be https (set KIBAN_WEBHOOK_ALLOW_HTTP=true to allow http for dev only)",
			}
		}
	default:
		return ResolvedWebhookTarget{}, &WebhookPolicyError{Message: "scheme must be https"}
	}

	host := u.Hostname()
	if host == "" {
		return ResolvedWebhookTarget{}, &WebhookPolicyError{Message: "target must have a host"}
	}
	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}

	if len(p.AllowedHosts) > 0 {
		if _, ok := p.AllowedHosts[strings.ToLower(host)]; !ok {
			return ResolvedWebhookTarget{}, &WebhookPolicyError{Message: "host is not in KIBAN_WEBHOOK_ALLOWED_HOSTS"}
		}
	}

	dialCtx, cancel := context.WithTimeout(ctx, webhookDialTimeout)
	defer cancel()

	addrs, err := p.resolveHost(dialCtx, host)
	if err != nil {
		return ResolvedWebhookTarget{}, &WebhookPolicyError{Message: "DNS resolution failed: " + err.Error()}
	}
	if len(addrs) == 0 {
		return ResolvedWebhookTarget{}, &WebhookPolicyError{Message: "host has no resolvable addresses"}
	}
	for _, addr := range addrs {
		if isDisallowedWebhookAddr(addr) {
			return ResolvedWebhookTarget{}, &WebhookPolicyError{
				Message: fmt.Sprintf("target address %s is not allowed (loopback/private/link-local/multicast/unspecified)", addr),
			}
		}
	}

	return ResolvedWebhookTarget{URL: u, Port: port, IPs: addrs}, nil
}

func (p *WebhookPolicy) resolveHost(ctx context.Context, host string) ([]netip.Addr, error) {
	// A literal IP needs no DNS lookup — also closes the trivial "IP literal in the URL" bypass
	// some naive SSRF guards miss.
	if ip, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{ip.Unmap()}, nil
	}
	ipAddrs, err := p.resolver().LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	out := make([]netip.Addr, 0, len(ipAddrs))
	for _, a := range ipAddrs {
		if addr, ok := netip.AddrFromSlice(a.IP); ok {
			out = append(out, addr.Unmap())
		}
	}
	return out, nil
}

// siteLocalV6 is the deprecated IPv6 site-local range (fec0::/10, RFC 3879) — netip.Addr has no
// IsSiteLocal helper (unlike the old net.IP), so it's checked explicitly. Unique-local (fc00::/7,
// RFC 4193) IS covered by netip.Addr.IsPrivate() already.
var siteLocalV6 = netip.MustParsePrefix("fec0::/10")

// isDisallowedWebhookAddr is the address-class reject list: loopback, RFC1918/ULA
// private, link-local unicast (covers 169.254.0.0/16, including the 169.254.169.254 cloud
// metadata address, and IPv6 fe80::/10), link-local/interface-local/other multicast, unspecified
// (0.0.0.0 / ::), and deprecated IPv6 site-local.
func isDisallowedWebhookAddr(addr netip.Addr) bool {
	if !addr.IsValid() {
		return true
	}
	addr = addr.Unmap()
	switch {
	case addr.IsLoopback(),
		addr.IsPrivate(),
		addr.IsLinkLocalUnicast(),
		addr.IsLinkLocalMulticast(),
		addr.IsInterfaceLocalMulticast(),
		addr.IsMulticast(),
		addr.IsUnspecified():
		return true
	}
	return addr.Is6() && siteLocalV6.Contains(addr)
}

// pinnedDialContext returns a DialContext that ignores the address the transport asks it to
// dial and instead dials ONLY the IPs Validate already classified as allowed — this is what
// closes the DNS-rebinding window: even if the target hostname's DNS answer changes between
// Validate and the transport's own (otherwise-independent) connect, the connection can only ever
// reach an address this policy has already approved.
func pinnedDialContext(target ResolvedWebhookTarget) func(ctx context.Context, network, addr string) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: webhookDialTimeout}
	return func(ctx context.Context, network, _ string) (net.Conn, error) {
		var lastErr error = errors.New("notification: no validated addresses to dial")
		for _, ip := range target.IPs {
			conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), target.Port))
			if err == nil {
				return conn, nil
			}
			lastErr = err
		}
		return nil, lastErr
	}
}
