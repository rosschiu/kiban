// SPDX-License-Identifier: Apache-2.0

package notification

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
)

// TestWebhookPolicy_AddressClasses is the table-driven unit test over the
// address classes the SSRF guard must reject vs allow. Every case uses a literal IP in the URL so
// Validate never performs a real DNS lookup — fully deterministic, no network access.
func TestWebhookPolicy_AddressClasses(t *testing.T) {
	cases := []struct {
		name    string
		url     string
		wantErr bool
	}{
		{"public IPv4 (TEST-NET-3, RFC 5737)", "https://203.0.113.10/hook", false},
		{"public IPv4 (documentation range)", "https://198.51.100.7/hook", false},
		{"loopback IPv4", "https://127.0.0.1/hook", true},
		{"loopback IPv6", "https://[::1]/hook", true},
		{"RFC1918 10/8", "https://10.0.0.5/hook", true},
		{"RFC1918 172.16/12", "https://172.16.4.4/hook", true},
		{"RFC1918 192.168/16", "https://192.168.1.1/hook", true},
		{"link-local IPv4", "https://169.254.1.1/hook", true},
		{"cloud metadata address", "https://169.254.169.254/latest/meta-data", true},
		{"link-local IPv6", "https://[fe80::1]/hook", true},
		{"unique-local IPv6 (fc00::/7)", "https://[fd00::1]/hook", true},
		{"site-local IPv6 (deprecated fec0::/10)", "https://[fec0::1]/hook", true},
		{"multicast IPv4", "https://224.0.0.1/hook", true},
		{"multicast IPv6", "https://[ff02::1]/hook", true},
		{"unspecified IPv4", "https://0.0.0.0/hook", true},
		{"unspecified IPv6", "https://[::]/hook", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := &WebhookPolicy{}
			_, err := p.Validate(context.Background(), tc.url)
			if tc.wantErr && err == nil {
				t.Fatalf("expected %s to be rejected, got no error", tc.url)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("expected %s to be allowed, got %v", tc.url, err)
			}
			if tc.wantErr {
				var werr *WebhookPolicyError
				if !errors.As(err, &werr) {
					t.Fatalf("expected *WebhookPolicyError, got %T: %v", err, err)
				}
			}
		})
	}
}

func TestWebhookPolicy_SchemeRules(t *testing.T) {
	t.Run("http rejected by default", func(t *testing.T) {
		p := &WebhookPolicy{}
		if _, err := p.Validate(context.Background(), "http://203.0.113.10/hook"); err == nil {
			t.Fatal("expected http to be rejected without KIBAN_WEBHOOK_ALLOW_HTTP")
		}
	})
	t.Run("http allowed with AllowHTTP", func(t *testing.T) {
		p := &WebhookPolicy{AllowHTTP: true}
		if _, err := p.Validate(context.Background(), "http://203.0.113.10/hook"); err != nil {
			t.Fatalf("expected http to be allowed with AllowHTTP=true, got %v", err)
		}
	})
	t.Run("https always allowed regardless of AllowHTTP", func(t *testing.T) {
		p := &WebhookPolicy{}
		if _, err := p.Validate(context.Background(), "https://203.0.113.10/hook"); err != nil {
			t.Fatalf("expected https to be allowed, got %v", err)
		}
	})
	t.Run("non-http(s) scheme rejected", func(t *testing.T) {
		p := &WebhookPolicy{}
		if _, err := p.Validate(context.Background(), "ftp://203.0.113.10/hook"); err == nil {
			t.Fatal("expected ftp scheme to be rejected")
		}
	})
	t.Run("invalid URL rejected", func(t *testing.T) {
		p := &WebhookPolicy{}
		if _, err := p.Validate(context.Background(), "not a url"); err == nil {
			t.Fatal("expected an invalid URL to be rejected")
		}
	})
}

func TestWebhookPolicy_Allowlist(t *testing.T) {
	t.Run("host not on allowlist rejected", func(t *testing.T) {
		p := &WebhookPolicy{AllowedHosts: map[string]struct{}{"allowed.example": {}}}
		if _, err := p.Validate(context.Background(), "https://203.0.113.10/hook"); err == nil {
			t.Fatal("expected a host outside the allowlist to be rejected")
		}
	})
	t.Run("host on allowlist allowed, case-insensitively", func(t *testing.T) {
		// A literal-IP host never triggers a DNS lookup, so this exercises the allowlist match
		// alone (case-insensitive: the stored key is lower-cased by NewWebhookPolicyFromEnv /
		// set here directly in upper-case to prove Validate itself lower-cases the incoming host
		// before the lookup, not just relying on the map having been pre-lower-cased).
		p := &WebhookPolicy{AllowedHosts: map[string]struct{}{"203.0.113.10": {}}}
		if _, err := p.Validate(context.Background(), "https://203.0.113.10/hook"); err != nil {
			t.Fatalf("expected an allowlisted host to be allowed, got %v", err)
		}
	})
}

// TestWebhookPolicy_DNSResolutionFailure proves a hostname whose lookup fails is rejected, using
// an injected Resolver so the test never depends on real DNS.
func TestWebhookPolicy_DNSResolutionFailure(t *testing.T) {
	p := &WebhookPolicy{
		Resolver: &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				return nil, errors.New("simulated resolver failure")
			},
		},
	}
	if _, err := p.Validate(context.Background(), "https://definitely-not-a-literal-ip.example/hook"); err == nil {
		t.Fatal("expected a DNS resolution failure to reject the target")
	}
}

func TestNewWebhookPolicyFromEnv_Defaults(t *testing.T) {
	p := NewWebhookPolicyFromEnv()
	if p.AllowHTTP {
		t.Fatal("expected AllowHTTP=false by default")
	}
	if len(p.AllowedHosts) != 0 {
		t.Fatalf("expected no allowlist by default, got %v", p.AllowedHosts)
	}
}

func TestNewWebhookPolicyFromEnv_ReadsEnv(t *testing.T) {
	t.Setenv("KIBAN_WEBHOOK_ALLOW_HTTP", "true")
	t.Setenv("KIBAN_WEBHOOK_ALLOWED_HOSTS", "Foo.Example, bar.example")
	p := NewWebhookPolicyFromEnv()
	if !p.AllowHTTP {
		t.Fatal("expected AllowHTTP=true from env")
	}
	if _, ok := p.AllowedHosts["foo.example"]; !ok {
		t.Fatalf("expected lower-cased foo.example in allowlist, got %v", p.AllowedHosts)
	}
	if _, ok := p.AllowedHosts["bar.example"]; !ok {
		t.Fatalf("expected bar.example in allowlist, got %v", p.AllowedHosts)
	}
}

// TestWebhookPolicyError_Error covers WebhookPolicyError.Error() (every other test type-asserts
// *WebhookPolicyError without ever formatting one).
func TestWebhookPolicyError_Error(t *testing.T) {
	err := &WebhookPolicyError{Message: "target address is not allowed"}
	got := err.Error()
	if got != "notification: webhook target rejected: target address is not allowed" {
		t.Fatalf("Error() = %q, unexpected shape", got)
	}
}

// TestPinnedDialContext_* cover pinnedDialContext directly. pinnedDialContext is deliberately
// agnostic to HOW target.IPs was approved — it
// just dials the addresses it's given — so these tests build a ResolvedWebhookTarget by hand
// (bypassing WebhookPolicy.Validate entirely, same as the type's own doc comment: "dials ONLY
// the IPs Validate already classified as allowed") rather than relaxing the SSRF policy itself,
// which stays untouched.
func TestPinnedDialContext_DialsApprovedAddress(t *testing.T) {
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
			_ = conn.Close()
		}
	}()

	_, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("split host port: %v", err)
	}
	target := ResolvedWebhookTarget{IPs: []netip.Addr{netip.MustParseAddr("127.0.0.1")}, Port: port}

	dial := pinnedDialContext(target)
	conn, err := dial(context.Background(), "tcp", "ignored:0")
	if err != nil {
		t.Fatalf("expected the dial to succeed against the approved address, got: %v", err)
	}
	_ = conn.Close()
}

func TestPinnedDialContext_FirstAddressFailsSecondSucceeds(t *testing.T) {
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
			_ = conn.Close()
		}
	}()
	_, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("split host port: %v", err)
	}

	// pinnedDialContext ignores the transport's own addr argument and dials target.Port against
	// EACH of target.IPs in order (net.JoinHostPort(ip, target.Port)) — 127.0.0.2 is loopback
	// (routes locally on Linux, same as 127.0.0.1) but nothing listens on THIS port there, so it
	// reliably refuses first, falling through to 127.0.0.1 where the real listener is.
	target := ResolvedWebhookTarget{
		IPs:  []netip.Addr{netip.MustParseAddr("127.0.0.2"), netip.MustParseAddr("127.0.0.1")},
		Port: port,
	}
	dial := pinnedDialContext(target)
	conn, err := dial(context.Background(), "tcp", "ignored:0")
	if err != nil {
		t.Fatalf("expected the dial to fall through to the second, working address, got: %v", err)
	}
	_ = conn.Close()
}

func TestPinnedDialContext_NoApprovedAddresses(t *testing.T) {
	target := ResolvedWebhookTarget{IPs: nil, Port: "0"}
	dial := pinnedDialContext(target)
	_, err := dial(context.Background(), "tcp", "ignored:0")
	if err == nil {
		t.Fatal("expected an error when target.IPs is empty")
	}
}
