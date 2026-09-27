// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	// provisionTTL bounds how long a resolved subject is trusted before the gateway resolves it
	// again (ResolveOrCreate is idempotent, so a re-resolve is a harmless upsert).
	provisionTTL = time.Hour
	// provisionCacheMax bounds the cache: past it the whole map is dropped and rebuilt.
	provisionCacheMax = 10000
	provisionTimeout  = 5 * time.Second
)

// Provisioner makes sure a validated subject has an identity.user_account row before its first
// request of this process proceeds: it POSTs /internal/identity/resolve with the
// request's own bearer — identity re-verifies it against the same issuer and audience the
// gateway just checked, so the header is forwarded unchanged and identity derives the subject
// from the token, never from anything the gateway says. Fail closed: anything but a 200 leaves
// the request at 503 AUTHORIZATION_UNAVAILABLE rather than letting it reach services that would
// answer AUTH_USER_NOT_FOUND (and write audit noise). A restart or TTL expiry just re-resolves.
type Provisioner struct {
	resolveURL string
	client     *http.Client
	logger     *slog.Logger

	// Known ceiling: plain map + mutex + TTL, cleared wholesale past provisionCacheMax and no
	// single-flight (concurrent first requests for one subject each resolve once — identity's
	// upsert is idempotent). An LRU + single-flight if subject churn or identity load ever matters.
	mu   sync.Mutex
	seen map[string]provisionEntry
}

type provisionEntry struct {
	at time.Time
	// ok: provisioned at `at`. !ok: a failure was already logged at `at` (log once per subject
	// until it succeeds).
	ok bool
}

// NewProvisioner targets identity at identityBaseURL (scheme+host). logger may be nil (tests);
// production passes the gateway's own logger so a failing identity is visible in its logs.
func NewProvisioner(identityBaseURL string, logger *slog.Logger) *Provisioner {
	mustParseAbsoluteURL(identityBaseURL)
	return &Provisioner{
		resolveURL: strings.TrimRight(identityBaseURL, "/") + "/internal/identity/resolve",
		client:     &http.Client{Timeout: provisionTimeout},
		logger:     logger,
		seen:       map[string]provisionEntry{},
	}
}

// Ensure resolves sub through identity unless it was resolved within provisionTTL.
// rawAuthorization is the request's full "Authorization" header value.
func (p *Provisioner) Ensure(ctx context.Context, sub, rawAuthorization string) error {
	p.mu.Lock()
	e, cached := p.seen[sub]
	p.mu.Unlock()
	if cached && e.ok && time.Since(e.at) < provisionTTL {
		return nil
	}

	err := p.resolve(ctx, rawAuthorization)

	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.seen) >= provisionCacheMax {
		p.seen = map[string]provisionEntry{}
	}
	if err == nil {
		p.seen[sub] = provisionEntry{at: time.Now(), ok: true}
		return nil
	}
	if !(cached && !e.ok) && p.logger != nil {
		p.logger.Error("gateway: identity provisioning failed, failing closed", slog.String("sub", sub), slog.Any("error", err))
	}
	p.seen[sub] = provisionEntry{at: time.Now(), ok: false}
	return err
}

func (p *Provisioner) resolve(ctx context.Context, rawAuthorization string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.resolveURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", rawAuthorization)
	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("identity resolve: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("identity resolve: status %d", resp.StatusCode)
	}
	return nil
}
