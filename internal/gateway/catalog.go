// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

// Catalog snapshot numbers: the snapshot is cached <=5s with single-flight refresh;
// capability errors are always re-checked per request against the snapshot.
const (
	catalogCacheTTL = 5 * time.Second
	catalogTimeout  = 5 * time.Second
)

// defaultCatalogMaxStale bounds how long a previously-fetched snapshot keeps being served while
// the registry is unreachable (fail closed, like everything else at this edge — a
// module disabled for security/entitlement reasons must not stay routable through an unbounded
// registry outage). 60s = 12x catalogCacheTTL: tolerates a blip without flapping every module on
// every missed refresh, bounds the exposure window to something an operator can reason about.
// Overridden via KIBAN_CATALOG_MAX_STALE (cmd/gateway wires it onto CatalogClient.MaxStale).
const defaultCatalogMaxStale = 60 * time.Second

// ModuleEntry is the gateway's per-module routing + capability snapshot, assembled from the
// registry's two public-read endpoints (capability + catalog reads pass through WITHOUT the
// admin gate): GET /api/platform/catalog (routing:
// basePath/healthPath/port + installed/enabled) and GET /api/platform/capabilities
// (dependency-aware capability shape). The catalog listing alone carries no dependency
// information (registry.CatalogEntry has no missingDependencies field — only
// registry.Capability does), so a snapshot refresh combines both reads.
type ModuleEntry struct {
	ModuleKey           string
	BasePath            string
	HealthPath          string
	Port                int32
	Installed           bool
	Enabled             bool
	MissingDependencies []string
}

// Snapshot is one cached read of the registry's module catalog + capability state.
type Snapshot struct {
	fetchedAt time.Time
	byKey     map[string]ModuleEntry
}

// Lookup returns the module entry for key, if the registry's catalog knows it at all. ok=false
// means an unknown key — callers turn that into 404.
func (s Snapshot) Lookup(key string) (ModuleEntry, bool) {
	e, ok := s.byKey[key]
	return e, ok
}

// CatalogClient fetches and caches the module catalog snapshot from the registry service over
// HTTP (no DB — the gateway is stateless). Get is
// safe for concurrent use; concurrent callers that all observe a stale snapshot share exactly
// one refresh (single-flight, hand-rolled here rather than importing golang.org/x/sync/
// singleflight to avoid a new dependency). Nothing here
// positively caches a capability DECISION past the snapshot's own TTL — Lookup always
// re-derives installed/enabled/missing from whatever snapshot is current.
type CatalogClient struct {
	baseURL string
	client  *http.Client
	logger  *slog.Logger

	// MaxStale bounds how long a snapshot keeps being served once refreshes start failing.
	// Zero (the NewCatalogClient default) means defaultCatalogMaxStale; exported so
	// cmd/gateway can set it from KIBAN_CATALOG_MAX_STALE without a second constructor.
	MaxStale time.Duration

	mu       sync.Mutex
	snapshot Snapshot
	inflight chan struct{} // non-nil while a refresh is in flight; closed on completion
	lastErr  error
}

// NewCatalogClient builds a client against the registry's base URL (e.g. http://127.0.0.1:8110).
// logger may be nil (tests that don't care about the staleness warning); production always
// passes the gateway's own logger so a fail-closed staleness event is visible in its logs, not
// just inferable from a client's 503.
func NewCatalogClient(baseURL string, logger *slog.Logger) *CatalogClient {
	return &CatalogClient{
		baseURL:  baseURL,
		client:   &http.Client{Timeout: catalogTimeout},
		logger:   logger,
		MaxStale: defaultCatalogMaxStale,
	}
}

// Get returns the current snapshot, refreshing it first if older than catalogCacheTTL. On a
// refresh failure with a previously-fetched snapshot on hand, the stale snapshot is served ONLY
// while its age is within MaxStale (better than treating every registry blip as "every module
// vanished"); beyond MaxStale, or with no snapshot at all yet, the error is returned so the
// caller fails closed (503 MODULE_UNAVAILABLE — a module disabled for security/
// entitlement reasons must not stay routable through an unbounded registry outage).
func (c *CatalogClient) Get(ctx context.Context) (Snapshot, error) {
	c.mu.Lock()
	fresh := c.snapshot.byKey != nil && time.Since(c.snapshot.fetchedAt) < catalogCacheTTL
	if fresh {
		snap := c.snapshot
		c.mu.Unlock()
		return snap, nil
	}
	if c.inflight != nil {
		wait := c.inflight
		c.mu.Unlock()
		<-wait
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.resultLocked()
	}
	done := make(chan struct{})
	c.inflight = done
	c.mu.Unlock()

	snap, fetchErr := c.fetch(ctx)

	c.mu.Lock()
	if fetchErr == nil {
		c.snapshot = snap
		c.lastErr = nil
	} else {
		c.lastErr = fetchErr
	}
	result, resultErr := c.resultLocked()
	close(done)
	c.inflight = nil
	c.mu.Unlock()

	return result, resultErr
}

// resultLocked decides what Get returns given the current c.snapshot/c.lastErr — the shared
// staleness-bound check for both the "waited on someone else's refresh" and "did my own refresh"
// paths. Caller must hold c.mu.
func (c *CatalogClient) resultLocked() (Snapshot, error) {
	if c.snapshot.byKey == nil {
		return Snapshot{}, c.lastErr
	}
	if c.lastErr == nil {
		return c.snapshot, nil
	}

	maxStale := c.MaxStale
	if maxStale <= 0 {
		maxStale = defaultCatalogMaxStale
	}
	age := time.Since(c.snapshot.fetchedAt)
	if age < maxStale {
		return c.snapshot, nil
	}

	if c.logger != nil {
		c.logger.Warn("gateway: catalog snapshot exceeded max staleness, failing closed",
			slog.Duration("age", age), slog.Duration("maxStale", maxStale), slog.Any("lastRefreshError", c.lastErr))
	}
	return Snapshot{}, fmt.Errorf("gateway: catalog snapshot stale beyond max (age=%s max=%s): %w", age, maxStale, c.lastErr)
}

type catalogRow struct {
	ModuleKey  string `json:"moduleKey"`
	BasePath   string `json:"basePath"`
	HealthPath string `json:"healthPath"`
	Port       int32  `json:"port"`
	Installed  bool   `json:"installed"`
	Enabled    bool   `json:"enabled"`
}

type capabilityRow struct {
	Module              string   `json:"module"`
	MissingDependencies []string `json:"missingDependencies"`
}

func (c *CatalogClient) fetch(ctx context.Context) (Snapshot, error) {
	// Detached from the caller: this one fetch is shared by every concurrent Get (single-flight),
	// so the first requester hanging up must not turn into a refresh failure — and eventually a
	// fail-closed 503 — for everyone else. catalogTimeout still bounds it.
	fetchCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), catalogTimeout)
	defer cancel()

	var catalogRows []catalogRow
	if err := c.getEnvelope(fetchCtx, "/api/platform/catalog", &catalogRows); err != nil {
		return Snapshot{}, fmt.Errorf("gateway: fetch catalog: %w", err)
	}

	var capRows []capabilityRow
	if err := c.getEnvelope(fetchCtx, "/api/platform/capabilities", &capRows); err != nil {
		return Snapshot{}, fmt.Errorf("gateway: fetch capabilities: %w", err)
	}
	missingByKey := make(map[string][]string, len(capRows))
	for _, r := range capRows {
		missingByKey[r.Module] = r.MissingDependencies
	}

	byKey := make(map[string]ModuleEntry, len(catalogRows))
	for _, r := range catalogRows {
		byKey[r.ModuleKey] = ModuleEntry{
			ModuleKey:           r.ModuleKey,
			BasePath:            r.BasePath,
			HealthPath:          r.HealthPath,
			Port:                r.Port,
			Installed:           r.Installed,
			Enabled:             r.Enabled,
			MissingDependencies: missingByKey[r.ModuleKey],
		}
	}
	return Snapshot{fetchedAt: time.Now(), byKey: byKey}, nil
}

// getEnvelope GETs path and decodes the {"data": ...} success envelope into out.
func (c *CatalogClient) getEnvelope(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d from %s", resp.StatusCode, path)
	}
	var envelope struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return fmt.Errorf("decode envelope from %s: %w", path, err)
	}
	return json.Unmarshal(envelope.Data, out)
}
