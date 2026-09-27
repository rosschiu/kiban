// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Unit tests for the catalog's fail-closed staleness bound. registryStub/writeTestEnvelope are
// shared with proxy_test.go (same package). Several of these tests seed CatalogClient.snapshot
// directly (unexported field, same-package test) rather than waiting out real TTL/staleness
// windows — catalogCacheTTL is fixed at 5s, so a real-time test would need to sleep past it;
// seeding fetchedAt in the
// past exercises the exact same Get()/resultLocked() code path deterministically and fast.

func TestCatalogClient_Get_FreshSnapshotServed(t *testing.T) {
	reg := newRegistryStub(t)
	reg.set([]catalogRow{{
		ModuleKey: "foo", BasePath: "/api/foo", HealthPath: "/health", Port: 1,
		Installed: true, Enabled: true,
	}}, nil)

	c := NewCatalogClient(reg.server.URL, nil)
	snap, err := c.Get(context.Background())
	if err != nil {
		t.Fatalf("Get() error = %v, want nil", err)
	}
	if _, ok := snap.Lookup("foo"); !ok {
		t.Fatal("expected a fresh snapshot to be served")
	}
}

// TestCatalogClient_Get_StaleWithinBound_ServedDuringOutage proves the core tolerance: a
// registry refresh failure does NOT immediately fail closed — the previously-fetched snapshot
// keeps serving as long as its age is within MaxStale (default 60s; here an explicit bound so
// the test doesn't depend on the default).
func TestCatalogClient_Get_StaleWithinBound_ServedDuringOutage(t *testing.T) {
	c := &CatalogClient{
		baseURL:  "http://127.0.0.1:1", // nothing listens here — every fetch fails
		client:   &http.Client{Timeout: catalogTimeout},
		MaxStale: 60 * time.Second,
	}
	c.snapshot = Snapshot{
		fetchedAt: time.Now().Add(-30 * time.Second), // past catalogCacheTTL, within MaxStale
		byKey:     map[string]ModuleEntry{"foo": {ModuleKey: "foo", Installed: true, Enabled: true}},
	}

	snap, err := c.Get(context.Background())
	if err != nil {
		t.Fatalf("Get() error = %v, want nil (stale-but-within-bound must still serve)", err)
	}
	if _, ok := snap.Lookup("foo"); !ok {
		t.Fatal("expected the pre-fetched stale snapshot to be served during the outage")
	}
}

// TestCatalogClient_Get_BeyondMaxStale_FailsClosed proves the bound actually bites: once a
// registry outage pushes the snapshot's age past MaxStale, Get() returns an error instead of
// serving indefinitely-stale routing/capability data — the caller (ModuleProxy.ServeHTTP) turns
// that into 503 MODULE_UNAVAILABLE (proxy_test.go's TestProxy_RegistryUnreachable503 covers the
// no-snapshot-at-all variant of that same 503 mapping).
func TestCatalogClient_Get_BeyondMaxStale_FailsClosed(t *testing.T) {
	c := &CatalogClient{
		baseURL:  "http://127.0.0.1:1",
		client:   &http.Client{Timeout: catalogTimeout},
		MaxStale: 60 * time.Second,
	}
	c.snapshot = Snapshot{
		fetchedAt: time.Now().Add(-90 * time.Second), // beyond MaxStale
		byKey:     map[string]ModuleEntry{"foo": {ModuleKey: "foo", Installed: true, Enabled: true}},
	}

	snap, err := c.Get(context.Background())
	if err == nil {
		t.Fatal("expected Get() to fail closed once staleness exceeds MaxStale")
	}
	if _, ok := snap.Lookup("foo"); ok {
		t.Fatal("expected a zero-value Snapshot on the fail-closed path, not the stale one")
	}
}

// TestCatalogClient_Get_DefaultMaxStaleAppliesWhenUnset proves NewCatalogClient's zero-value
// MaxStale falls back to defaultCatalogMaxStale (60s) rather than failing closed immediately —
// resultLocked's "maxStale <= 0" fallback, exercised via a client built with the field forced
// back to zero after construction.
func TestCatalogClient_Get_DefaultMaxStaleAppliesWhenUnset(t *testing.T) {
	c := NewCatalogClient("http://127.0.0.1:1", nil)
	c.MaxStale = 0 // simulate a caller that never set it
	c.snapshot = Snapshot{
		fetchedAt: time.Now().Add(-30 * time.Second), // within the 60s default, beyond the 5s TTL
		byKey:     map[string]ModuleEntry{"foo": {ModuleKey: "foo", Installed: true, Enabled: true}},
	}

	if _, err := c.Get(context.Background()); err != nil {
		t.Fatalf("Get() error = %v, want nil (age 30s must be within the 60s default MaxStale)", err)
	}
}

// TestCatalogClient_Get_RecoversAfterOutage proves recovery: once the registry starts answering
// again, the SAME CatalogClient (no restart) resumes serving a fresh snapshot on its very next
// Get() call, even immediately after a fail-closed response.
func TestCatalogClient_Get_RecoversAfterOutage(t *testing.T) {
	var fail atomic.Bool
	mux := http.NewServeMux()
	mux.HandleFunc("/api/platform/catalog", func(w http.ResponseWriter, r *http.Request) {
		if fail.Load() {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		writeTestEnvelope(w, []catalogRow{{
			ModuleKey: "foo", BasePath: "/api/foo", HealthPath: "/health", Port: 1,
			Installed: true, Enabled: true,
		}})
	})
	mux.HandleFunc("/api/platform/capabilities", func(w http.ResponseWriter, r *http.Request) {
		if fail.Load() {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		writeTestEnvelope(w, []capabilityRow{})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := NewCatalogClient(srv.URL, nil)
	c.MaxStale = 2 * time.Second

	if _, err := c.Get(context.Background()); err != nil {
		t.Fatalf("initial Get: %v", err)
	}

	// Age the snapshot past both catalogCacheTTL and MaxStale, then simulate the registry going
	// down: the next Get() must fail closed.
	fail.Store(true)
	c.mu.Lock()
	c.snapshot.fetchedAt = time.Now().Add(-10 * time.Second)
	c.mu.Unlock()

	if _, err := c.Get(context.Background()); err == nil {
		t.Fatal("expected Get() to fail closed once the outage pushes the snapshot beyond MaxStale")
	}

	// Registry recovers — the same client, no restart, serves fresh data again immediately.
	fail.Store(false)
	snap, err := c.Get(context.Background())
	if err != nil {
		t.Fatalf("expected recovery once the registry answers again, got: %v", err)
	}
	if _, ok := snap.Lookup("foo"); !ok {
		t.Fatal("expected the recovered snapshot to contain the module again")
	}
}

// TestCatalogClient_Get_RefreshDetachedFromFirstCaller proves the single-flight refresh runs on
// its own context: the caller that STARTED the fetch cancelling mid-flight neither fails the
// fetch nor poisons lastErr for the concurrent caller waiting on it (which would otherwise
// count down MaxStale toward a fail-closed 503 on a perfectly healthy registry).
func TestCatalogClient_Get_RefreshDetachedFromFirstCaller(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	mux := http.NewServeMux()
	mux.HandleFunc("/api/platform/catalog", func(w http.ResponseWriter, r *http.Request) {
		once.Do(func() { close(started) })
		<-release
		writeTestEnvelope(w, []catalogRow{{ModuleKey: "foo", Installed: true, Enabled: true, Port: 1}})
	})
	mux.HandleFunc("/api/platform/capabilities", func(w http.ResponseWriter, r *http.Request) {
		writeTestEnvelope(w, []capabilityRow{})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	c := NewCatalogClient(srv.URL, nil)

	ctx1, cancel1 := context.WithCancel(context.Background())
	first := make(chan error, 1)
	go func() {
		_, err := c.Get(ctx1)
		first <- err
	}()
	<-started
	cancel1() // the initiator hangs up mid-fetch

	second := make(chan error, 1)
	go func() {
		_, err := c.Get(context.Background())
		second <- err
	}()
	// Let the second caller reach the in-flight wait before the registry answers.
	time.Sleep(50 * time.Millisecond)
	close(release)

	if err := <-second; err != nil {
		t.Fatalf("second caller Get() = %v, want nil (refresh must survive the first caller's cancel)", err)
	}
	if err := <-first; err != nil {
		t.Fatalf("first caller Get() = %v, want nil (its own fetch is detached)", err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.lastErr != nil {
		t.Fatalf("lastErr = %v, want nil", c.lastErr)
	}
}
