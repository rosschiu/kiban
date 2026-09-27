// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeIdentity is a stand-in identity service: counts POST /internal/identity/resolve calls,
// records the bearer it received, and answers with whatever status the test sets.
type fakeIdentity struct {
	*httptest.Server
	calls  atomic.Int32
	status atomic.Int32
	bearer atomic.Value
}

func newFakeIdentity(t *testing.T) *fakeIdentity {
	t.Helper()
	f := &fakeIdentity{}
	f.status.Store(http.StatusOK)
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/internal/identity/resolve" {
			t.Errorf("unexpected identity call %s %s", r.Method, r.URL.Path)
		}
		f.calls.Add(1)
		f.bearer.Store(r.Header.Get("Authorization"))
		w.WriteHeader(int(f.status.Load()))
		_, _ = w.Write([]byte(`{"data":{}}`))
	}))
	t.Cleanup(f.Close)
	return f
}

func provisionFixture(t *testing.T) (*fakeJWKSServer, *fakeIdentity, *Provisioner, http.Handler, *atomic.Int32) {
	t.Helper()
	jwks := newFakeJWKSServer(t)
	v := newTestVerifier(t, jwks.URL+"/certs")
	identity := newFakeIdentity(t)
	prov := NewProvisioner(identity.URL, nil)
	var nextCalls atomic.Int32
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { nextCalls.Add(1) })
	return jwks, identity, prov, RequireAuth(v, prov)(next), &nextCalls
}

func doProvisioned(handler http.Handler, bearer string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/api/foo/bar", nil)
	req.Header.Set("Authorization", "Bearer "+bearer)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

// TestProvision_FirstRequestResolvesOnce: the first request for a subject resolves through
// identity with the request's own bearer forwarded unchanged; the second does not.
func TestProvision_FirstRequestResolvesOnce(t *testing.T) {
	jwks, identity, _, handler, nextCalls := provisionFixture(t)
	bearer := jwks.signToken(t, tokenOpts{subject: "user-1", audience: []string{testAudience}})

	for i := 0; i < 2; i++ {
		if rec := doProvisioned(handler, bearer); rec.Code != http.StatusOK {
			t.Fatalf("request %d: status = %d, want 200: %s", i, rec.Code, rec.Body.String())
		}
	}
	if got := identity.calls.Load(); got != 1 {
		t.Errorf("identity resolve calls = %d, want 1", got)
	}
	if got := identity.bearer.Load(); got != "Bearer "+bearer {
		t.Errorf("identity received Authorization %q, want the request's own bearer", got)
	}
	if got := nextCalls.Load(); got != 2 {
		t.Errorf("next handler calls = %d, want 2", got)
	}

	// A different subject is its own first request.
	other := jwks.signToken(t, tokenOpts{subject: "user-2", audience: []string{testAudience}})
	doProvisioned(handler, other)
	if got := identity.calls.Load(); got != 2 {
		t.Errorf("identity resolve calls after a second subject = %d, want 2", got)
	}
}

// TestProvision_IdentityFailure503 fails closed: a non-200 from identity is 503
// AUTHORIZATION_UNAVAILABLE, next never runs, and the subject is NOT cached as provisioned (the
// next request retries and succeeds once identity recovers).
func TestProvision_IdentityFailure503(t *testing.T) {
	jwks, identity, _, handler, nextCalls := provisionFixture(t)
	bearer := jwks.signToken(t, tokenOpts{subject: "user-1", audience: []string{testAudience}})

	identity.status.Store(http.StatusInternalServerError)
	rec := doProvisioned(handler, bearer)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"AUTHORIZATION_UNAVAILABLE"`) {
		t.Errorf("body = %s, want AUTHORIZATION_UNAVAILABLE", rec.Body.String())
	}
	if nextCalls.Load() != 0 {
		t.Error("next handler must not run when provisioning fails")
	}

	identity.status.Store(http.StatusOK)
	if rec := doProvisioned(handler, bearer); rec.Code != http.StatusOK {
		t.Fatalf("after identity recovers: status = %d, want 200", rec.Code)
	}
	if got := identity.calls.Load(); got != 2 {
		t.Errorf("identity resolve calls = %d, want 2 (failure never cached)", got)
	}
}

// TestProvision_TransportError503: an unreachable identity is the same fail-closed 503.
func TestProvision_TransportError503(t *testing.T) {
	jwks := newFakeJWKSServer(t)
	v := newTestVerifier(t, jwks.URL+"/certs")
	prov := NewProvisioner("http://127.0.0.1:1", nil)
	handler := RequireAuth(v, prov)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next handler must not run")
	}))
	bearer := jwks.signToken(t, tokenOpts{subject: "user-1", audience: []string{testAudience}})
	if rec := doProvisioned(handler, bearer); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}

// TestProvision_TTLExpiryReResolves: a cached subject older than provisionTTL resolves again.
func TestProvision_TTLExpiryReResolves(t *testing.T) {
	jwks, identity, prov, handler, _ := provisionFixture(t)
	bearer := jwks.signToken(t, tokenOpts{subject: "user-1", audience: []string{testAudience}})

	doProvisioned(handler, bearer)
	prov.mu.Lock()
	prov.seen["user-1"] = provisionEntry{at: time.Now().Add(-provisionTTL - time.Second), ok: true}
	prov.mu.Unlock()
	doProvisioned(handler, bearer)
	if got := identity.calls.Load(); got != 2 {
		t.Errorf("identity resolve calls = %d, want 2 (expired entry re-resolved)", got)
	}
}

// TestProvision_ConcurrentFirstRequests: concurrent first requests for one subject all
// succeed; without single-flight each may resolve once, never more, and afterwards the subject
// is cached.
func TestProvision_ConcurrentFirstRequests(t *testing.T) {
	jwks, identity, _, handler, nextCalls := provisionFixture(t)
	bearer := jwks.signToken(t, tokenOpts{subject: "user-1", audience: []string{testAudience}})

	const n = 8
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if rec := doProvisioned(handler, bearer); rec.Code != http.StatusOK {
				t.Errorf("status = %d, want 200", rec.Code)
			}
		}()
	}
	wg.Wait()
	if got := identity.calls.Load(); got < 1 || got > n {
		t.Errorf("identity resolve calls = %d, want 1..%d", got, n)
	}
	if got := nextCalls.Load(); got != n {
		t.Errorf("next handler calls = %d, want %d", got, n)
	}
	doProvisioned(handler, bearer)
	if got := identity.calls.Load(); got > n {
		t.Errorf("a request after the burst re-resolved (calls = %d)", got)
	}
}

// TestProvision_InvalidBearerNeverReachesIdentity: token validation stays first — identity is
// never asked about a bearer the gateway itself rejects.
func TestProvision_InvalidBearerNeverReachesIdentity(t *testing.T) {
	_, identity, _, handler, _ := provisionFixture(t)
	if rec := doProvisioned(handler, "garbage.not.a.jwt"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if identity.calls.Load() != 0 {
		t.Error("identity must not be called for an invalid bearer")
	}
}
