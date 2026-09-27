// SPDX-License-Identifier: Apache-2.0

// Package testchaos provides shared "dependency down" fake upstream servers for chaos tests:
// every module's HTTP layer must prove fail-closed (authz-down -> 503
// AUTHORIZATION_UNAVAILABLE, org-down -> 503, never a fallback to stale data) and, where the
// module's design says so, fail-open-by-design (notification-down must not fail the business
// write it's attached to). Rather than each module hand-rolling its own down-server plumbing,
// this package is the ONE place that models the three concrete "down" shapes a real dependency
// exhibits: connection-refused, slower-than-the-client-timeout, and a well-formed 500. Every
// caller supplies its own *http.Client with an explicit Timeout — this package never assumes one.
package testchaos

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// RefusedURL returns a URL nothing listens on, so any request against it fails immediately with
// a connection-refused transport error (no network round trip, no test-time cost) — the
// "upstream process is down" shape.
func RefusedURL() string {
	return "http://127.0.0.1:1"
}

// SlowServer starts an httptest server that sleeps for delay before responding 200 with a
// minimal well-formed envelope body. Pair delay with a caller *http.Client whose Timeout is
// shorter, so the request observed by the module under test is a client-side timeout error —
// the "upstream is up but wedged" shape, distinct from RefusedURL's immediate failure. The
// server is closed automatically via t.Cleanup.
func SlowServer(t *testing.T, delay time.Duration) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(delay):
		case <-r.Context().Done():
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"data":{}}`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// ErrorServer starts an httptest server that always responds with the given status and an empty
// body — the "upstream is up but erroring" shape (typically 500). The server is closed
// automatically via t.Cleanup.
func ErrorServer(t *testing.T, status int) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
	}))
	t.Cleanup(srv.Close)
	return srv
}
