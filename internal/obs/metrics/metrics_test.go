// SPDX-License-Identifier: Apache-2.0

package metrics

import (
	"bufio"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"
)

// docMetricNames parses docs/metrics.md's own "## Metric table" section, reading
// the first column of every markdown table row shaped `| `name` | type | ... |` — the doc IS
// the source of truth, so this is a real parse of the shipped doc file, never
// a hand-copied literal list that could silently drift from it.
func docMetricNames(t *testing.T) []string {
	t.Helper()

	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("metrics_test: could not determine caller for repo root lookup")
	}
	// this file lives at <repoRoot>/internal/obs/metrics/metrics_test.go
	repoRoot := filepath.Join(filepath.Dir(thisFile), "..", "..", "..")
	docPath := filepath.Join(repoRoot, "docs", "metrics.md")

	f, err := os.Open(docPath)
	if err != nil {
		t.Fatalf("open %s: %v", docPath, err)
	}
	defer f.Close()

	// Matches a markdown table row whose first cell is a backtick-quoted metric name, e.g.
	// "| `http_requests_total` | counter | `route`, `method`, `status` | ... |". The header/
	// separator rows ("| Name | Type | ... |", "|---|---|...|") never match (no backticks in the
	// first cell).
	rowPattern := regexp.MustCompile("^\\| `([a-zA-Z0-9_]+)` \\|")

	seen := map[string]bool{}
	var names []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		m := rowPattern.FindStringSubmatch(scanner.Text())
		if m == nil {
			continue
		}
		name := m[1]
		if !seen[name] {
			seen[name] = true
			names = append(names, name)
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan %s: %v", docPath, err)
	}
	if len(names) == 0 {
		t.Fatalf("parsed zero metric rows from %s — parser or doc structure broke", docPath)
	}
	return names
}

// TestNames_MatchesDoc_BothDirections is the code<->doc drift pin's unit-test half:
// every name Names() returns must appear in the doc's own table, AND every name
// the doc's table lists must be something Names() returns. A metric added to this package
// without a doc row, or a doc row for a metric this package never registers, fails here.
func TestNames_MatchesDoc_BothDirections(t *testing.T) {
	doc := docMetricNames(t)
	docSet := map[string]bool{}
	for _, n := range doc {
		docSet[n] = true
	}

	code := Names()
	codeSet := map[string]bool{}
	for _, n := range code {
		codeSet[n] = true
	}

	var codeNotInDoc, docNotInCode []string
	for _, n := range code {
		if !docSet[n] {
			codeNotInDoc = append(codeNotInDoc, n)
		}
	}
	for _, n := range doc {
		if !codeSet[n] {
			docNotInCode = append(docNotInCode, n)
		}
	}
	sort.Strings(codeNotInDoc)
	sort.Strings(docNotInCode)

	if len(codeNotInDoc) > 0 {
		t.Errorf("metrics registered in internal/obs/metrics but missing from docs/metrics.md's table: %v", codeNotInDoc)
	}
	if len(docNotInCode) > 0 {
		t.Errorf("metric rows in docs/metrics.md with no matching name in internal/obs/metrics.Names(): %v", docNotInCode)
	}
}

// TestNames_NoDuplicates guards Names() itself against a copy-paste duplicate, which would make
// the drift pin above pass vacuously for a genuinely missing name.
func TestNames_NoDuplicates(t *testing.T) {
	seen := map[string]bool{}
	for _, n := range Names() {
		if seen[n] {
			t.Errorf("Names() contains duplicate %q", n)
		}
		seen[n] = true
	}
}

// TestRegistry_StandardSetRegisters proves New() actually registers exactly the standard-set
// families (not the drift pin itself — that's Names()'s job above — but a check that New()
// doesn't silently register nothing, or something Handler() can't expose).
func TestRegistry_StandardSetRegisters(t *testing.T) {
	r := New("test-service", "0.1.0", "abc123")
	// CounterVec/HistogramVec families with zero observed label combinations are omitted from
	// Gather() entirely (client_golang's own behavior) — drive one request through Middleware so
	// http_requests_total/http_request_duration_seconds have at least one sample.
	handler := r.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/x", nil))

	families, err := r.reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	got := map[string]bool{}
	for _, mf := range families {
		got[mf.GetName()] = true
	}
	for _, want := range []string{NameHTTPRequestsTotal, NameHTTPRequestDuration, NameHTTPRequestsInFlight, NameBuildInfo} {
		if !got[want] {
			t.Errorf("New() did not register %q", want)
		}
	}
	// Service-specific families must NOT appear until their EnableXxx is called.
	for _, notWant := range []string{NameAuthzDecisionsTotal, NameDeliveryJobs, NameGatewayUpstreamRequests} {
		if got[notWant] {
			t.Errorf("New() registered %q before its EnableXxx was called", notWant)
		}
	}
}

// TestRegistry_EnableMethodsRegisterTheirOwnFamilies proves each EnableXxx call adds exactly its
// own families, nothing else's.
func TestRegistry_EnableMethodsRegisterTheirOwnFamilies(t *testing.T) {
	cases := []struct {
		name  string
		build func() *Registry
		want  []string
	}{
		{"authz", func() *Registry {
			r := New("authz", "v", "c").EnableAuthzDecisions()
			r.RecordAuthzDecision("ALLOWED", 0)
			return r
		}, []string{NameAuthzDecisionsTotal, NameAuthzDecisionDuration}},
		{"notification", func() *Registry {
			r := New("notification", "v", "c").EnableDeliveryJobs()
			r.RecordDeliveryAttempt("email", "success")
			r.SetDeliveryJobsGauge(map[string]int{"pending": 1})
			return r
		}, []string{NameDeliveryJobs, NameDeliveryAttemptsTotal}},
		{"gateway", func() *Registry {
			r := New("gateway", "v", "c").EnableGatewayUpstream()
			r.RecordGatewayUpstream("notification", 200, 0)
			return r
		}, []string{NameGatewayUpstreamRequests, NameGatewayUpstreamDuration}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := tc.build()
			families, err := r.reg.Gather()
			if err != nil {
				t.Fatalf("Gather: %v", err)
			}
			got := map[string]bool{}
			for _, mf := range families {
				got[mf.GetName()] = true
			}
			for _, want := range tc.want {
				if !got[want] {
					t.Errorf("%s: expected family %q registered, got families %v", tc.name, want, got)
				}
			}
		})
	}
}

// TestRegistry_Handler_ServesRealMetrics proves Handler() on a real (non-nil) Registry actually
// serves that Registry's own prometheus.Registry content, never the process-global default —
// TestRegistry_NilSafe below only exercises the nil-Registry 404 branch, leaving the real
// promhttp.HandlerFor(...) line itself unit-tested only by kiban-test-only live tests
// (docs_metrics_live_test.go) until this test.
func TestRegistry_Handler_ServesRealMetrics(t *testing.T) {
	r := New("metrics-handler-test", "0.0.0", "test")
	rec := httptest.NewRecorder()

	r.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "kiban_build_info") {
		t.Errorf("response body does not contain kiban_build_info; got:\n%s", rec.Body.String())
	}
}

// TestRegistry_NilSafe proves every Record*/Observe*/Handler/Middleware call on a nil *Registry
// is a safe no-op — every existing call site that doesn't wire metrics (most test fixtures)
// relies on this.
func TestRegistry_NilSafe(t *testing.T) {
	var r *Registry
	r.RecordAuthzDecision("ALLOWED", 0)
	r.RecordDeliveryAttempt("email", "success")
	r.SetDeliveryJobsGauge(map[string]int{"pending": 1})
	r.RecordGatewayUpstream("notification", 200, 0)
	r.ObserveDBPool(nil)
	if h := r.Handler(); h == nil {
		t.Error("Handler() on nil Registry returned nil instead of a 404 handler")
	}
	mw := r.Middleware()
	if mw == nil {
		t.Fatal("Middleware() on nil Registry returned nil")
	}
	called := false
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusTeapot)
	}))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", nil))
	if !called {
		t.Error("nil-Registry middleware never called next")
	}
	if rec.Code != http.StatusTeapot {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusTeapot)
	}
}

// The HTTP method token is attacker-controlled on an
// edge-facing listener; unknown methods must fold into "OTHER" so the label set stays bounded.
func TestNormalizeMethod_BoundsCardinality(t *testing.T) {
	for _, std := range []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "CONNECT", "TRACE"} {
		if got := normalizeMethod(std); got != std {
			t.Fatalf("normalizeMethod(%q) = %q, want identity", std, got)
		}
	}
	for _, junk := range []string{"FOO", "get", "PROPFIND", "X-ATTACK-1", "", "GET "} {
		if got := normalizeMethod(junk); got != "OTHER" {
			t.Fatalf("normalizeMethod(%q) = %q, want OTHER", junk, got)
		}
	}
}

// Middleware's statusRecorder wrapper used to embed
// http.ResponseWriter with no Flush() of its own, silently dropping http.Flusher even when the
// real underlying ResponseWriter implements it — a streaming/SSE handler wrapped by this
// middleware would build its response in memory instead of actually flushing. This proves a
// handler that flushes THROUGH the middleware reaches the real underlying Flusher:
// httptest.ResponseRecorder implements http.Flusher itself (setting Flushed=true), so if the
// flush reaches it, that field proves the whole chain (handler -> statusRecorder -> real writer)
// forwarded correctly.
func TestMiddleware_FlushForwardsToUnderlyingWriter(t *testing.T) {
	r := New("test", "0.0.0", "test")
	mw := r.Middleware()

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		f, ok := w.(http.Flusher)
		if !ok {
			t.Fatal("ResponseWriter passed to the wrapped handler does not implement http.Flusher")
		}
		w.WriteHeader(http.StatusOK)
		f.Flush()
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", nil))

	if !rec.Flushed {
		t.Error("Flush() through the middleware never reached the underlying httptest.ResponseRecorder")
	}
}
