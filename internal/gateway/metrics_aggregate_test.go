// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rosschiu/kiban/internal/obs/metrics"
)

// fakeMetricsUpstream answers GET /metrics with status+body after delay.
func fakeMetricsUpstream(t *testing.T, status int, body string, delay time.Duration) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/metrics" {
			t.Errorf("upstream got path %q, want /metrics", r.URL.Path)
		}
		time.Sleep(delay)
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func aggregateBody(t *testing.T, own *metrics.Registry, foundation map[string]string, timeout time.Duration) (string, http.Header) {
	t.Helper()
	agg := newMetricsAggregator(own, foundation, nil)
	if timeout > 0 {
		agg.timeout = timeout
	}
	rec := httptest.NewRecorder()
	agg.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/platform/metrics", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (the aggregate is always 200); body: %s", rec.Code, rec.Body.String())
	}
	return rec.Body.String(), rec.Header()
}

func mustContain(t *testing.T, body string, lines ...string) {
	t.Helper()
	for _, l := range lines {
		if !strings.Contains(body, l+"\n") {
			t.Errorf("aggregate lacks line %q; body:\n%s", l, body)
		}
	}
}

func TestMetricsAggregate_LabelInjectionAndUp(t *testing.T) {
	up := fakeMetricsUpstream(t, 200, "# HELP foo Foo.\n# TYPE foo gauge\nfoo 1\nbar{a=\"b\"} 2\nbaz{service=\"stale\",z=\"q\"} 3\n", 0)
	body, hdr := aggregateBody(t, nil, map[string]string{"reg": up.URL}, 0)
	mustContain(t, body,
		`foo{service="reg"} 1`,
		`bar{a="b",service="reg"} 2`,
		`baz{service="reg",z="q"} 3`, // an upstream's own service label is replaced, not duplicated
		`kiban_metrics_scrape_up{service="reg"} 1`,
		`kiban_metrics_scrape_up{service="gateway"} 1`,
		`# TYPE kiban_metrics_scrape_up gauge`,
	)
	if ct := hdr.Get("Content-Type"); ct != metricsContentType {
		t.Errorf("Content-Type = %q, want %q", ct, metricsContentType)
	}
}

func TestMetricsAggregate_OwnRegistryIsLabeledGateway(t *testing.T) {
	own := metrics.New("gateway", "v", "c")
	body, _ := aggregateBody(t, own, nil, 0)
	if !strings.Contains(body, `kiban_build_info{commit="c",service="gateway",version="v"} 1`) {
		t.Fatalf("own registry missing or unlabeled:\n%s", body)
	}
}

func TestMetricsAggregate_FailuresYieldUpZeroOnly(t *testing.T) {
	cases := map[string]*httptest.Server{
		"http500":   fakeMetricsUpstream(t, 500, "boom 1\n", 0),
		"malformed": fakeMetricsUpstream(t, 200, "good 1\nthis is not a sample line\n", 0),
		"timeout":   fakeMetricsUpstream(t, 200, "late 1\n", 300*time.Millisecond),
		"dead":      nil,
	}
	foundation := map[string]string{}
	for name, srv := range cases {
		if srv == nil {
			foundation[name] = "http://127.0.0.1:1" // nothing listens
			continue
		}
		foundation[name] = srv.URL
	}
	body, _ := aggregateBody(t, nil, foundation, 50*time.Millisecond)
	for name := range cases {
		mustContain(t, body, `kiban_metrics_scrape_up{service="`+name+`"} 0`)
	}
	for _, leaked := range []string{"boom", "good", "late"} {
		if strings.Contains(body, leaked+"{") {
			t.Errorf("failed target leaked series %q:\n%s", leaked, body)
		}
	}
}

func TestMetricsAggregate_NameCollisionMergesUnderOneHeader(t *testing.T) {
	a := fakeMetricsUpstream(t, 200, "# HELP shared First help.\n# TYPE shared counter\nshared 1\n", 0)
	b := fakeMetricsUpstream(t, 200, "# HELP shared Second help.\n# TYPE shared counter\nshared 2\n", 0)
	body, _ := aggregateBody(t, nil, map[string]string{"a": a.URL, "b": b.URL}, 0)
	mustContain(t, body, `shared{service="a"} 1`, `shared{service="b"} 2`)
	if n := strings.Count(body, "# TYPE shared "); n != 1 {
		t.Errorf("# TYPE shared appears %d times, want 1:\n%s", n, body)
	}
	if n := strings.Count(body, "# HELP shared "); n != 1 {
		t.Errorf("# HELP shared appears %d times, want 1:\n%s", n, body)
	}
}

func TestMetricsAggregate_EscapedLabelValuesSurvive(t *testing.T) {
	up := fakeMetricsUpstream(t, 200, "esc{path=\"a\\\"b\\\\c\\nd\"} 1\n", 0)
	body, _ := aggregateBody(t, nil, map[string]string{"reg": up.URL}, 0)
	mustContain(t, body, `esc{path="a\"b\\c\nd",service="reg"} 1`)
}

// The mounted route: superadmin guard in front, and the catalog's installed+enabled modules
// (host from moduleHost, port from the catalog) are scraped while a disabled one is not.
func TestPlatformMetricsRoute_AggregatesEnabledModules(t *testing.T) {
	enabled := fakeMetricsUpstream(t, 200, "mod_metric 7\n", 0)
	disabled := fakeMetricsUpstream(t, 200, "never_scraped 1\n", 0)
	registry := newRegistryStub(t)
	off := readyEntry(t, "off", disabled.URL)
	off.Enabled = false
	registry.set([]catalogRow{readyEntry(t, "notification", enabled.URL), off}, nil)

	jwks := newFakeJWKSServer(t)
	verifier := newTestVerifier(t, jwks.URL+"/certs")
	authz := fakeAuthzServer(t, http.StatusOK, `{"data":{"allowed":true,"reason":"ALLOWED","evidence":[]}}`)
	agg := newMetricsAggregator(metrics.New("gateway", "v", "c"), map[string]string{"registry": registry.server.URL}, NewCatalogClient(registry.server.URL, nil))
	mux := http.NewServeMux()
	mountPlatformRoutes(mux, verifier, nil, mustParseAbsoluteURL(registry.server.URL), NewAuthzAdminClient(authz.URL), agg)

	req := httptest.NewRequest(http.MethodGet, "/api/platform/metrics", nil)
	req.Header.Set("Authorization", "Bearer "+jwks.signToken(t, tokenOpts{subject: "su", audience: []string{testAudience}}))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	mustContain(t, body,
		`mod_metric{service="notification"} 7`,
		`kiban_metrics_scrape_up{service="notification"} 1`,
		`kiban_metrics_scrape_up{service="registry"} 0`, // the stub has no /metrics
		`kiban_metrics_scrape_up{service="gateway"} 1`,
	)
	if strings.Contains(body, "never_scraped") || strings.Contains(body, `service="off"`) {
		t.Errorf("disabled module was scraped:\n%s", body)
	}
}
