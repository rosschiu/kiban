// SPDX-License-Identifier: Apache-2.0

// Package metrics is the platform's Prometheus exposition package: one Registry per service
// process, built once in that service's main and threaded through to (a) an HTTP middleware
// wrapped directly around the service's own mux (b) a GET /metrics handler on the service's own
// listener and (c) whichever service-specific Record*/Observe* calls that service's own code
// needs (authz's decision path, notification's delivery worker, the gateway's module proxy).
//
// Every service gets the standard set (http_requests_total, http_request_duration_seconds,
// http_requests_in_flight, kiban_build_info, kiban_db_pool_*) via New + ObserveDBPool.
// Service-specific families are opt-in (EnableAuthzDecisions/EnableDeliveryJobs/
// EnableGatewayUpstream) so a service's own /metrics never advertises a family it can't ever
// emit a non-zero sample for — the metrics reference doc documents exactly which services
// emit which names, and this package's own Names() is that same list's source of truth (see
// metrics_test.go's doc-drift pin, the code->doc half; the doc->code half lives in
// docs_metrics_live_test.go, kiban-test only).
//
// One dependency: github.com/prometheus/client_golang (promhttp + the client's own
// prometheus.Registry — never the process-global DefaultRegisterer, so a service's /metrics
// output is exactly this package's own families, nothing pulled in by another package's
// init()). No Go/process collectors (goroutines, GC, memory) are registered — kept out
// specifically so the doc<->code drift pin stays exact rather than needing to special-case an
// open-ended process-metrics family.
package metrics

import (
	"net/http"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	dto "github.com/prometheus/client_model/go"

	"github.com/rosschiu/kiban/internal/httpx"
)

// The 13 canonical metric names this package can ever register, grouped as
// the metrics reference doc's table groups them. Names() returns exactly this list — the
// unit-test half of the doc<->code drift pin (metrics_test.go) diffs it against the doc's own
// parsed table, in both directions.
const (
	NameHTTPRequestsTotal       = "http_requests_total"
	NameHTTPRequestDuration     = "http_request_duration_seconds"
	NameHTTPRequestsInFlight    = "http_requests_in_flight"
	NameBuildInfo               = "kiban_build_info"
	NameDBPoolAcquiredConns     = "kiban_db_pool_acquired_conns"
	NameDBPoolIdleConns         = "kiban_db_pool_idle_conns"
	NameDBPoolMaxConns          = "kiban_db_pool_max_conns"
	NameAuthzDecisionsTotal     = "kiban_authz_decisions_total"
	NameAuthzDecisionDuration   = "kiban_authz_decision_duration_seconds"
	NameDeliveryJobs            = "kiban_delivery_jobs"
	NameDeliveryAttemptsTotal   = "kiban_delivery_attempts_total"
	NameGatewayUpstreamRequests = "kiban_gateway_upstream_requests_total"
	NameGatewayUpstreamDuration = "kiban_gateway_upstream_duration_seconds"
)

// Names returns every metric name this package knows how to register, standard set first (every
// service) then the service-specific families in the order the metrics reference doc lists
// them (authz, notification, gateway).
func Names() []string {
	return []string{
		NameHTTPRequestsTotal, NameHTTPRequestDuration, NameHTTPRequestsInFlight, NameBuildInfo,
		NameDBPoolAcquiredConns, NameDBPoolIdleConns, NameDBPoolMaxConns,
		NameAuthzDecisionsTotal, NameAuthzDecisionDuration,
		NameDeliveryJobs, NameDeliveryAttemptsTotal,
		NameGatewayUpstreamRequests, NameGatewayUpstreamDuration,
	}
}

// Registry is one service's Prometheus collector set. Zero value is not usable — build with New.
// All Record*/Observe* methods are nil-receiver-safe no-ops (a *Registry left nil, e.g. in a unit
// test that doesn't care about metrics, never panics) and safe for concurrent use (every field is
// a prometheus collector, which is itself concurrency-safe).
type Registry struct {
	service string
	reg     *prometheus.Registry

	requestsTotal   *prometheus.CounterVec
	requestDuration *prometheus.HistogramVec
	inFlight        prometheus.Gauge

	authzDecisions   *prometheus.CounterVec
	authzDecisionDur *prometheus.HistogramVec
	deliveryJobs     *prometheus.GaugeVec
	deliveryAttempts *prometheus.CounterVec
	upstreamRequests *prometheus.CounterVec
	upstreamDuration *prometheus.HistogramVec
}

// New builds a Registry for service, registering the standard set immediately:
// http_requests_total/http_request_duration_seconds{route,method,status}, service.
// http_requests_in_flight{service}, and kiban_build_info{service,version,commit}=1 (version and
// commit come from the VERSION file / KIBAN_COMMIT — see internal/version).
// Call ObserveDBPool and whichever EnableXxx methods this service's own metric set needs before
// mounting Handler().
func New(service, version, commit string) *Registry {
	reg := prometheus.NewRegistry()
	r := &Registry{service: service, reg: reg}

	constLabels := prometheus.Labels{"service": service}

	r.requestsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name:        NameHTTPRequestsTotal,
		Help:        "Total HTTP requests handled by this service, by mux route pattern.",
		ConstLabels: constLabels,
	}, []string{"route", "method", "status"})

	r.requestDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:        NameHTTPRequestDuration,
		Help:        "HTTP request duration in seconds, by mux route pattern.",
		ConstLabels: constLabels,
		Buckets:     prometheus.DefBuckets,
	}, []string{"route", "method", "status"})

	r.inFlight = prometheus.NewGauge(prometheus.GaugeOpts{
		Name:        NameHTTPRequestsInFlight,
		Help:        "In-flight HTTP requests currently being handled by this service.",
		ConstLabels: constLabels,
	})

	buildInfo := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: NameBuildInfo,
		Help: "Always 1; labels carry the running build's identity.",
		ConstLabels: prometheus.Labels{
			"service": service, "version": version, "commit": commit,
		},
	})
	buildInfo.Set(1)

	reg.MustRegister(r.requestsTotal, r.requestDuration, r.inFlight, buildInfo)
	return r
}

// Handler returns the GET /metrics handler for this Registry's own registry — never the
// process-global DefaultGatherer, so this is exactly (and only) the families this package
// registered for this service.
func (r *Registry) Handler() http.Handler {
	if r == nil {
		return http.NotFoundHandler()
	}
	return promhttp.HandlerFor(r.reg, promhttp.HandlerOpts{})
}

// Gather returns this Registry's current metric families (the gateway's aggregated operator
// route merges them with every other service's scrape). Nil receiver: empty, no error.
func (r *Registry) Gather() ([]*dto.MetricFamily, error) {
	if r == nil {
		return nil, nil
	}
	return r.reg.Gather()
}

// unmatchedRoute is the route label used when the request never matched a registered mux
// pattern (r.Pattern empty — a raw 404, or a handler that isn't reached via ServeMux pattern
// dispatch at all). Never the raw path: an attacker-controlled 404 storm must not create
// unbounded label cardinality.
const unmatchedRoute = "unmatched"

// Middleware returns HTTP middleware recording http_requests_total/http_request_duration_seconds/
// http_requests_in_flight for every request that passes through it. It must wrap the service's
// own top-level mux DIRECTLY (nothing between this middleware and the mux may replace the
// *http.Request pointer, e.g. via r.WithContext) — net/http's ServeMux sets r.Pattern on the
// same *http.Request it was handed, in place, before invoking the matched handler
// (net/http/server.go's ServeMux.ServeHTTP), so reading r.Pattern AFTER next.ServeHTTP returns
// sees the mux's own route pattern here, never the raw path. Every cmd/*/main.go wires this
// innermost (closest to the mux), with httpx.Correlation/Recover/AccessLog wrapped around it —
// see those files' own comments for why the ordering matters.
func (r *Registry) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			if r == nil {
				next.ServeHTTP(w, req)
				return
			}
			r.inFlight.Inc()
			defer r.inFlight.Dec()

			start := time.Now()
			rec := &httpx.StatusRecorder{ResponseWriter: w, Status: http.StatusOK}
			next.ServeHTTP(rec, req)
			duration := time.Since(start).Seconds()

			route := req.Pattern
			if route == "" {
				route = unmatchedRoute
			}
			status := strconv.Itoa(rec.Status)
			method := normalizeMethod(req.Method)
			r.requestsTotal.WithLabelValues(route, method, status).Inc()
			r.requestDuration.WithLabelValues(route, method, status).Observe(duration)
		})
	}
}

// ObserveDBPool registers kiban_db_pool_acquired_conns/idle_conns/max_conns{service} as live
// GaugeFuncs reading pool.Stat() at each scrape — never a periodically-updated snapshot, so the
// exposed value is always current as of the scrape itself. Call once per service that owns a
// pgxpool.Pool (every foundation/module service except the gateway, which has none).
func (r *Registry) ObserveDBPool(pool *pgxpool.Pool) {
	if r == nil || pool == nil {
		return
	}
	constLabels := prometheus.Labels{"service": r.service}
	r.reg.MustRegister(
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Name: NameDBPoolAcquiredConns, Help: "Currently acquired connections in this service's DB pool.",
			ConstLabels: constLabels,
		}, func() float64 { return float64(pool.Stat().AcquiredConns()) }),
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Name: NameDBPoolIdleConns, Help: "Currently idle connections in this service's DB pool.",
			ConstLabels: constLabels,
		}, func() float64 { return float64(pool.Stat().IdleConns()) }),
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Name: NameDBPoolMaxConns, Help: "Configured maximum connections for this service's DB pool.",
			ConstLabels: constLabels,
		}, func() float64 { return float64(pool.Stat().MaxConns()) }),
	)
}

// EnableAuthzDecisions registers kiban_authz_decisions_total{service,reason} and
// kiban_authz_decision_duration_seconds{service} — authz only.
func (r *Registry) EnableAuthzDecisions() *Registry {
	if r == nil {
		return r
	}
	constLabels := prometheus.Labels{"service": r.service}
	r.authzDecisions = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: NameAuthzDecisionsTotal, Help: "Effective-access decisions, by reason code.",
		ConstLabels: constLabels,
	}, []string{"reason"})
	r.authzDecisionDur = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name: NameAuthzDecisionDuration, Help: "Effective-access decision latency in seconds.",
		ConstLabels: constLabels, Buckets: prometheus.DefBuckets,
	}, []string{})
	r.reg.MustRegister(r.authzDecisions, r.authzDecisionDur)
	return r
}

// RecordAuthzDecision records one effective-access decision outcome (reason is one of
// internal/authz/decision.Reason's 13 codes, ALLOWED included) and how long it took to reach.
func (r *Registry) RecordAuthzDecision(reason string, d time.Duration) {
	if r == nil || r.authzDecisions == nil {
		return
	}
	r.authzDecisions.WithLabelValues(reason).Inc()
	r.authzDecisionDur.WithLabelValues().Observe(d.Seconds())
}

// EnableDeliveryJobs registers kiban_delivery_jobs{service,state} (gauge) and
// kiban_delivery_attempts_total{service,kind,outcome} (counter) — notification only.
func (r *Registry) EnableDeliveryJobs() *Registry {
	if r == nil {
		return r
	}
	constLabels := prometheus.Labels{"service": r.service}
	r.deliveryJobs = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: NameDeliveryJobs, Help: "Delivery jobs currently in each state (pending/done/dead).",
		ConstLabels: constLabels,
	}, []string{"state"})
	r.deliveryAttempts = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: NameDeliveryAttemptsTotal, Help: "Delivery attempts, by job kind and outcome.",
		ConstLabels: constLabels,
	}, []string{"kind", "outcome"})
	r.reg.MustRegister(r.deliveryJobs, r.deliveryAttempts)
	return r
}

// SetDeliveryJobsGauge sets kiban_delivery_jobs{state} from a fresh state->count snapshot
// (counts is expected to come from a single grouped COUNT query — a periodic re-count,
// chosen over updating the gauge on every individual state transition so the worker's own hot
// path never blocks on a metrics call).
// States absent from counts are set to 0 (never left stale from a previous snapshot).
func (r *Registry) SetDeliveryJobsGauge(counts map[string]int) {
	if r == nil || r.deliveryJobs == nil {
		return
	}
	for _, state := range []string{"pending", "done", "dead"} {
		r.deliveryJobs.WithLabelValues(state).Set(float64(counts[state]))
	}
}

// RecordDeliveryAttempt records one delivery attempt's outcome (kind: "email"|"webhook";
// outcome: "success"|"retry"|"dead").
func (r *Registry) RecordDeliveryAttempt(kind, outcome string) {
	if r == nil || r.deliveryAttempts == nil {
		return
	}
	r.deliveryAttempts.WithLabelValues(kind, outcome).Inc()
}

// EnableGatewayUpstream registers kiban_gateway_upstream_requests_total{service,module,status}
// and kiban_gateway_upstream_duration_seconds{service,module} — gateway only.
func (r *Registry) EnableGatewayUpstream() *Registry {
	if r == nil {
		return r
	}
	constLabels := prometheus.Labels{"service": r.service}
	r.upstreamRequests = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: NameGatewayUpstreamRequests, Help: "Gateway module-proxy upstream responses, by module and status.",
		ConstLabels: constLabels,
	}, []string{"module", "status"})
	r.upstreamDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name: NameGatewayUpstreamDuration, Help: "Gateway module-proxy upstream latency in seconds, by module.",
		ConstLabels: constLabels, Buckets: prometheus.DefBuckets,
	}, []string{"module"})
	r.reg.MustRegister(r.upstreamRequests, r.upstreamDuration)
	return r
}

// RecordGatewayUpstream records one proxied module request's outcome as observed at the
// gateway's own reverse-proxy boundary (status 0 from the proxy's ErrorHandler path is
// normalized to the actual status code the gateway wrote — the caller passes the real one).
func (r *Registry) RecordGatewayUpstream(module string, status int, d time.Duration) {
	if r == nil || r.upstreamRequests == nil {
		return
	}
	statusStr := strconv.Itoa(status)
	r.upstreamRequests.WithLabelValues(module, statusStr).Inc()
	r.upstreamDuration.WithLabelValues(module).Observe(d.Seconds())
}

// normalizeMethod bounds the `method` label's cardinality: the HTTP method token is
// attacker-controlled on an edge-facing listener, so anything outside the standard set is
// folded into "OTHER". Route patterns are already bounded
// (mux pattern, never the raw path); status is a 3-digit code.
func normalizeMethod(m string) string {
	switch m {
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch,
		http.MethodDelete, http.MethodOptions, http.MethodConnect, http.MethodTrace:
		return m
	}
	return "OTHER"
}
