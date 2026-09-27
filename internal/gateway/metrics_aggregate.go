// SPDX-License-Identifier: Apache-2.0

// `GET /api/platform/metrics` — ONE Prometheus text exposition for the whole platform (one
// scrape target): the gateway's own registry plus every foundation service's and every
// installed+enabled module's `/metrics`, fetched concurrently on the internal network. Every
// series carries `service="<name>"`; a target that fails, times out, over-runs the body budget
// or ships an unparseable body contributes only `kiban_metrics_scrape_up{service="x"} 0`, so
// the route is always 200 — a Prometheus scraping it sees a partial outage as a series, never
// as a failed scrape of the platform. Per-service `/metrics` listeners are unchanged.
package gateway

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/common/model"
	"google.golang.org/protobuf/proto"

	"github.com/rosschiu/kiban/internal/obs/metrics"
)

const (
	metricsScrapeTimeout   = 2 * time.Second
	metricsScrapeBodyLimit = 8 << 20 // 8 MiB across every upstream body
	metricsScrapeUpName    = "kiban_metrics_scrape_up"
	metricsContentType     = "text/plain; version=0.0.4; charset=utf-8"
)

// metricsTarget is one upstream `/metrics` to fold in, keyed by the `service` label it gets.
type metricsTarget struct {
	name string
	url  string
}

// metricsAggregator serves the aggregated exposition. own is this process's registry (nil-safe:
// then only upstreams appear); foundation maps service name -> base URL; catalog supplies the
// installed+enabled modules per request (host via moduleHost, port from the catalog entry).
type metricsAggregator struct {
	own        *metrics.Registry
	foundation map[string]string
	catalog    *CatalogClient
	timeout    time.Duration
	client     *http.Client
}

func newMetricsAggregator(own *metrics.Registry, foundation map[string]string, catalog *CatalogClient) *metricsAggregator {
	return &metricsAggregator{
		own: own, foundation: foundation, catalog: catalog,
		timeout: metricsScrapeTimeout, client: &http.Client{},
	}
}

func (a *metricsAggregator) targets(ctx context.Context) []metricsTarget {
	var ts []metricsTarget
	for name, base := range a.foundation {
		ts = append(ts, metricsTarget{name: name, url: base + "/metrics"})
	}
	if a.catalog != nil {
		// A catalog failure drops the modules from this scrape (no up series either: the set is
		// unknown); the registry target's own up=0 already says why.
		if snap, err := a.catalog.Get(ctx); err == nil {
			for key, e := range snap.byKey {
				if e.Installed && e.Enabled {
					ts = append(ts, metricsTarget{name: key, url: fmt.Sprintf("http://%s:%d/metrics", moduleHost(key), e.Port)})
				}
			}
		}
	}
	sort.Slice(ts, func(i, j int) bool { return ts[i].name < ts[j].name })
	return ts
}

func (a *metricsAggregator) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	targets := a.targets(r.Context())
	results := make([][]*dto.MetricFamily, len(targets))
	var wg sync.WaitGroup
	var budget atomic.Int64
	budget.Store(metricsScrapeBodyLimit)
	for i, t := range targets {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i] = a.scrape(r.Context(), t, &budget)
		}()
	}
	wg.Wait()

	merged := map[string]*dto.MetricFamily{}
	up := &dto.MetricFamily{
		Name: proto.String(metricsScrapeUpName), Type: dto.MetricType_GAUGE.Enum(),
		Help: proto.String("1 when the service's /metrics answered this aggregated scrape, 0 otherwise."),
	}
	add := func(service string, fams []*dto.MetricFamily, ok bool) {
		v := 0.0
		if ok {
			v = 1
		}
		up.Metric = append(up.Metric, &dto.Metric{
			Label: []*dto.LabelPair{{Name: proto.String("service"), Value: proto.String(service)}},
			Gauge: &dto.Gauge{Value: proto.Float64(v)},
		})
		for _, f := range fams {
			for _, m := range f.Metric {
				setLabel(m, "service", service)
			}
			if first, dup := merged[f.GetName()]; dup {
				if first.GetType() == f.GetType() { // first HELP/TYPE wins; a type clash drops the repeat
					first.Metric = append(first.Metric, f.Metric...)
				}
				continue
			}
			merged[f.GetName()] = f
		}
	}
	ownFams, err := a.own.Gather()
	add("gateway", ownFams, err == nil)
	for i, t := range targets {
		add(t.name, results[i], results[i] != nil)
	}
	merged[metricsScrapeUpName] = up

	names := make([]string, 0, len(merged))
	for n := range merged {
		names = append(names, n)
	}
	sort.Strings(names)
	var buf bytes.Buffer
	for _, n := range names {
		if _, err := expfmt.MetricFamilyToText(&buf, merged[n]); err != nil {
			http.Error(w, "metrics: encode "+n+": "+err.Error(), http.StatusInternalServerError)
			return
		}
	}
	w.Header().Set("Content-Type", metricsContentType)
	_, _ = w.Write(buf.Bytes())
}

// scrape fetches one target; nil means failed (any transport error, non-200, over budget, or
// unparseable text). A parsed-but-empty body yields a non-nil empty slice (up=1).
func (a *metricsAggregator) scrape(ctx context.Context, t metricsTarget, budget *atomic.Int64) []*dto.MetricFamily {
	ctx, cancel := context.WithTimeout(ctx, a.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, t.url, nil)
	if err != nil {
		return nil
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	// Known ceiling: the budget is reserved after the read, so concurrent targets can jointly
	// overrun 8 MiB by at most one body each; exact accounting needs a pre-reserved slice.
	limit := budget.Load()
	if limit <= 0 {
		return nil
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil || int64(len(body)) > limit {
		return nil
	}
	budget.Add(-int64(len(body)))
	parser := expfmt.NewTextParser(model.LegacyValidation)
	parsed, err := parser.TextToMetricFamilies(bytes.NewReader(body))
	if err != nil {
		return nil
	}
	fams := make([]*dto.MetricFamily, 0, len(parsed))
	for _, f := range parsed {
		fams = append(fams, f)
	}
	return fams
}

// setLabel sets name=value on m, replacing an existing pair (every service already stamps
// its own `service` const label) or appending one; pairs stay name-sorted.
func setLabel(m *dto.Metric, name, value string) {
	for _, lp := range m.Label {
		if lp.GetName() == name {
			lp.Value = proto.String(value)
			return
		}
	}
	m.Label = append(m.Label, &dto.LabelPair{Name: proto.String(name), Value: proto.String(value)})
	sort.Slice(m.Label, func(i, j int) bool { return m.Label[i].GetName() < m.Label[j].GetName() })
}
