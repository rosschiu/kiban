// SPDX-License-Identifier: Apache-2.0

//go:build bench

package bench

// Engine latency benchmark: warmup 200, measured 2000 checks in the 50/25/25 deep/direct/deny
// mix, 20 rounds of 100 batchCan items, with batchCan going through
// internal/authz/engine.Engine.BatchCan's concurrent worker pool (8 goroutines, shared sync.Map
// memo, one pgxpool.Pool). Emits bench-results.json (machine-readable) and appends a
// re-measurement section to the bench report — no hand-typed numbers.

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"math/rand"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/rosschiu/kiban/internal/authz/engine"
)

const (
	warmupCount      = 200
	measuredTotal    = 2000
	deepAllowShare   = 0.50
	directAllowShare = 0.25

	batchRounds      = 20
	batchItemsPerRnd = 100

	checkP95TargetMs    = 10.0
	batchCanP95TargetMs = 50.0
)

type classStats struct {
	Class  string  `json:"class"`
	N      int     `json:"n"`
	MinMs  float64 `json:"minMs"`
	P50Ms  float64 `json:"p50Ms"`
	P95Ms  float64 `json:"p95Ms"`
	P99Ms  float64 `json:"p99Ms"`
	MaxMs  float64 `json:"maxMs"`
	MeanMs float64 `json:"meanMs"`
}

func computeStats(class string, samples []float64) classStats {
	cp := append([]float64(nil), samples...)
	sort.Float64s(cp)
	sum := 0.0
	for _, v := range cp {
		sum += v
	}
	n := len(cp)
	if n == 0 {
		return classStats{Class: class}
	}
	return classStats{
		Class: class, N: n, MinMs: cp[0],
		P50Ms: percentile(cp, 50), P95Ms: percentile(cp, 95), P99Ms: percentile(cp, 99),
		MaxMs: cp[n-1], MeanMs: sum / float64(n),
	}
}

func percentile(sorted []float64, p float64) float64 {
	n := len(sorted)
	if n == 0 {
		return 0
	}
	idx := int(math.Ceil(p/100*float64(n))) - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= n {
		idx = n - 1
	}
	return sorted[idx]
}

type hostSpecs struct {
	GoVersion   string `json:"goVersion"`
	GOARCH      string `json:"goarch"`
	GOOS        string `json:"goos"`
	NumCPU      int    `json:"numCPU"`
	CPUModel    string `json:"cpuModel"`
	MemTotalGiB string `json:"memTotalGiB"`
}

func gatherHostSpecs() hostSpecs {
	hs := hostSpecs{GoVersion: runtime.Version(), GOARCH: runtime.GOARCH, GOOS: runtime.GOOS, NumCPU: runtime.NumCPU()}
	if data, err := os.ReadFile("/proc/cpuinfo"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "model name") {
				if parts := strings.SplitN(line, ":", 2); len(parts) == 2 {
					hs.CPUModel = strings.TrimSpace(parts[1])
				}
				break
			}
		}
	}
	if data, err := os.ReadFile("/proc/meminfo"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "MemTotal:") {
				if fields := strings.Fields(line); len(fields) >= 2 {
					if kb, err := strconv.ParseFloat(fields[1], 64); err == nil {
						hs.MemTotalGiB = fmt.Sprintf("%.1f", kb/1024/1024)
					}
				}
				break
			}
		}
	}
	return hs
}

type batchCanStats struct {
	Rounds          int     `json:"rounds"`
	ItemsPerRound   int     `json:"itemsPerRound"`
	Workers         int     `json:"workers"`
	RoundTotalP50Ms float64 `json:"roundTotalP50Ms"`
	RoundTotalP95Ms float64 `json:"roundTotalP95Ms"`
	RoundTotalP99Ms float64 `json:"roundTotalP99Ms"`
	RoundTotalMinMs float64 `json:"roundTotalMinMs"`
	RoundTotalMaxMs float64 `json:"roundTotalMaxMs"`
}

type benchResult struct {
	GeneratedAt         string        `json:"generatedAt"`
	Host                hostSpecs     `json:"host"`
	DatasetTotal        int64         `json:"datasetTotalTuples"`
	DatasetCounts       TupleCounts   `json:"datasetCounts"`
	HotCompanyID        string        `json:"hotCompanyID"`
	HotMembers          int           `json:"hotMembers"`
	HotBusinessObjs     int           `json:"hotBusinessObjects"`
	WarmupCount         int           `json:"warmupCount"`
	MeasuredTotal       int           `json:"measuredTotal"`
	CheckByClass        []classStats  `json:"checkByClass"`
	CheckOverallP95Ms   float64       `json:"checkOverallP95Ms"`
	BatchCan            batchCanStats `json:"batchCan"`
	EngineLines         int           `json:"engineLines"`
	CheckP95TargetMs    float64       `json:"checkP95TargetMs"`
	BatchCanP95TargetMs float64       `json:"batchCanP95TargetMs"`
	CheckPass           bool          `json:"checkPass"`
	BatchCanPass        bool          `json:"batchCanPass"`
	Errors              []string      `json:"errors"`
}

func TestBench(t *testing.T) {
	if testing.Short() {
		t.Skip("bench-authz: skipped under -short (1M-tuple load takes real time)")
	}
	ctx := context.Background()
	pool := authzPool(t)

	rows, counts, ids := DefaultLoadgen.Generate()
	n, err := Load(ctx, pool, rows)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	t.Logf("dataset loaded: %d tuples, HOT company %s", n, ids.HotCompanyID)

	modelData, err := os.ReadFile(filepath.Join("..", "engine", "model.json"))
	if err != nil {
		t.Fatalf("read model.json: %v", err)
	}
	model, err := engine.LoadModel(modelData)
	if err != nil {
		t.Fatalf("LoadModel: %v", err)
	}
	en := &engine.Engine{Pool: pool, Model: model}

	if len(ids.HotBusinessIDs) == 0 || len(ids.OtherCompanyBiz) == 0 {
		t.Fatalf("loadgen sample IDs missing: %+v", ids)
	}

	type checkVec struct {
		class               string
		objType, objID, rel string
		subjType, subjID    string
	}
	nextDeep := func(i int) checkVec {
		obj := ids.HotBusinessIDs[i%len(ids.HotBusinessIDs)]
		return checkVec{"deep_inheritance_allow", "timesheet_entry", obj, "viewer", "user", ids.HotCompanyAdminID}
	}
	nextDirect := func(i int) checkVec {
		idx := i % len(ids.HotBusinessIDs)
		return checkVec{"direct_allow", "timesheet_entry", ids.HotBusinessIDs[idx], "viewer", "user", ids.HotGrantees[idx]}
	}
	nextDeny := func(i int) checkVec {
		obj := ids.OtherCompanyBiz[i%len(ids.OtherCompanyBiz)]
		return checkVec{"deny", "timesheet_entry", obj, "viewer", "user", ids.HotCompanyAdminID}
	}

	rng := rand.New(rand.NewSource(4242))

	for i := 0; i < warmupCount; i++ {
		var v checkVec
		switch i % 4 {
		case 0, 1:
			v = nextDeep(i)
		case 2:
			v = nextDirect(i)
		case 3:
			v = nextDeny(i)
		}
		if _, err := en.Check(ctx, v.objType, v.objID, v.rel, v.subjType, v.subjID); err != nil {
			t.Fatalf("warmup check error: %v", err)
		}
	}

	nDeep := int(measuredTotal * deepAllowShare)
	nDirect := int(measuredTotal * directAllowShare)
	nDeny := measuredTotal - nDeep - nDirect
	plan := make([]checkVec, 0, measuredTotal)
	for i := 0; i < nDeep; i++ {
		plan = append(plan, nextDeep(i))
	}
	for i := 0; i < nDirect; i++ {
		plan = append(plan, nextDirect(i))
	}
	for i := 0; i < nDeny; i++ {
		plan = append(plan, nextDeny(i))
	}
	rng.Shuffle(len(plan), func(i, j int) { plan[i], plan[j] = plan[j], plan[i] })

	byClass := map[string][]float64{}
	var allMs []float64
	var errs []string
	for _, v := range plan {
		start := time.Now()
		allowed, err := en.Check(ctx, v.objType, v.objID, v.rel, v.subjType, v.subjID)
		elapsed := time.Since(start).Seconds() * 1000
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s check(%s:%s#%s, %s:%s): %v", v.class, v.objType, v.objID, v.rel, v.subjType, v.subjID, err))
			continue
		}
		wantAllow := v.class != "deny"
		if allowed != wantAllow {
			t.Fatalf("class %s: check(%s:%s#%s, %s:%s) = %v, want %v", v.class, v.objType, v.objID, v.rel, v.subjType, v.subjID, allowed, wantAllow)
		}
		byClass[v.class] = append(byClass[v.class], elapsed)
		allMs = append(allMs, elapsed)
	}

	var checkStats []classStats
	for _, class := range []string{"deep_inheritance_allow", "direct_allow", "deny"} {
		checkStats = append(checkStats, computeStats(class, byClass[class]))
	}
	sortedAll := append([]float64(nil), allMs...)
	sort.Float64s(sortedAll)
	overallP95 := percentile(sortedAll, 95)

	// batchCan: 20 rounds of 100 mixed items, ONE subject per round, evaluated CONCURRENTLY
	// via engine.Engine.BatchCan (worker pool of 8, shared sync.Map memo) — the concurrency
	// under measurement here.
	var roundTotalsMs []float64
	for r := 0; r < batchRounds; r++ {
		nD := int(batchItemsPerRnd * deepAllowShare)
		nA := int(batchItemsPerRnd * directAllowShare)
		nN := batchItemsPerRnd - nD - nA
		items := make([]engine.BatchItem, 0, batchItemsPerRnd)
		for i := 0; i < nD; i++ {
			v := nextDeep(r*batchItemsPerRnd + i)
			items = append(items, engine.BatchItem{ObjType: v.objType, ObjID: v.objID, Rel: v.rel})
		}
		for i := 0; i < nA; i++ {
			// batchCan is single-subject; reuse deep-allow objects so every item in the round
			// is answerable by the round's one subject.
			v := nextDeep(r*batchItemsPerRnd + nD + i)
			items = append(items, engine.BatchItem{ObjType: v.objType, ObjID: v.objID, Rel: v.rel})
		}
		for i := 0; i < nN; i++ {
			v := nextDeny(r*batchItemsPerRnd + i)
			items = append(items, engine.BatchItem{ObjType: v.objType, ObjID: v.objID, Rel: v.rel})
		}

		roundStart := time.Now()
		results := en.BatchCan(ctx, "user", ids.HotCompanyAdminID, items)
		roundTotalsMs = append(roundTotalsMs, time.Since(roundStart).Seconds()*1000)

		for _, res := range results {
			if res.Err != nil {
				errs = append(errs, fmt.Sprintf("batchCan round %d item %s:%s#%s: %v", r, res.Item.ObjType, res.Item.ObjID, res.Item.Rel, res.Err))
			}
		}
	}

	sortedRounds := append([]float64(nil), roundTotalsMs...)
	sort.Float64s(sortedRounds)
	bcStats := batchCanStats{
		Rounds: batchRounds, ItemsPerRound: batchItemsPerRnd, Workers: 8,
		RoundTotalP50Ms: percentile(sortedRounds, 50), RoundTotalP95Ms: percentile(sortedRounds, 95),
		RoundTotalP99Ms: percentile(sortedRounds, 99), RoundTotalMinMs: sortedRounds[0], RoundTotalMaxMs: sortedRounds[len(sortedRounds)-1],
	}

	engineLines := countLines(t, filepath.Join("..", "engine", "eval.go")) +
		countLines(t, filepath.Join("..", "engine", "model.go")) +
		countLines(t, filepath.Join("..", "engine", "batch.go"))

	result := benchResult{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339), Host: gatherHostSpecs(),
		DatasetTotal: n, DatasetCounts: counts, HotCompanyID: ids.HotCompanyID,
		HotMembers: DefaultLoadgen.HotMembers, HotBusinessObjs: DefaultLoadgen.HotBusiness,
		WarmupCount: warmupCount, MeasuredTotal: len(allMs), CheckByClass: checkStats,
		CheckOverallP95Ms: overallP95, BatchCan: bcStats, EngineLines: engineLines,
		CheckP95TargetMs: checkP95TargetMs, BatchCanP95TargetMs: batchCanP95TargetMs,
		CheckPass: overallP95 < checkP95TargetMs, BatchCanPass: bcStats.RoundTotalP95Ms < batchCanP95TargetMs,
		Errors: errs,
	}

	jsonBytes, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		t.Fatalf("marshal bench result: %v", err)
	}
	if err := os.WriteFile("bench-results.json", jsonBytes, 0o644); err != nil {
		t.Fatalf("write bench-results.json: %v", err)
	}
	t.Logf("wrote bench-results.json")

	reportPath := filepath.Join("bench-report.md")
	if err := appendT104Section(reportPath, result); err != nil {
		t.Fatalf("append report section: %v", err)
	}
	t.Logf("appended re-measurement section to %s", reportPath)

	t.Logf("check overall p95=%.3fms (target <%.0fms, pass=%v)", overallP95, checkP95TargetMs, result.CheckPass)
	t.Logf("batchCan(100) round-total p95=%.3fms (target <%.0fms, pass=%v)", bcStats.RoundTotalP95Ms, batchCanP95TargetMs, result.BatchCanPass)
	if len(errs) > 0 {
		t.Logf("%d errors during measurement (see bench-results.json)", len(errs))
	}

	if !result.CheckPass || !result.BatchCanPass {
		t.Errorf("bench gate MISSED: checkPass=%v batchCanPass=%v — see bench-results.json", result.CheckPass, result.BatchCanPass)
	}
}

func countLines(t *testing.T, path string) int {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("count lines %s: %v", path, err)
	}
	return strings.Count(string(data), "\n")
}

// appendT104Section appends (or replaces, if already present from a prior run) the
// re-measurement section to the bench report — the report's earlier content stays untouched.
func appendT104Section(path string, r benchResult) error {
	pass := func(b bool) string {
		if b {
			return "PASS"
		}
		return "FAIL"
	}

	var sb strings.Builder
	sb.WriteString("\n## Re-measurement (concurrent batch decisions)\n\n")
	sb.WriteString(fmt.Sprintf("Generated: %s · Source: `internal/authz/bench/bench-results.json` (emitted by\n", r.GeneratedAt))
	sb.WriteString("`make bench-authz`). Same protocol as the measurement above, against the SAME dataset\n")
	sb.WriteString("shapes and cardinalities, EXCEPT `batchCan` now runs through the product\n")
	sb.WriteString("`internal/authz/engine.Engine.BatchCan` — a worker pool of 8 goroutines over one shared\n")
	sb.WriteString("`pgxpool.Pool`, memo shared via `sync.Map` — instead of the spike's sequential loop.\n\n")

	sb.WriteString("### Host\n\n| Field | Value |\n|---|---|\n")
	sb.WriteString(fmt.Sprintf("| CPU | %s |\n| Cores | %d |\n| Memory | %s GiB |\n| Go | %s (%s/%s) |\n\n",
		r.Host.CPUModel, r.Host.NumCPU, r.Host.MemTotalGiB, r.Host.GoVersion, r.Host.GOOS, r.Host.GOARCH))

	sb.WriteString(fmt.Sprintf("### Dataset\n\nTotal tuples: **%d**. HOT company `%s` — %d members, %d business objects.\n\n",
		r.DatasetTotal, r.HotCompanyID, r.HotMembers, r.HotBusinessObjs))

	sb.WriteString("### Check latency by class\n\n| Class | N | p50 (ms) | p95 (ms) | p99 (ms) |\n|---|---|---|---|---|\n")
	for _, cs := range r.CheckByClass {
		sb.WriteString(fmt.Sprintf("| %s | %d | %.3f | %.3f | %.3f |\n", cs.Class, cs.N, cs.P50Ms, cs.P95Ms, cs.P99Ms))
	}
	sb.WriteString(fmt.Sprintf("\nOverall check p95 (%d measured): **%.3f ms**.\n\n", r.MeasuredTotal, r.CheckOverallP95Ms))

	sb.WriteString("### batchCan(100) latency — CONCURRENT (worker pool of 8)\n\n")
	sb.WriteString("| Metric | min (ms) | p50 (ms) | p95 (ms) | p99 (ms) | max (ms) |\n|---|---|---|---|---|---|\n")
	sb.WriteString(fmt.Sprintf("| Round total (%d rounds x %d items) | %.3f | %.3f | %.3f | %.3f | %.3f |\n\n",
		r.BatchCan.Rounds, r.BatchCan.ItemsPerRound, r.BatchCan.RoundTotalMinMs, r.BatchCan.RoundTotalP50Ms,
		r.BatchCan.RoundTotalP95Ms, r.BatchCan.RoundTotalP99Ms, r.BatchCan.RoundTotalMaxMs))

	sb.WriteString(fmt.Sprintf("### Engine size\n\n`internal/authz/engine/{eval,model,batch}.go` combined: **%d lines** (fence: 4,000).\n\n", r.EngineLines))

	sb.WriteString("### Pass/fail against the performance gate\n\n| Target | Threshold | Measured | Result |\n|---|---|---|---|\n")
	sb.WriteString(fmt.Sprintf("| `check` p95 | < %.0f ms | %.3f ms | **%s** |\n", r.CheckP95TargetMs, r.CheckOverallP95Ms, pass(r.CheckPass)))
	sb.WriteString(fmt.Sprintf("| `batchCan(100)` round-total p95 | < %.0f ms | %.3f ms | **%s** |\n\n", r.BatchCanP95TargetMs, r.BatchCan.RoundTotalP95Ms, pass(r.BatchCanPass)))

	if len(r.Errors) > 0 {
		sb.WriteString(fmt.Sprintf("%d errors occurred during measurement (see bench-results.json).\n\n", len(r.Errors)))
	}

	existing, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	content := string(existing)
	marker := "\n## Re-measurement"
	if idx := strings.Index(content, marker); idx >= 0 {
		content = content[:idx]
	}
	return os.WriteFile(path, []byte(content+sb.String()), 0o644)
}
