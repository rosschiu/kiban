// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// fakeStep is a minimal Step for Runner tests — the "frame" tests exercise ordering and
// truthful outcome propagation without needing a real database or subprocess.
type fakeStep struct {
	name    string
	outcome Outcome
	detail  string
	err     error
	calls   *[]string // appends name here when Run executes, proving/disproving call order
}

func (f fakeStep) Name() string { return f.name }

func (f fakeStep) Run(ctx context.Context, deps *Deps) (Outcome, string, error) {
	if f.calls != nil {
		*f.calls = append(*f.calls, f.name)
	}
	return f.outcome, f.detail, f.err
}

func TestFrame_Runner_RunsStepsInOrderWithTruthfulOutcomes(t *testing.T) {
	var calls []string
	runner := &Runner{Steps: []Step{
		fakeStep{name: "a", outcome: OutcomeApplied, detail: "did work", calls: &calls},
		fakeStep{name: "b", outcome: OutcomeConverged, detail: "already there", calls: &calls},
		fakeStep{name: "c", outcome: OutcomeApplied, detail: "did more work", calls: &calls},
	}}

	results, err := runner.Run(context.Background(), &Deps{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got, want := calls, []string{"a", "b", "c"}; !equalStrings(got, want) {
		t.Fatalf("call order = %v, want %v", got, want)
	}
	if len(results) != 3 {
		t.Fatalf("got %d results, want 3", len(results))
	}
	wantOutcomes := []Outcome{OutcomeApplied, OutcomeConverged, OutcomeApplied}
	for i, res := range results {
		if res.Step != calls[i] {
			t.Errorf("results[%d].Step = %q, want %q", i, res.Step, calls[i])
		}
		if res.Outcome != wantOutcomes[i] {
			t.Errorf("results[%d].Outcome = %q, want %q", i, res.Outcome, wantOutcomes[i])
		}
		if res.Err != nil {
			t.Errorf("results[%d].Err = %v, want nil", i, res.Err)
		}
	}
}

func TestFrame_Runner_StopsAtFirstFailureNoClaimedRollback(t *testing.T) {
	var calls []string
	failErr := errors.New("boom")
	runner := &Runner{Steps: []Step{
		fakeStep{name: "a", outcome: OutcomeApplied, calls: &calls},
		fakeStep{name: "b", outcome: OutcomeFailed, err: failErr, calls: &calls},
		fakeStep{name: "c", outcome: OutcomeApplied, calls: &calls},
	}}

	results, err := runner.Run(context.Background(), &Deps{})
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
	if !errors.Is(err, failErr) {
		t.Errorf("error = %v, want it to wrap %v", err, failErr)
	}
	if got, want := calls, []string{"a", "b"}; !equalStrings(got, want) {
		t.Fatalf("call order = %v, want %v (step c must never run after b fails)", got, want)
	}
	if len(results) != 2 {
		t.Fatalf("got %d results, want 2 (only the steps that actually ran)", len(results))
	}
	if results[1].Outcome != OutcomeFailed || results[1].Err != failErr {
		t.Errorf("results[1] = %+v, want Failed/failErr", results[1])
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestFrame_AdvisoryLock_SecondRunWaits proves the Postgres advisory-lock serialization: two
// concurrent bootstrap runs against the SAME database never interleave —
// the second run's fn only starts after the first's has fully finished (and released the lock),
// never overlapping it.
func TestFrame_AdvisoryLock_SecondRunWaits(t *testing.T) {
	pool := bootstrapAdminPool(t)

	var mu sync.Mutex
	var events []string
	record := func(s string) {
		mu.Lock()
		events = append(events, s)
		mu.Unlock()
	}

	var wg sync.WaitGroup
	start := make(chan struct{})

	run := func(label string, hold time.Duration) {
		defer wg.Done()
		<-start
		err := WithAdvisoryLock(context.Background(), pool, func(ctx context.Context) error {
			record(label + ":start")
			time.Sleep(hold)
			record(label + ":end")
			return nil
		})
		if err != nil {
			t.Errorf("%s: WithAdvisoryLock: %v", label, err)
		}
	}

	wg.Add(2)
	go run("first", 300*time.Millisecond)
	go run("second", 50*time.Millisecond)
	close(start) // both goroutines race to acquire the lock at roughly the same instant

	wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	if len(events) != 4 {
		t.Fatalf("got %d events, want 4: %v", len(events), events)
	}
	indexOf := func(s string) int {
		for i, e := range events {
			if e == s {
				return i
			}
		}
		t.Fatalf("event %q missing from %v", s, events)
		return -1
	}
	firstStart, firstEnd := indexOf("first:start"), indexOf("first:end")
	secondStart, secondEnd := indexOf("second:start"), indexOf("second:end")
	// Non-overlapping: one run's whole [start,end] window must be entirely before the other's
	// — never interleaved, which is what "the lock serializes concurrent runs" means.
	nonOverlapping := (firstEnd < secondStart) || (secondEnd < firstStart)
	if !nonOverlapping {
		t.Fatalf("runs overlapped (lock did not serialize): events=%v firstStart=%d firstEnd=%d secondStart=%d secondEnd=%d",
			events, firstStart, firstEnd, secondStart, secondEnd)
	}
}
