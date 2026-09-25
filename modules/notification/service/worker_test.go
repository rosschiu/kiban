// SPDX-License-Identifier: Apache-2.0

package notification

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/rosschiu/kiban/internal/obs/metrics"
)

// seedDeliveryJob inserts one pending delivery_job directly (bypassing SendMessage's fan-out) so
// worker tests can drive ClaimJobs/CompleteJob/FailJob in isolation, against a real message row
// (delivery_job.message_id has a FK).
func seedDeliveryJob(t *testing.T, store *Store, companyID uuid.UUID) (messageID, jobID uuid.UUID) {
	t.Helper()
	ctx := context.Background()
	target := "https://203.0.113.10/inbound" // RFC 5737 TEST-NET-3: not private/loopback/link-local, passes the SSRF policy with no real network access
	c, err := store.CreateChannel(ctx, "actor:admin", companyID, "worker-test-chan", "Label", "webhook", &target)
	if err != nil {
		t.Fatalf("create channel: %v", err)
	}
	deleteChannelCascade(t, store, c.ID)
	m, _, err := store.SendMessage(ctx, "actor:admin", companyID, c.ID, "Subj", "Body", "")
	if err != nil {
		t.Fatalf("send message: %v", err)
	}
	jobs, err := store.ClaimJobs(ctx, 0, 10) // lease=0: claims immediately, we release it below
	if err != nil {
		t.Fatalf("claim seeded job: %v", err)
	}
	if len(jobs) != 1 {
		t.Fatalf("expected exactly 1 seeded job, got %d", len(jobs))
	}
	// Release the seed claim back to pending/unleased so the actual test starts from a clean
	// "never claimed" state (attempts intentionally left at 1 from this seed claim — tests that
	// care about the exact attempts count account for it).
	if _, err := store.pool.Exec(ctx, `UPDATE notification.delivery_job SET leased_until = NULL WHERE id = $1`, pgFromUUID(jobs[0].ID)); err != nil {
		t.Fatalf("release seed claim: %v", err)
	}
	return m.ID, jobs[0].ID
}

// insertPendingDeliveryJob creates a fresh company/channel/message (never claimed) and returns its
// single resulting delivery_job's id, left in status='pending' with leased_until NULL — unlike
// seedDeliveryJob, it never calls ClaimJobs, so it's safe to call more than once in the same test
// without one call's claim sweeping up a previously-inserted, still-pending row from another call.
func insertPendingDeliveryJob(t *testing.T, store *Store, keySuffix string) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	companyID := uuid.New()
	target := "https://203.0.113.10/inbound" // RFC 5737 TEST-NET-3, see seedDeliveryJob
	c, err := store.CreateChannel(ctx, "actor:admin", companyID, "chan-"+keySuffix, "Label", "webhook", &target)
	if err != nil {
		t.Fatalf("create channel: %v", err)
	}
	deleteChannelCascade(t, store, c.ID)
	m, _, err := store.SendMessage(ctx, "actor:admin", companyID, c.ID, "Subj", "Body", "")
	if err != nil {
		t.Fatalf("send message: %v", err)
	}
	var jobID uuid.UUID
	var pgID pgtype.UUID
	if err := store.pool.QueryRow(ctx, `SELECT id FROM notification.delivery_job WHERE message_id = $1`, pgFromUUID(m.ID)).Scan(&pgID); err != nil {
		t.Fatalf("query seeded job id: %v", err)
	}
	jobID = uuidFromPg(pgID)
	return jobID
}

func TestClaimJobs_SkipsLockedAndRespectsLeaseExpiry(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	companyID := uuid.New()
	_, jobID := seedDeliveryJob(t, store, companyID)

	// First claim succeeds (attempts becomes 2: 1 from the seed claim + 1 here).
	jobs, err := store.ClaimJobs(ctx, 50*time.Millisecond, 10)
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	if len(jobs) != 1 || jobs[0].ID != jobID {
		t.Fatalf("expected to claim the seeded job, got %+v", jobs)
	}
	if jobs[0].Attempts != 2 {
		t.Fatalf("expected attempts=2 (1 seed + 1 here), got %d", jobs[0].Attempts)
	}

	// Immediately re-claiming finds nothing: the lease hasn't expired yet.
	again, err := store.ClaimJobs(ctx, 50*time.Millisecond, 10)
	if err != nil {
		t.Fatalf("re-claim: %v", err)
	}
	if len(again) != 0 {
		t.Fatalf("expected no claimable jobs while the lease is live, got %+v", again)
	}
}

// TestLeaseCrashReclaim: "kill worker mid-lease,
// second worker completes after expiry". worker1 claims the job (simulating it starting delivery)
// and then does nothing further — a crash, from the job's point of view: no CompleteJob, no
// FailJob, ever. worker2 polls after the short lease expires, reclaims the SAME job (attempts
// increments again — proof it's a genuine reclaim, not a fresh job), and completes it.
func TestLeaseCrashReclaim(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	companyID := uuid.New()
	_, jobID := seedDeliveryJob(t, store, companyID)

	const lease = 150 * time.Millisecond

	// worker1: claims and "crashes" (never completes or fails the job).
	worker1Jobs, err := store.ClaimJobs(ctx, lease, 10)
	if err != nil {
		t.Fatalf("worker1 claim: %v", err)
	}
	if len(worker1Jobs) != 1 || worker1Jobs[0].ID != jobID {
		t.Fatalf("expected worker1 to claim the seeded job, got %+v", worker1Jobs)
	}
	attemptsAfterWorker1 := worker1Jobs[0].Attempts

	// Before the lease expires, a concurrent claim attempt (worker2 polling too early) finds
	// nothing — proves the reclaim below is really waiting on lease expiry, not racing it.
	tooEarly, err := store.ClaimJobs(ctx, lease, 10)
	if err != nil {
		t.Fatalf("too-early claim: %v", err)
	}
	if len(tooEarly) != 0 {
		t.Fatalf("expected no claimable jobs before the lease expires, got %+v", tooEarly)
	}

	time.Sleep(lease + 100*time.Millisecond) // let worker1's lease expire (simulated crash)

	// worker2: reclaims the SAME job after expiry.
	worker2Jobs, err := store.ClaimJobs(ctx, lease, 10)
	if err != nil {
		t.Fatalf("worker2 claim: %v", err)
	}
	if len(worker2Jobs) != 1 || worker2Jobs[0].ID != jobID {
		t.Fatalf("expected worker2 to reclaim the same job, got %+v", worker2Jobs)
	}
	if worker2Jobs[0].Attempts != attemptsAfterWorker1+1 {
		t.Fatalf("expected attempts to increment again on reclaim (%d -> %d), got %d",
			attemptsAfterWorker1, attemptsAfterWorker1+1, worker2Jobs[0].Attempts)
	}

	// worker2 completes it — the crash-recovery loop closes.
	if err := store.CompleteJob(ctx, jobID, worker2Jobs[0].LeaseToken); err != nil {
		t.Fatalf("worker2 complete: %v", err)
	}

	// worker1's (stale, already-superseded) lease token can never complete the job worker2 now
	// owns — this is the test's core assertion: "first Complete must no-op", proven
	// via ErrLeaseLost rather than a silent overwrite of worker2's 'done' state.
	if err := store.CompleteJob(ctx, jobID, worker1Jobs[0].LeaseToken); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("expected worker1's stale lease token to no-op with ErrLeaseLost, got %v", err)
	}

	// Now genuinely done: even after another lease expiry window, nothing is claimable.
	time.Sleep(lease + 50*time.Millisecond)
	final, err := store.ClaimJobs(ctx, lease, 10)
	if err != nil {
		t.Fatalf("final claim: %v", err)
	}
	for _, j := range final {
		if j.ID == jobID {
			t.Fatalf("expected the completed job to never be claimable again, got %+v", j)
		}
	}
}

func TestFailJob_RetriesThenDeadLettersAtMaxAttempts(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	companyID := uuid.New()
	_, jobID := seedDeliveryJob(t, store, companyID)

	// seedDeliveryJob already left attempts=1. Each loop iteration claims (attempts+1) then fails
	// back to pending (since FailJob dead-letters once attempts>=maxAttempts, this loop must stop
	// SHORT of that so the job is still "pending" for the final claim below to push it over the
	// line) — maxAttempts-2 iterations lands exactly on attempts=maxAttempts-1, still pending.
	for i := 0; i < maxAttempts-2; i++ {
		jobs, err := store.ClaimJobs(ctx, time.Millisecond, 10)
		if err != nil {
			t.Fatalf("claim (iteration %d): %v", i, err)
		}
		if len(jobs) != 1 {
			t.Fatalf("expected exactly 1 claimable job (iteration %d), got %d", i, len(jobs))
		}
		if err := store.FailJob(ctx, jobID, jobs[0].LeaseToken, jobs[0].Attempts, errors.New("simulated delivery failure")); err != nil {
			t.Fatalf("fail job (iteration %d): %v", i, err)
		}
		// FailJob now parks the job for retryBackoff(attempts) (seconds to minutes); this test
		// is about the attempts ladder, not the backoff (TestFailJob_BackoffHoldsJobBackFromReclaim
		// is), so clear the hold-back so the next claim sees the job immediately.
		if _, err := store.pool.Exec(ctx, `UPDATE notification.delivery_job SET leased_until = NULL WHERE id = $1`, pgFromUUID(jobID)); err != nil {
			t.Fatalf("clear backoff (iteration %d): %v", i, err)
		}
	}

	jobs, err := store.ClaimJobs(ctx, time.Millisecond, 10)
	if err != nil {
		t.Fatalf("final claim: %v", err)
	}
	if len(jobs) != 1 {
		t.Fatalf("expected the job still claimable for its final attempt, got %d", len(jobs))
	}
	if jobs[0].Attempts < maxAttempts {
		t.Fatalf("expected attempts >= maxAttempts (%d) by now, got %d", maxAttempts, jobs[0].Attempts)
	}
	if err := store.FailJob(ctx, jobID, jobs[0].LeaseToken, jobs[0].Attempts, errors.New("final failure")); err != nil {
		t.Fatalf("fail job (dead-letter): %v", err)
	}

	var status string
	if err := store.pool.QueryRow(ctx, `SELECT status FROM notification.delivery_job WHERE id = $1`, pgFromUUID(jobID)).Scan(&status); err != nil {
		t.Fatalf("query status: %v", err)
	}
	if status != "dead" {
		t.Fatalf("expected status=dead after maxAttempts failures, got %q", status)
	}
}

// fakeDeliverer is a Deliverer test double — the only case where this codebase's "mocks
// only for genuinely external systems" applies: mailpit/webhook-target are real containers
// (exercised by the curl proof + TestWorker_RunOnce below with a real HTTP webhook target), but
// unit-level Worker plumbing (claim -> deliver -> complete/fail wiring) doesn't need either.
type fakeDeliverer struct {
	err error
}

func (f *fakeDeliverer) Deliver(ctx context.Context, d JobDelivery) error { return f.err }

func TestWorker_RunOnce_CompletesOnSuccess(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	companyID := uuid.New()
	_, jobID := seedDeliveryJob(t, store, companyID)

	w := NewWorker(store, &fakeDeliverer{}, &fakeDeliverer{}, testLogger())
	w.LeaseDuration = time.Second
	n := w.runOnce(ctx)
	if n != 1 {
		t.Fatalf("expected runOnce to process 1 job, got %d", n)
	}

	var status string
	if err := store.pool.QueryRow(ctx, `SELECT status FROM notification.delivery_job WHERE id = $1`, pgFromUUID(jobID)).Scan(&status); err != nil {
		t.Fatalf("query status: %v", err)
	}
	if status != "done" {
		t.Fatalf("expected status=done, got %q", status)
	}
}

func TestWorker_RunOnce_RetriesOnFailure(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	companyID := uuid.New()
	_, jobID := seedDeliveryJob(t, store, companyID)

	w := NewWorker(store, &fakeDeliverer{}, &fakeDeliverer{err: errors.New("boom")}, testLogger())
	w.LeaseDuration = time.Second
	if n := w.runOnce(ctx); n != 1 {
		t.Fatalf("expected runOnce to process 1 job, got %d", n)
	}

	var status string
	var attempts int
	if err := store.pool.QueryRow(ctx, `SELECT status, attempts FROM notification.delivery_job WHERE id = $1`, pgFromUUID(jobID)).Scan(&status, &attempts); err != nil {
		t.Fatalf("query status: %v", err)
	}
	if status != "pending" {
		t.Fatalf("expected status=pending after a failed delivery, got %q", status)
	}
	if attempts < 2 {
		t.Fatalf("expected attempts >= 2 (seed claim + this run), got %d", attempts)
	}
}

// slowDeliverer simulates a delivery that takes real wall-clock time, honoring ctx cancellation —
// used to prove the heartbeat keeps extending a job's lease while delivery is genuinely still
// in flight, and that cancelling ctx (a lost-lease abort) stops it early.
type slowDeliverer struct {
	delay time.Duration
	err   error
}

func (s *slowDeliverer) Deliver(ctx context.Context, d JobDelivery) error {
	select {
	case <-time.After(s.delay):
		return s.err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// TestWorker_Heartbeat_ExtendsLeaseUnderSlowDelivery is the heartbeat test:
// "heartbeat extends under a slow fake deliverer". LeaseDuration is set short enough that the
// ORIGINAL lease would already have expired by the time the mid-delivery assertion runs — if the
// heartbeat weren't extending leased_until every LeaseDuration/3, this would fail.
func TestWorker_Heartbeat_ExtendsLeaseUnderSlowDelivery(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	companyID := uuid.New()
	_, jobID := seedDeliveryJob(t, store, companyID)

	claimedAt := time.Now()
	slow := &slowDeliverer{delay: 400 * time.Millisecond}
	w := NewWorker(store, slow, slow, testLogger())
	w.LeaseDuration = 120 * time.Millisecond // heartbeat every 40ms

	done := make(chan int, 1)
	go func() { done <- w.runOnce(ctx) }()

	// Past the ORIGINAL lease's expiry (120ms) but well before the slow delivery finishes
	// (400ms).
	time.Sleep(250 * time.Millisecond)
	var leasedUntil time.Time
	if err := store.pool.QueryRow(ctx, `SELECT leased_until FROM notification.delivery_job WHERE id = $1`, pgFromUUID(jobID)).Scan(&leasedUntil); err != nil {
		t.Fatalf("query leased_until mid-delivery: %v", err)
	}
	if !leasedUntil.After(claimedAt.Add(w.LeaseDuration)) {
		t.Fatalf("expected the heartbeat to have extended leased_until past the original lease window (claimed ~%s, LeaseDuration=%s), got leased_until=%s",
			claimedAt, w.LeaseDuration, leasedUntil)
	}

	n := <-done
	if n != 1 {
		t.Fatalf("expected runOnce to process 1 job, got %d", n)
	}

	var status string
	if err := store.pool.QueryRow(ctx, `SELECT status FROM notification.delivery_job WHERE id = $1`, pgFromUUID(jobID)).Scan(&status); err != nil {
		t.Fatalf("query status: %v", err)
	}
	if status != "done" {
		t.Fatalf("expected status=done after the slow-but-alive delivery completed, got %q", status)
	}
}

// slowFirstBatchDeliverer simulates a claimed BATCH where the first job (jobA) stalls well past
// lease expiry and the second job (jobB) delivers instantly, counting how many times jobB is
// actually delivered — the race: a worker heartbeating only the job it is CURRENTLY delivering
// leaves every other job in the same claimed batch to expire behind it and be reclaimed by a
// second worker, so the slow-delivering worker later resumes its own (stale) copy of that job and
// delivers it again once its own delay finishes.
type slowFirstBatchDeliverer struct {
	jobA, jobB uuid.UUID
	slowDelay  time.Duration
	bCount     atomic.Int32
}

func (d *slowFirstBatchDeliverer) Deliver(ctx context.Context, del JobDelivery) error {
	if del.Job.ID == d.jobA {
		select {
		case <-time.After(d.slowDelay):
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if del.Job.ID == d.jobB {
		d.bCount.Add(1)
	}
	return nil
}

// TestWorker_SlowFirstDeliveryDoesNotDoubleDeliverLaterBatchJob is the batch race test:
// a worker claims a batch [A, B]; A's delivery stalls past lease expiry. A worker that only
// heartbeats the job it is actively delivering (A) lets B's lease, set once at claim
// time, expire while the worker is still stuck on A; a second worker reclaims and delivers B, and
// then the FIRST worker — oblivious, since nothing cancelled its in-flight batch — resumes its own
// stale copy of B once A's slow delivery finally returns, delivering it a second time externally
// (the CompleteJob fencing catches the STATE clobber via ErrLeaseLost, but the external send has
// already happened twice; batch heartbeating closes that window, fencing alone does not).
//
// This test fails against a single-job heartbeat: bCount ends at 2, not 1.
func TestWorker_SlowFirstDeliveryDoesNotDoubleDeliverLaterBatchJob(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	// seedDeliveryJob's own claim-then-release dance (used by every other test in this file) would
	// sweep up BOTH jobs on its second call — ClaimJobs is a global, unscoped-by-company queue — so
	// this test inserts the two pending rows directly instead, leaving them both untouched (never
	// claimed) until worker1's own batch claim below.
	jobAID := insertPendingDeliveryJob(t, store, "batch-race-a")
	time.Sleep(5 * time.Millisecond) // guarantee jobB's created_at sorts after jobA's
	jobBID := insertPendingDeliveryJob(t, store, "batch-race-b")

	deliverer := &slowFirstBatchDeliverer{jobA: jobAID, jobB: jobBID, slowDelay: 400 * time.Millisecond}

	worker1 := NewWorker(store, deliverer, deliverer, testLogger())
	worker1.LeaseDuration = 150 * time.Millisecond // heartbeat every 50ms
	worker1.BatchSize = 2

	worker1Done := make(chan int, 1)
	go func() { worker1Done <- worker1.runOnce(ctx) }()

	// Give worker1 time to claim [A, B] and start (stall on) A's delivery, then wait past B's
	// ORIGINAL lease expiry (150ms) but well before A's slow delivery returns (400ms).
	time.Sleep(250 * time.Millisecond)

	worker2 := NewWorker(store, deliverer, deliverer, testLogger())
	worker2.LeaseDuration = 150 * time.Millisecond
	worker2.BatchSize = 2
	worker2.runOnce(ctx) // reclaims B if (and only if) its lease was left to expire

	n1 := <-worker1Done
	if n1 != 2 {
		t.Fatalf("expected worker1 to have claimed 2 jobs, got %d", n1)
	}

	if got := deliverer.bCount.Load(); got != 1 {
		t.Fatalf("expected jobB delivered exactly once across both workers, got %d deliveries (duplicate external send)", got)
	}
}

// cancelObservingDeliverer records whether/how fast ctx was actually cancelled — used to prove
// that the lease-loss signal must genuinely cancel the in-flight delivery
// context (context.WithCancel plumbed into Deliver), not merely be logged after Deliver eventually
// returns on its own.
type cancelObservingDeliverer struct {
	longDelay time.Duration
	elapsed   atomic.Int64 // nanoseconds until ctx.Done() (or longDelay, if never cancelled)
}

func (d *cancelObservingDeliverer) Deliver(ctx context.Context, del JobDelivery) error {
	start := time.Now()
	select {
	case <-ctx.Done():
		d.elapsed.Store(int64(time.Since(start)))
		return ctx.Err()
	case <-time.After(d.longDelay):
		d.elapsed.Store(int64(time.Since(start)))
		return nil
	}
}

// TestWorker_LeaseLossCancelsInFlightDeliveryContext is the lease-loss cancellation
// test: "a stalled delivery's context reports Done when the heartbeat detects loss." The job's
// lease_token is stolen out from under worker1 directly (simulating a second worker's reclaim)
// while worker1's Deliver call is stalled; the next heartbeat tick must discover the mismatch and
// genuinely cancel worker1's in-flight delivery context well before its own long artificial delay
// would otherwise return.
func TestWorker_LeaseLossCancelsInFlightDeliveryContext(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	jobID := insertPendingDeliveryJob(t, store, "lease-loss-cancel")

	deliverer := &cancelObservingDeliverer{longDelay: 2 * time.Second}
	w := NewWorker(store, deliverer, deliverer, testLogger())
	w.LeaseDuration = 90 * time.Millisecond // heartbeat every 30ms
	w.BatchSize = 1

	runDone := make(chan int, 1)
	go func() { runDone <- w.runOnce(ctx) }()

	// Let the worker claim the job and get into its (stalled) Deliver call.
	time.Sleep(40 * time.Millisecond)

	// Simulate a second worker reclaiming this job: steal the lease_token directly. The next
	// heartbeat tick's ExtendLeaseBatch will present the ORIGINAL (now stale) token, match no row,
	// and must cancel worker1's delivery context.
	if _, err := store.pool.Exec(ctx, `UPDATE notification.delivery_job SET lease_token = gen_random_uuid() WHERE id = $1`, pgFromUUID(jobID)); err != nil {
		t.Fatalf("simulate reclaim (steal lease_token): %v", err)
	}

	select {
	case n := <-runDone:
		if n != 1 {
			t.Fatalf("expected runOnce to process 1 job, got %d", n)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("worker1's runOnce did not return promptly after lease loss — delivery context was not genuinely cancelled")
	}

	elapsed := time.Duration(deliverer.elapsed.Load())
	if elapsed <= 0 {
		t.Fatal("deliverer never recorded an elapsed duration")
	}
	if elapsed >= deliverer.longDelay {
		t.Fatalf("expected the delivery context to be cancelled well before the artificial long delay (%s), took %s — ctx.Done() never fired, only a post-hoc signal", deliverer.longDelay, elapsed)
	}

	var status string
	if err := store.pool.QueryRow(ctx, `SELECT status FROM notification.delivery_job WHERE id = $1`, pgFromUUID(jobID)).Scan(&status); err != nil {
		t.Fatalf("query status: %v", err)
	}
	if status != "pending" {
		t.Fatalf("expected the abandoned job's status untouched by worker1 (still 'pending' from the simulated reclaim), got %q", status)
	}
}

// nonRetryableDeliverer always fails with ErrNonRetryableDelivery, simulating a delivery-time
// SSRF policy rejection.
type nonRetryableDeliverer struct{}

func (nonRetryableDeliverer) Deliver(ctx context.Context, d JobDelivery) error {
	return fmt.Errorf("%w: target rejected by policy (simulated)", ErrNonRetryableDelivery)
}

// TestWorker_RunOnce_NonRetryableDeliveryDeadLettersImmediately: a non-retryable delivery error
// (delivery-time policy violation) must
// dead-letter the job on its FIRST failure, never re-enter the normal pending/retry ladder.
func TestWorker_RunOnce_NonRetryableDeliveryDeadLettersImmediately(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	companyID := uuid.New()
	_, jobID := seedDeliveryJob(t, store, companyID)

	w := NewWorker(store, &fakeDeliverer{}, nonRetryableDeliverer{}, testLogger())
	w.LeaseDuration = time.Second
	if n := w.runOnce(ctx); n != 1 {
		t.Fatalf("expected runOnce to process 1 job, got %d", n)
	}

	var status string
	var attempts int
	if err := store.pool.QueryRow(ctx, `SELECT status, attempts FROM notification.delivery_job WHERE id = $1`, pgFromUUID(jobID)).Scan(&status, &attempts); err != nil {
		t.Fatalf("query status: %v", err)
	}
	if status != "dead" {
		t.Fatalf("expected status=dead immediately on a non-retryable delivery failure, got %q", status)
	}
	if attempts >= maxAttempts {
		t.Fatalf("expected dead-lettering well before exhausting maxAttempts (proves it's the non-retryable path, not coincidence), got attempts=%d", attempts)
	}
}

// TestWorker_Run_DrivesBothTickers proves Run's own event loop actually fires both the poll
// ticker (runOnce) and the metrics ticker (reportJobCounts) — both PollInterval and
// MetricsInterval are set very short so a bounded-duration context sees each branch at least
// once before it cancels, matching the shape cmd/gateway/main_test.go's own refreshJWKSPeriodically
// test uses for the analogous "drive a real ticker.C branch without waiting out the production
// interval" problem.
func TestWorker_Run_DrivesBothTickers(t *testing.T) {
	store := newTestStore(t)
	_, jobID := seedDeliveryJob(t, store, uuid.New())

	w := NewWorker(store, &fakeDeliverer{}, &fakeDeliverer{}, testLogger())
	w.PollInterval = 10 * time.Millisecond
	w.MetricsInterval = 15 * time.Millisecond
	w.LeaseDuration = time.Second
	w.Metrics = metrics.New("notification-test", "test", "test").EnableDeliveryJobs()

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	w.Run(ctx)

	var status string
	if err := store.pool.QueryRow(context.Background(), `SELECT status FROM notification.delivery_job WHERE id = $1`, pgFromUUID(jobID)).Scan(&status); err != nil {
		t.Fatalf("query status: %v", err)
	}
	if status != "done" {
		t.Fatalf("expected Run's poll ticker to have processed the seeded job (status=done), got %q", status)
	}
}

// TestStore_CountJobsByState proves the delivery-jobs gauge source: counts are scoped to THIS store's
// own claim_group (never another run's or the live container's "default"), and reflect every
// status a job can land in.
func TestStore_CountJobsByState(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	// A done job. seedDeliveryJob's own ClaimJobs(limit=10) call would sweep up ANY other
	// pending job in this store's claim_group, so both seeded (done/dead) jobs are created
	// BEFORE the never-claimed pending job below — and each uses its own companyID, since
	// seedDeliveryJob's channel key is fixed ("worker-test-chan") and channel keys are unique
	// per (company_id, key).
	_, doneJobID := seedDeliveryJob(t, store, uuid.New())
	doneWorker := NewWorker(store, &fakeDeliverer{}, &fakeDeliverer{}, testLogger())
	doneWorker.LeaseDuration = time.Second
	if n := doneWorker.runOnce(ctx); n != 1 {
		t.Fatalf("expected runOnce to process 1 job (done), got %d", n)
	}
	var doneStatus string
	if err := store.pool.QueryRow(ctx, `SELECT status FROM notification.delivery_job WHERE id = $1`, pgFromUUID(doneJobID)).Scan(&doneStatus); err != nil {
		t.Fatalf("query done status: %v", err)
	}
	if doneStatus != "done" {
		t.Fatalf("expected done, got %q", doneStatus)
	}

	// A dead job.
	_, deadJobID := seedDeliveryJob(t, store, uuid.New())
	deadWorker := NewWorker(store, &fakeDeliverer{}, nonRetryableDeliverer{}, testLogger())
	deadWorker.LeaseDuration = time.Second
	if n := deadWorker.runOnce(ctx); n != 1 {
		t.Fatalf("expected runOnce to process 1 job (dead), got %d", n)
	}
	var deadStatus string
	if err := store.pool.QueryRow(ctx, `SELECT status FROM notification.delivery_job WHERE id = $1`, pgFromUUID(deadJobID)).Scan(&deadStatus); err != nil {
		t.Fatalf("query dead status: %v", err)
	}
	if deadStatus != "dead" {
		t.Fatalf("expected dead, got %q", deadStatus)
	}

	// A pending job (never claimed) — inserted last, see the comment above.
	insertPendingDeliveryJob(t, store, "count-pending")

	counts, err := store.CountJobsByState(ctx)
	if err != nil {
		t.Fatalf("CountJobsByState: %v", err)
	}
	if counts["pending"] < 1 {
		t.Errorf("expected at least 1 pending job in this run's claim_group, got counts=%v", counts)
	}
	if counts["done"] < 1 {
		t.Errorf("expected at least 1 done job in this run's claim_group, got counts=%v", counts)
	}
	if counts["dead"] < 1 {
		t.Errorf("expected at least 1 dead job in this run's claim_group, got counts=%v", counts)
	}
}

// TestWorker_ReportJobCounts_SetsGaugeFromLiveCounts proves reportJobCounts (Run's own periodic
// ticker branch) calls through to Store.CountJobsByState and Metrics.SetDeliveryJobsGauge without
// error — a nil Metrics is a documented no-op (never even queries the DB, see reportJobCounts's
// own doc comment); this proves the non-nil path actually runs end to end against the real store.
func TestWorker_ReportJobCounts_SetsGaugeFromLiveCounts(t *testing.T) {
	store := newTestStore(t)
	insertPendingDeliveryJob(t, store, "report-counts")

	w := NewWorker(store, &fakeDeliverer{}, &fakeDeliverer{}, testLogger())
	w.Metrics = metrics.New("notification-test", "test", "test").EnableDeliveryJobs()

	// Must not panic/error with Metrics set; the nil case (default NewWorker) is exercised by
	// every other test in this file that never sets Metrics at all.
	w.reportJobCounts(context.Background())
}

// TestWorker_RecordDeliveryAttempt_OutcomesForEachPath proves the three RecordDeliveryAttempt
// call sites (success, retry, dead) all execute without panicking when Metrics is wired — the
// success/retry/dead-letter status assertions themselves are already covered by
// TestWorker_RunOnce_Success/TestWorker_RunOnce_RetriesOnFailure/
// TestWorker_RunOnce_NonRetryableDeliveryDeadLettersImmediately above; this adds Metrics to the
// same three shapes so the RecordDeliveryAttempt call sites run with a non-nil Registry too.
func TestWorker_RecordDeliveryAttempt_OutcomesForEachPath(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	mreg := metrics.New("notification-test", "test", "test").EnableDeliveryJobs()

	t.Run("success", func(t *testing.T) {
		companyID := uuid.New()
		_, jobID := seedDeliveryJob(t, store, companyID)
		w := NewWorker(store, &fakeDeliverer{}, &fakeDeliverer{}, testLogger())
		w.LeaseDuration = time.Second
		w.Metrics = mreg
		if n := w.runOnce(ctx); n != 1 {
			t.Fatalf("expected 1 job processed, got %d", n)
		}
		var status string
		if err := store.pool.QueryRow(ctx, `SELECT status FROM notification.delivery_job WHERE id = $1`, pgFromUUID(jobID)).Scan(&status); err != nil {
			t.Fatalf("query status: %v", err)
		}
		if status != "done" {
			t.Fatalf("expected done, got %q", status)
		}
	})

	t.Run("retry", func(t *testing.T) {
		companyID := uuid.New()
		_, jobID := seedDeliveryJob(t, store, companyID)
		w := NewWorker(store, &fakeDeliverer{}, &fakeDeliverer{err: errors.New("boom")}, testLogger())
		w.LeaseDuration = time.Second
		w.Metrics = mreg
		if n := w.runOnce(ctx); n != 1 {
			t.Fatalf("expected 1 job processed, got %d", n)
		}
		var status string
		if err := store.pool.QueryRow(ctx, `SELECT status FROM notification.delivery_job WHERE id = $1`, pgFromUUID(jobID)).Scan(&status); err != nil {
			t.Fatalf("query status: %v", err)
		}
		if status != "pending" {
			t.Fatalf("expected pending (retry), got %q", status)
		}
	})

	t.Run("dead", func(t *testing.T) {
		companyID := uuid.New()
		_, jobID := seedDeliveryJob(t, store, companyID)
		w := NewWorker(store, &fakeDeliverer{}, nonRetryableDeliverer{}, testLogger())
		w.LeaseDuration = time.Second
		w.Metrics = mreg
		if n := w.runOnce(ctx); n != 1 {
			t.Fatalf("expected 1 job processed, got %d", n)
		}
		var status string
		if err := store.pool.QueryRow(ctx, `SELECT status FROM notification.delivery_job WHERE id = $1`, pgFromUUID(jobID)).Scan(&status); err != nil {
			t.Fatalf("query status: %v", err)
		}
		if status != "dead" {
			t.Fatalf("expected dead, got %q", status)
		}
	})
}

// TestFailJob_BackoffHoldsJobBackFromReclaim: after a failure the job is pending but
// NOT reclaimable until retryBackoff(attempts) has elapsed — leased_until is set into the future
// and the claim predicate (leased_until < now()) honours it.
func TestFailJob_BackoffHoldsJobBackFromReclaim(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	_, jobID := seedDeliveryJob(t, store, uuid.New())

	jobs, err := store.ClaimJobs(ctx, time.Millisecond, 10)
	if err != nil || len(jobs) != 1 {
		t.Fatalf("claim: jobs=%d err=%v", len(jobs), err)
	}
	before := time.Now()
	if err := store.FailJob(ctx, jobID, jobs[0].LeaseToken, jobs[0].Attempts, errors.New("boom")); err != nil {
		t.Fatalf("fail job: %v", err)
	}

	var status string
	var leasedUntil time.Time
	if err := store.pool.QueryRow(ctx, `SELECT status, leased_until FROM notification.delivery_job WHERE id = $1`, pgFromUUID(jobID)).Scan(&status, &leasedUntil); err != nil {
		t.Fatalf("query job: %v", err)
	}
	want := retryBackoff(jobs[0].Attempts)
	if status != "pending" {
		t.Fatalf("status = %q, want pending", status)
	}
	if got := leasedUntil.Sub(before); got < want-time.Second || got > want+5*time.Second {
		t.Fatalf("leased_until is %s ahead, want ~%s (backoff for attempts=%d)", got, want, jobs[0].Attempts)
	}

	time.Sleep(5 * time.Millisecond) // well past the tiny claim lease, well short of the backoff
	again, err := store.ClaimJobs(ctx, time.Millisecond, 10)
	if err != nil {
		t.Fatalf("re-claim: %v", err)
	}
	if len(again) != 0 {
		t.Fatalf("expected the failed job to be held back by its backoff, got %+v", again)
	}
}

func TestRetryBackoff_ExponentialCapped(t *testing.T) {
	cases := map[int]time.Duration{0: time.Second, 1: 2 * time.Second, 3: 8 * time.Second, 7: 128 * time.Second, 10: maxRetryBackoff, 11: maxRetryBackoff, 100: maxRetryBackoff, -1: time.Second}
	for attempts, want := range cases {
		if got := retryBackoff(attempts); got != want {
			t.Errorf("retryBackoff(%d) = %s, want %s", attempts, got, want)
		}
	}
}
