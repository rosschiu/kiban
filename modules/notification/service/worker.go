// SPDX-License-Identifier: Apache-2.0

package notification

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/rosschiu/kiban/internal/audit"
	"github.com/rosschiu/kiban/internal/obs/metrics"
)

// DeliveryJob is one leased background delivery.
type DeliveryJob struct {
	ID          uuid.UUID
	MessageID   uuid.UUID
	Kind        string // "email" | "webhook"
	Target      string
	Status      string // "pending" | "done" | "dead"
	Attempts    int
	LeasedUntil *time.Time
	LastError   *string
	// LeaseToken is the fencing token this specific claim holds. Every Complete/Fail call must
	// present the token it was handed by ClaimJobs (and
	// every token passed to ExtendLeaseBatch) — a stale token (the lease already expired and a
	// second worker reclaimed the row) affects zero rows instead of overwriting the second
	// worker's state. Never the zero UUID for a freshly claimed job.
	LeaseToken uuid.UUID
}

// ErrLeaseLost is returned by CompleteJob/FailJob/FailJobPermanent when the fencing UPDATE affects
// zero rows — the caller's lease_token no longer matches the row (it expired and was reclaimed by
// another worker, or the job already left 'pending'). Callers log and drop; they must never retry
// with a different token or otherwise overwrite state a newer claim owns. ExtendLeaseBatch reports
// the same condition per-token, via its returned map, rather than this error (a batch call must
// not fail wholesale just because one job's lease in the batch was lost).
var ErrLeaseLost = errors.New("notification: lease lost (job reclaimed by another worker or already settled)")

// maxAttempts: a job whose attempts reach 8 is marked dead and audited.
const maxAttempts = 8

// intervalLiteral renders a Go duration as a Postgres interval literal Postgres's parser always
// accepts ("<seconds> seconds") — Duration.String()'s Go-flavored suffixes (e.g. "200ms") are
// NOT valid interval input, so this is required, not cosmetic.
func intervalLiteral(d time.Duration) string {
	return fmt.Sprintf("%f seconds", d.Seconds())
}

// ClaimJobs claims up to limit jobs: UPDATE ... leased_until=now()+lease,
// attempts=attempts+1 WHERE status='pending' AND (leased_until IS NULL OR leased_until<now())
// ORDER BY created_at LIMIT n FOR UPDATE SKIP LOCKED RETURNING *. lease is a parameter (not a
// fixed 30s) so tests can use a short lease to prove crash-reclaim without a 30s sleep; the
// worker's own production loop (Worker.leaseDuration) uses 30s. The claim is also
// scoped to s.claimGroup — this Store only ever claims jobs it (or another
// Store sharing its group) enqueued, so a module's own test suite's Store, bound to its own
// per-run group, never races the live kiban-notification container's worker Store, bound to
// "default".
func (s *Store) ClaimJobs(ctx context.Context, lease time.Duration, limit int) ([]DeliveryJob, error) {
	rows, err := s.pool.Query(ctx, `
		UPDATE notification.delivery_job
		SET leased_until = now() + $1::interval, attempts = attempts + 1, lease_token = gen_random_uuid()
		WHERE id IN (
			SELECT id FROM notification.delivery_job
			WHERE claim_group = $2 AND status = 'pending' AND (leased_until IS NULL OR leased_until < now())
			ORDER BY created_at LIMIT $3 FOR UPDATE SKIP LOCKED
		)
		RETURNING id, message_id, kind, target, status, attempts, leased_until, last_error, lease_token`,
		intervalLiteral(lease), s.claimGroup, limit,
	)
	if err != nil {
		return nil, fmt.Errorf("notification: claim jobs: %w", err)
	}
	defer rows.Close()

	var out []DeliveryJob
	for rows.Next() {
		var j DeliveryJob
		var pgID, pgMessageID, pgLeaseToken pgtype.UUID
		var leasedUntil pgtype.Timestamptz
		if err := rows.Scan(&pgID, &pgMessageID, &j.Kind, &j.Target, &j.Status, &j.Attempts, &leasedUntil, &j.LastError, &pgLeaseToken); err != nil {
			return nil, fmt.Errorf("notification: scan claimed job: %w", err)
		}
		j.ID, j.MessageID, j.LeaseToken = uuidFromPg(pgID), uuidFromPg(pgMessageID), uuidFromPg(pgLeaseToken)
		if leasedUntil.Valid {
			t := leasedUntil.Time
			j.LeasedUntil = &t
		}
		out = append(out, j)
	}
	return out, rows.Err()
}

// CountJobsByState returns this Store's own claim_group's delivery_job count per status
// ("pending"/"done"/"dead") — the kiban_delivery_jobs{state} gauge source. A single
// grouped COUNT query, called periodically by the worker (Worker.reportJobCounts), never on
// every state transition.
func (s *Store) CountJobsByState(ctx context.Context) (map[string]int, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT status, count(*) FROM notification.delivery_job WHERE claim_group = $1 GROUP BY status`,
		s.claimGroup,
	)
	if err != nil {
		return nil, fmt.Errorf("notification: count jobs by state: %w", err)
	}
	defer rows.Close()

	counts := make(map[string]int, 3)
	for rows.Next() {
		var status string
		var n int64
		if err := rows.Scan(&status, &n); err != nil {
			return nil, fmt.Errorf("notification: scan job state count: %w", err)
		}
		counts[status] = int(n)
	}
	return counts, rows.Err()
}

// CompleteJob marks a job done, fenced by leaseToken: a
// worker whose lease already expired and got reclaimed affects zero rows here instead of
// clobbering the reclaiming worker's state — see ErrLeaseLost.
func (s *Store) CompleteJob(ctx context.Context, id, leaseToken uuid.UUID) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE notification.delivery_job SET status = 'done', last_error = NULL, lease_token = NULL
		WHERE id = $1 AND lease_token = $2`,
		pgFromUUID(id), pgFromUUID(leaseToken),
	)
	if err != nil {
		return fmt.Errorf("notification: complete job: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrLeaseLost
	}
	return nil
}

// maxRetryBackoff caps retryBackoff so a long outage retries every 15 minutes rather than never.
const maxRetryBackoff = 15 * time.Minute

// retryBackoff is the delay before a failed job may be reclaimed: min(2^attempts s, 15 min).
// attempts is the count ClaimJobs already incremented (so the first failure, attempts=1, waits
// 2 s; the seventh, attempts=7, 128 s).
func retryBackoff(attempts int) time.Duration {
	if attempts < 0 {
		attempts = 0
	}
	if attempts > 10 { // 2^10 s > maxRetryBackoff already; also keeps the shift in range
		return maxRetryBackoff
	}
	return min(time.Duration(1<<uint(attempts))*time.Second, maxRetryBackoff)
}

// FailJob records a delivery failure (back to pending, or dead once attempts reach maxAttempts), fenced
// by leaseToken. attempts was already incremented by ClaimJobs; leased_until is set to
// now()+retryBackoff(attempts) so the claim predicate (leased_until < now()) holds the job back
// for the backoff — an outbound outage no longer burns every attempt in a few seconds.
func (s *Store) FailJob(ctx context.Context, id, leaseToken uuid.UUID, attempts int, deliverErr error) error {
	errMsg := deliverErr.Error()
	if attempts >= maxAttempts {
		return s.markJobDead(ctx, id, leaseToken, attempts, errMsg)
	}

	tag, err := s.pool.Exec(ctx, `
		UPDATE notification.delivery_job
		SET status = 'pending', leased_until = now() + $4::interval, lease_token = NULL, last_error = $1
		WHERE id = $2 AND lease_token = $3`,
		errMsg, pgFromUUID(id), pgFromUUID(leaseToken), intervalLiteral(retryBackoff(attempts)),
	)
	if err != nil {
		return fmt.Errorf("notification: fail job: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrLeaseLost
	}
	return nil
}

// FailJobPermanent marks a job dead immediately, without going through the normal retry ladder
// (a delivery-time SSRF policy violation is non-retryable
// — retrying a target the policy just rejected can never succeed, so it isn't given the
// remaining attempts budget). attempts is recorded as -1 in the audit payload to distinguish a
// policy-forced dead-letter from one that genuinely exhausted maxAttempts.
func (s *Store) FailJobPermanent(ctx context.Context, id, leaseToken uuid.UUID, deliverErr error) error {
	return s.markJobDead(ctx, id, leaseToken, -1, deliverErr.Error())
}

func (s *Store) markJobDead(ctx context.Context, id, leaseToken uuid.UUID, attempts int, errMsg string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("notification: begin tx: %w", err)
	}
	defer tx.Rollback(ctx)

	tag, err := tx.Exec(ctx, `
		UPDATE notification.delivery_job SET status = 'dead', leased_until = NULL, lease_token = NULL, last_error = $1
		WHERE id = $2 AND lease_token = $3`,
		errMsg, pgFromUUID(id), pgFromUUID(leaseToken),
	)
	if err != nil {
		return fmt.Errorf("notification: mark job dead: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrLeaseLost
	}
	if err := s.audit.Record(ctx, tx, audit.Event{
		Actor: "system:notification-worker", Action: "notification.delivery.dead",
		Subject: "notification_delivery_job:" + id.String(),
		Payload: map[string]any{"attempts": attempts, "lastError": errMsg},
	}); err != nil {
		return fmt.Errorf("notification: audit dead job: %w", err)
	}
	return tx.Commit(ctx)
}

// ExtendLeaseBatch heartbeats every job in a claimed batch, not only the one currently being
// delivered: otherwise a slow first delivery lets every LATER job in that same batch expire behind
// it and be reclaimed by another worker, causing a duplicate external send once the slow delivery
// finally finished and the original worker resumed its own stale copy of the later job. Extending
// every job in the claimed batch in one UPDATE (keeping the single-round-trip batch claim) closes
// that window: as long as this worker is still alive and ticking, no job it holds can be reclaimed,
// whether or not delivery of it has started yet. Scoped to status='pending' like ExtendLease, so a
// token whose job already left 'pending' (this worker's own Complete/Fail already ran, in a
// concurrent goroutine — not a competing worker) is silently excluded rather than misreported as
// lost; the RETURNING set tells the caller exactly which tokens are still genuinely held.
func (s *Store) ExtendLeaseBatch(ctx context.Context, tokens []uuid.UUID, lease time.Duration) (map[uuid.UUID]bool, error) {
	extended := make(map[uuid.UUID]bool, len(tokens))
	if len(tokens) == 0 {
		return extended, nil
	}
	pgTokens := make([]pgtype.UUID, len(tokens))
	for i, t := range tokens {
		pgTokens[i] = pgFromUUID(t)
	}
	rows, err := s.pool.Query(ctx, `
		UPDATE notification.delivery_job SET leased_until = now() + $1::interval
		WHERE lease_token = ANY($2::uuid[]) AND status = 'pending'
		RETURNING lease_token`,
		intervalLiteral(lease), pgTokens,
	)
	if err != nil {
		return nil, fmt.Errorf("notification: extend lease batch: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var pgToken pgtype.UUID
		if err := rows.Scan(&pgToken); err != nil {
			return nil, fmt.Errorf("notification: scan extended lease token: %w", err)
		}
		extended[uuidFromPg(pgToken)] = true
	}
	return extended, rows.Err()
}

// JobTarget resolves a delivery job's recipient-facing metadata the deliverer needs beyond
// DeliveryJob itself (message subject/body) — a small join, kept out of ClaimJobs's own RETURNING
// clause because most callers (list/inspect) never need the message body.
type JobDelivery struct {
	Job         DeliveryJob
	SubjectLine string
	Body        string
}

func (s *Store) LoadJobDelivery(ctx context.Context, job DeliveryJob) (JobDelivery, error) {
	var d JobDelivery
	d.Job = job
	err := s.pool.QueryRow(ctx, `SELECT subject_line, body FROM notification.message WHERE id = $1`, pgFromUUID(job.MessageID)).
		Scan(&d.SubjectLine, &d.Body)
	if errors.Is(err, pgx.ErrNoRows) {
		return JobDelivery{}, ErrMessageNotFound
	}
	if err != nil {
		return JobDelivery{}, fmt.Errorf("notification: load job delivery: %w", err)
	}
	return d, nil
}

// Deliverer sends one job (email via net/smtp to mailpit, webhook via signed HTTP POST).
type Deliverer interface {
	Deliver(ctx context.Context, d JobDelivery) error
}

// Worker is the leased delivery loop: poll -> claim -> deliver -> complete/fail,
// heartbeating the lease while delivery is in flight. One Worker instance is one "worker" for
// crash-reclaim purposes — stopping it (ctx cancel) mid-lease, with no complete/fail ever
// recorded, is exactly the "kill worker mid-lease" scenario the mandatory test drives.
type Worker struct {
	Store         *Store
	Mailer        Deliverer
	Webhook       Deliverer
	Logger        *slog.Logger
	PollInterval  time.Duration
	LeaseDuration time.Duration
	BatchSize     int

	// Metrics records kiban_delivery_jobs{state} (a periodic re-count, see reportJobCounts —
	// a periodic re-count is cheaper than updating the gauge on
	// every individual state transition) and kiban_delivery_attempts_total{kind,outcome} (updated
	// inline, once per attempt: deliverLeased/failJob). Nil-safe (every Registry method on a nil
	// *metrics.Registry is a documented no-op) — left unset by every existing test's NewWorker
	// call, so nothing here changes their behavior.
	Metrics *metrics.Registry
	// MetricsInterval controls how often reportJobCounts re-counts delivery_job by state.
	// Defaults to 15s (NewWorker) — independent of PollInterval so a fast test poll interval
	// doesn't turn this into a per-second COUNT query.
	MetricsInterval time.Duration
}

func NewWorker(store *Store, mailer, webhook Deliverer, logger *slog.Logger) *Worker {
	return &Worker{
		Store: store, Mailer: mailer, Webhook: webhook, Logger: logger,
		PollInterval: time.Second, LeaseDuration: 30 * time.Second, BatchSize: 10,
		MetricsInterval: 15 * time.Second,
	}
}

// Run polls until ctx is cancelled. It never returns an error — delivery failures are per-job
// (FailJob), not process-fatal (Design: "fail=>pending", retried, never crashes the worker).
func (w *Worker) Run(ctx context.Context) {
	ticker := time.NewTicker(w.PollInterval)
	defer ticker.Stop()

	metricsInterval := w.MetricsInterval
	if metricsInterval <= 0 {
		metricsInterval = 15 * time.Second
	}
	metricsTicker := time.NewTicker(metricsInterval)
	defer metricsTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.runOnce(ctx)
		case <-metricsTicker.C:
			w.reportJobCounts(ctx)
		}
	}
}

// reportJobCounts re-counts delivery_job by state (Store.CountJobsByState, scoped to this
// worker's own claim_group) and sets kiban_delivery_jobs{state} from the fresh snapshot. A
// nil Metrics skips the query entirely (never spends a DB round trip on a metric nobody reads).
func (w *Worker) reportJobCounts(ctx context.Context) {
	if w.Metrics == nil {
		return
	}
	counts, err := w.Store.CountJobsByState(ctx)
	if err != nil {
		w.Logger.Warn("notification: count jobs by state", slog.Any("error", err))
		return
	}
	w.Metrics.SetDeliveryJobsGauge(counts)
}

// batchLease is one claimed job's slot in runOnce's batch, carrying the per-job context the
// batch heartbeat can genuinely cancel when it discovers this specific job's lease was
// lost — independent of every other job's slot, and independent of whether this job's delivery
// has even started yet.
type batchLease struct {
	job     DeliveryJob
	ctx     context.Context
	cancel  context.CancelFunc
	settled atomic.Bool // true once this job's Complete/Fail has been attempted (heartbeat stops extending it)
}

// runOnce claims and processes at most one batch; Run loops it, tests call it directly for
// deterministic single-pass control.
func (w *Worker) runOnce(ctx context.Context) int {
	jobs, err := w.Store.ClaimJobs(ctx, w.LeaseDuration, w.BatchSize)
	if err != nil {
		w.Logger.Error("notification: claim jobs", slog.Any("error", err))
		return 0
	}
	if len(jobs) == 0 {
		return 0
	}

	// The worker claims a BATCH in one round trip but
	// must heartbeat every job in it, not only the one currently being delivered — otherwise a
	// slow first delivery lets every LATER job's lease expire behind it, another worker reclaims
	// and delivers it, and this worker (oblivious) resumes its own stale copy once the slow
	// delivery finally returns: a duplicate external send. One heartbeat goroutine, covering the
	// whole batch, closes that window; each job still gets its own cancellable context so a
	// per-job lease loss genuinely cancels only that job's in-flight Deliver call (real
	// cancellation, not just a logged signal).
	leases := make([]*batchLease, len(jobs))
	for i, job := range jobs {
		jobCtx, cancel := context.WithCancel(ctx)
		leases[i] = &batchLease{job: job, ctx: jobCtx, cancel: cancel}
	}

	hbCtx, hbCancel := context.WithCancel(ctx)
	heartbeatDone := make(chan struct{})
	go w.batchHeartbeat(hbCtx, leases, heartbeatDone)

	for _, l := range leases {
		select {
		case <-l.ctx.Done():
			// Lease already lost before this job's delivery even started (the batch heartbeat
			// caught it while an earlier job in the batch was still being delivered): skip
			// Deliver entirely rather than sending to a target another worker already owns.
			w.Logger.Warn("notification: lease lost before delivery started, abandoning job (no state overwrite)",
				slog.String("jobId", l.job.ID.String()))
			l.settled.Store(true)
			continue
		default:
		}
		w.deliverLeased(ctx, l)
	}

	hbCancel()
	<-heartbeatDone
	return len(jobs)
}

func (w *Worker) deliverLeased(ctx context.Context, l *batchLease) {
	job := l.job
	defer l.settled.Store(true)

	d, err := w.Store.LoadJobDelivery(ctx, job)
	if err != nil {
		w.Logger.Error("notification: load job delivery", slog.String("jobId", job.ID.String()), slog.Any("error", err))
		w.failJob(ctx, job, err)
		return
	}

	deliverer := w.Mailer
	if job.Kind == "webhook" {
		deliverer = w.Webhook
	}
	if deliverer == nil {
		w.Logger.Error("notification: no deliverer configured", slog.String("kind", job.Kind))
		return
	}

	// l.ctx is cancelled by the batch heartbeat the instant it discovers THIS job's lease was
	// lost (genuine context.Context cancellation reaching Deliver/SendMail/webhook POST, not just
	// a signal checked after the fact), and independently the moment this delivery attempt
	// itself returns below.
	err = deliverer.Deliver(l.ctx, d)
	lostMidDelivery := l.ctx.Err() != nil
	l.cancel()

	if lostMidDelivery {
		w.Logger.Warn("notification: lease lost mid-delivery, abandoning job (no state overwrite)",
			slog.String("jobId", job.ID.String()))
		return
	}

	if err != nil {
		w.Logger.Warn("notification: delivery failed", slog.String("jobId", job.ID.String()), slog.Int("attempts", job.Attempts), slog.Any("error", err))
		w.failJob(ctx, job, err)
		return
	}
	w.Metrics.RecordDeliveryAttempt(job.Kind, "success")
	if err := w.Store.CompleteJob(ctx, job.ID, job.LeaseToken); err != nil && !errors.Is(err, ErrLeaseLost) {
		w.Logger.Error("notification: complete job", slog.Any("error", err))
	}
}

// failJob routes a delivery error to the non-retryable (FailJobPermanent, immediate dead-letter)
// or normal (FailJob, retry ladder) path depending on whether it's an ErrNonRetryableDelivery —
// currently only a delivery-time WebhookPolicy rejection (retrying a target the SSRF
// policy just rejected can never succeed).
func (w *Worker) failJob(ctx context.Context, job DeliveryJob, deliverErr error) {
	outcome := "retry"
	var failErr error
	if errors.Is(deliverErr, ErrNonRetryableDelivery) {
		outcome = "dead"
		failErr = w.Store.FailJobPermanent(ctx, job.ID, job.LeaseToken, deliverErr)
	} else {
		if job.Attempts >= maxAttempts {
			outcome = "dead"
		}
		failErr = w.Store.FailJob(ctx, job.ID, job.LeaseToken, job.Attempts, deliverErr)
	}
	w.Metrics.RecordDeliveryAttempt(job.Kind, outcome)
	if failErr != nil && !errors.Is(failErr, ErrLeaseLost) {
		w.Logger.Error("notification: fail job", slog.Any("error", failErr))
	}
}

// batchHeartbeat calls ExtendLeaseBatch every w.LeaseDuration/3, covering every
// still-unsettled job in the claimed batch — not only the one currently being delivered — until
// hbCtx is done (runOnce cancels it once every job in the batch has been processed). For any
// unsettled job whose token ExtendLeaseBatch does NOT report as extended (lost to a competing
// worker, since a settled job's own status leaving 'pending' is excluded from the RETURNING set by
// design, not by this loop), it genuinely cancels that job's own context — real
// context.Context cancellation reaching an in-flight Deliver call (SendMail/webhook POST), not
// merely a signal a caller checks after the fact.
func (w *Worker) batchHeartbeat(hbCtx context.Context, leases []*batchLease, done chan<- struct{}) {
	defer close(done)
	interval := w.LeaseDuration / 3
	if interval <= 0 {
		interval = time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-hbCtx.Done():
			return
		case <-ticker.C:
			var tokens []uuid.UUID
			pending := make([]*batchLease, 0, len(leases))
			for _, l := range leases {
				if l.settled.Load() {
					continue
				}
				tokens = append(tokens, l.job.LeaseToken)
				pending = append(pending, l)
			}
			if len(tokens) == 0 {
				continue
			}
			// A fresh (non-cancelled) context for the extend call itself: hbCtx may be cancelled
			// concurrently by runOnce right as the batch finishes, and that race must not abort
			// an extend that's otherwise about to succeed for jobs still genuinely in flight.
			extended, err := w.Store.ExtendLeaseBatch(context.Background(), tokens, w.LeaseDuration)
			if err != nil {
				w.Logger.Error("notification: extend lease batch", slog.Any("error", err))
				continue
			}
			for _, l := range pending {
				if !extended[l.job.LeaseToken] && !l.settled.Load() {
					w.Logger.Warn("notification: extend lease failed, lease lost", slog.String("jobId", l.job.ID.String()))
					l.cancel()
				}
			}
		}
	}
}
