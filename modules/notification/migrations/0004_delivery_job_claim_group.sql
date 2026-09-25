-- SPDX-License-Identifier: Apache-2.0

-- Partition delivery_job claims by claim_group so a module's own live compose-container worker
-- (which only ever polls claim_group='default') never races that same module's own `go test`
-- suite driving ClaimJobs directly against a different, per-test-run claim_group. This replaces
-- the "stop the container before testing" workaround with real structural isolation — no
-- container stop/start is required for `go test ./modules/notification/...` to be deterministic
-- against a live `kiban-notification` container anymore.
ALTER TABLE notification.delivery_job ADD COLUMN claim_group text NOT NULL DEFAULT 'default';

-- The claim query now filters on claim_group first; replace the pending-only partial index
-- (0002_notification_tables.sql's delivery_job_claim_idx, immutable/shipped — a new index here,
-- not an edit there) with one that leads on claim_group so the SKIP LOCKED scan stays cheap per
-- group regardless of how many other groups' rows accumulate.
DROP INDEX notification.delivery_job_claim_idx;
CREATE INDEX delivery_job_claim_idx ON notification.delivery_job (claim_group, created_at) WHERE status = 'pending';

---- create above / drop below ----

DROP INDEX notification.delivery_job_claim_idx;
CREATE INDEX delivery_job_claim_idx ON notification.delivery_job (created_at) WHERE status = 'pending';
ALTER TABLE notification.delivery_job DROP COLUMN claim_group;
