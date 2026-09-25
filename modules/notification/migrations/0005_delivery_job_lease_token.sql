-- SPDX-License-Identifier: Apache-2.0

-- Fence delivery_job leases with
-- a per-claim token so Complete/Fail/ExtendLease can never overwrite state a DIFFERENT claim (a
-- reclaim after this worker's lease already expired) now owns. Without this, a slow-but-alive
-- worker that finishes after its own lease expired and got reclaimed by a second worker could
-- still call CompleteJob and silently clobber the second worker's in-flight attempt.
--
-- lease_token is set fresh by every ClaimJobs claim (including a reclaim of the same row) and
-- cleared back to NULL whenever the job leaves 'pending' (done/dead) or a fail returns it to
-- pending unleased. Complete/Fail/ExtendLease all gate their UPDATE on
-- "WHERE id = $1 AND lease_token = $2" — zero rows affected means the caller's token is stale
-- (lost the lease), handled by the caller as a no-op (see store.go's ErrLeaseLost), never as a
-- state overwrite.
ALTER TABLE notification.delivery_job ADD COLUMN lease_token uuid;

---- create above / drop below ----

ALTER TABLE notification.delivery_job DROP COLUMN lease_token;
