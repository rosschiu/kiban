-- SPDX-License-Identifier: Apache-2.0

-- Make timesheet.submission's Idempotency-Key replay payload-bound
-- (notification's own idempotency_key_hash column, modules/notification/migrations/0006_message_idempotency_hash.sql,
-- is the template). Before this migration, SubmitWeek replayed on key match alone — a second
-- request reusing the same key with a DIFFERENT weekStart silently returned the FIRST request's
-- submission instead of erroring. idempotency_key_hash stores the sha256 (hex) of the canonical
-- payload (companyId + memberId + weekStart), so a key match with a hash mismatch can be
-- rejected as a conflict (409 IDEMPOTENCY_CONFLICT) instead of replayed.
ALTER TABLE timesheet.submission ADD COLUMN idempotency_key_hash text;

---- create above / drop below ----

ALTER TABLE timesheet.submission DROP COLUMN idempotency_key_hash;
