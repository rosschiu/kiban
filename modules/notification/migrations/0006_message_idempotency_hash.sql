-- SPDX-License-Identifier: Apache-2.0

-- Make Idempotency-Key replay payload-bound (409 on conflicting reuse). Before this migration, SendMessage replayed on key match alone — a second
-- request reusing the same key with a DIFFERENT subject/body/channel silently returned the FIRST
-- request's message instead of erroring, masking a client bug. idempotency_key_hash stores the
-- sha256 (hex) of the canonical payload (channelId + subjectLine + body) alongside the key, so a
-- key match with a hash mismatch can be rejected as a conflict instead of replayed.
ALTER TABLE notification.message ADD COLUMN idempotency_key_hash text;

---- create above / drop below ----

ALTER TABLE notification.message DROP COLUMN idempotency_key_hash;
