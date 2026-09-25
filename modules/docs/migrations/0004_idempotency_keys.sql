-- SPDX-License-Identifier: Apache-2.0

-- Payload-bound Idempotency-Key support for docs's non-idempotent writes (notification's own
-- idempotency_key_hash column, modules/notification/migrations/0006_message_idempotency_hash.sql,
-- is the template).
--
-- docs.document: idempotency_key/idempotency_key_hash scoped per (company_id, owner_kcsub, key)
-- — document create has no pre-existing object to scope by, so it's scoped the same way
-- timesheet's submission create is (company + caller).
--
-- docs.share: idempotency_key/idempotency_key_hash scoped per (document_id, key) — a share
-- grant already has an object (the document) to scope by, the same shape as notification's own
-- message-send scoping by channel_id.
ALTER TABLE docs.document ADD COLUMN idempotency_key text;
ALTER TABLE docs.document ADD COLUMN idempotency_key_hash text;
CREATE UNIQUE INDEX document_idempotency_key_unique
    ON docs.document (company_id, owner_kcsub, idempotency_key) WHERE idempotency_key IS NOT NULL;

ALTER TABLE docs.share ADD COLUMN idempotency_key text;
ALTER TABLE docs.share ADD COLUMN idempotency_key_hash text;
-- NOT unique on (document_id, idempotency_key) alone: docs.share already has its own
-- UNIQUE (document_id, member_id) upsert-in-place constraint (a repeat share of the SAME
-- member always resolves to one row regardless of key) — the idempotency key is looked up
-- explicitly by the store, not enforced by a second unique index that could conflict with the
-- first.

---- create above / drop below ----

DROP INDEX docs.document_idempotency_key_unique;
ALTER TABLE docs.document DROP COLUMN idempotency_key_hash;
ALTER TABLE docs.document DROP COLUMN idempotency_key;
ALTER TABLE docs.share DROP COLUMN idempotency_key_hash;
ALTER TABLE docs.share DROP COLUMN idempotency_key;
