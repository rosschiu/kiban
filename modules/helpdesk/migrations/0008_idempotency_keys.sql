-- SPDX-License-Identifier: Apache-2.0

-- Payload-bound Idempotency-Key support for helpdesk's non-idempotent writes
-- (notification's own idempotency_key_hash column,
-- modules/notification/migrations/0006_message_idempotency_hash.sql, is the template).
--
-- helpdesk.ticket: idempotency_key/idempotency_key_hash scoped per (company_id, reporter_kcsub,
-- key) — ticket create has no pre-existing object to scope by, same shape as timesheet's
-- submission create (company + caller).
--
-- helpdesk.comment: idempotency_key/idempotency_key_hash scoped per (ticket_id, author_kcsub,
-- key) — a comment already has an object (the ticket) to scope by; author_kcsub is included so
-- two different commenters reusing the same client-generated key on the same ticket are never
-- conflated.
ALTER TABLE helpdesk.ticket ADD COLUMN idempotency_key text;
ALTER TABLE helpdesk.ticket ADD COLUMN idempotency_key_hash text;
CREATE UNIQUE INDEX ticket_idempotency_key_unique
    ON helpdesk.ticket (company_id, reporter_kcsub, idempotency_key) WHERE idempotency_key IS NOT NULL;

ALTER TABLE helpdesk.comment ADD COLUMN idempotency_key text;
ALTER TABLE helpdesk.comment ADD COLUMN idempotency_key_hash text;
CREATE UNIQUE INDEX comment_idempotency_key_unique
    ON helpdesk.comment (ticket_id, author_kcsub, idempotency_key) WHERE idempotency_key IS NOT NULL;

---- create above / drop below ----

DROP INDEX helpdesk.comment_idempotency_key_unique;
ALTER TABLE helpdesk.comment DROP COLUMN idempotency_key_hash;
ALTER TABLE helpdesk.comment DROP COLUMN idempotency_key;
DROP INDEX helpdesk.ticket_idempotency_key_unique;
ALTER TABLE helpdesk.ticket DROP COLUMN idempotency_key_hash;
ALTER TABLE helpdesk.ticket DROP COLUMN idempotency_key;
