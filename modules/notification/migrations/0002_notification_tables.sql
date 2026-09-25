-- SPDX-License-Identifier: Apache-2.0

-- Notification tables: channel, subscription, message, recipient_state,
-- delivery_job (lease columns: leased_until, attempts, last_error — leased-job pattern).
-- company_id/companyId is a plain uuid column here, never a cross-schema FK to org.org_unit
-- (modules never reach into foundation schemas — the module consumes org's company facts
-- through its API only; company existence/membership is verified by the service at
-- request time via org's internal facts endpoint, not enforced in SQL).
CREATE EXTENSION IF NOT EXISTS pgcrypto; -- gen_random_uuid()

CREATE TABLE notification.channel (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id uuid NOT NULL,
    key        text NOT NULL CHECK (key ~ '^[a-z][a-z0-9_-]{1,63}$'),
    label      text NOT NULL CHECK (char_length(label) BETWEEN 1 AND 120),
    kind       text NOT NULL CHECK (kind IN ('in_app', 'email', 'webhook')),
    target     text, -- webhook URL for kind='webhook'; unused for in_app/email
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (company_id, key)
);

CREATE INDEX channel_company_id_idx ON notification.channel (company_id);

CREATE TABLE notification.subscription (
    channel_id uuid NOT NULL REFERENCES notification.channel (id) ON DELETE CASCADE,
    subject    text NOT NULL, -- caller's kcSub (subject only, never a role)
    email      text,          -- subscriber-supplied delivery address, required for kind='email' channels
    muted      boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (channel_id, subject)
);

CREATE TABLE notification.message (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id      uuid NOT NULL,
    channel_id      uuid NOT NULL REFERENCES notification.channel (id) ON DELETE CASCADE,
    subject_line    text NOT NULL CHECK (char_length(subject_line) BETWEEN 1 AND 200),
    body            text NOT NULL,
    created_by      text NOT NULL, -- caller's kcSub
    idempotency_key text,
    created_at      timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX message_channel_id_idx ON notification.message (channel_id);
CREATE INDEX message_company_id_idx ON notification.message (company_id);
-- Idempotency-Key scoped per channel (Idempotency-Key, <=200 chars, on
-- effectful POSTs where retry is expected); NULL keys never collide (partial index).
CREATE UNIQUE INDEX message_channel_idempotency_key_unique
    ON notification.message (channel_id, idempotency_key) WHERE idempotency_key IS NOT NULL;

CREATE TABLE notification.recipient_state (
    message_id uuid NOT NULL REFERENCES notification.message (id) ON DELETE CASCADE,
    subject    text NOT NULL,
    read_at    timestamptz,
    PRIMARY KEY (message_id, subject)
);

CREATE INDEX recipient_state_subject_idx ON notification.recipient_state (subject);

-- delivery_job: leased background delivery. claim = UPDATE ... leased_until=now()+30s,
-- attempts=attempts+1 WHERE status='pending' AND (leased_until IS NULL OR leased_until<now())
-- ORDER BY created_at LIMIT n FOR UPDATE SKIP LOCKED RETURNING *. deliver: email->mailpit smtp |
-- webhook->POST with hmac header; success=>done, fail=>pending (attempts>=8=>dead+audited);
-- worker heartbeats extend lease; crash => lease expiry re-claims.
CREATE TABLE notification.delivery_job (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    message_id   uuid NOT NULL REFERENCES notification.message (id) ON DELETE CASCADE,
    kind         text NOT NULL CHECK (kind IN ('email', 'webhook')),
    target       text NOT NULL,
    status       text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'done', 'dead')),
    attempts     integer NOT NULL DEFAULT 0,
    leased_until timestamptz,
    last_error   text,
    created_at   timestamptz NOT NULL DEFAULT now()
);

-- Partial claim index: the claim query filters status='pending' and orders by created_at; a
-- partial index on the pending subset keeps the SKIP LOCKED scan cheap regardless of how many
-- done/dead jobs accumulate.
CREATE INDEX delivery_job_claim_idx ON notification.delivery_job (created_at) WHERE status = 'pending';
CREATE INDEX delivery_job_message_id_idx ON notification.delivery_job (message_id);

GRANT SELECT, INSERT, UPDATE, DELETE ON
    notification.channel,
    notification.subscription,
    notification.message,
    notification.recipient_state,
    notification.delivery_job
TO kiban_notification;

---- create above / drop below ----

REVOKE ALL ON
    notification.channel,
    notification.subscription,
    notification.message,
    notification.recipient_state,
    notification.delivery_job
FROM kiban_notification;

DROP TABLE notification.delivery_job;
DROP TABLE notification.recipient_state;
DROP TABLE notification.message;
DROP TABLE notification.subscription;
DROP TABLE notification.channel;
