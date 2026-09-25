-- SPDX-License-Identifier: Apache-2.0

-- Same root cause as 0012_helpdesk_role.sql / notification's
-- 0006_notification_audit_usage.sql / timesheet's 0009_timesheet_audit_usage.sql / docs's
-- 0011_docs_audit_usage.sql: the shared `audit` schema's USAGE grant is a hand-enumerated role
-- list, immutable/shipped, so it cannot simply gain a new name. kiban_helpdesk needs USAGE on
-- `audit` for its own audit.helpdesk__events writer (internal/audit).
GRANT USAGE ON SCHEMA audit TO kiban_helpdesk;

---- create above / drop below ----

REVOKE USAGE ON SCHEMA audit FROM kiban_helpdesk;
