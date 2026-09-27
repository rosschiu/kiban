-- SPDX-License-Identifier: Apache-2.0

-- Same root cause as 0008_timesheet_role.sql / notification's
-- 0006_notification_audit_usage.sql: the shared `audit` schema's USAGE grant is a hand-enumerated
-- role list, immutable/shipped, so it cannot simply gain a new name. kiban_timesheet needs USAGE
-- on `audit` for its own audit.timesheet__events writer (internal/audit).
GRANT USAGE ON SCHEMA audit TO kiban_timesheet;

---- create above / drop below ----

REVOKE USAGE ON SCHEMA audit FROM kiban_timesheet;
