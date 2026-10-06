-- SPDX-License-Identifier: Apache-2.0

-- A user account is a person or a service (a Keycloak client's service account: the identity an
-- app's backend uses when no human is present). Both are users to authorization; the kind exists
-- so directories and apps can tell them apart. Set at provisioning by asking Keycloak (the
-- client's service-account-user link); existing rows are classified by Keycloak's fixed
-- service-account-<client> username convention.
ALTER TABLE identity.user_account
    ADD COLUMN kind text NOT NULL DEFAULT 'person' CHECK (kind IN ('person', 'service'));

UPDATE identity.user_account SET kind = 'service' WHERE preferred_username LIKE 'service-account-%';

-- The published read view (0003) gains the column; grants on the view are unchanged.
CREATE OR REPLACE VIEW identity.user_read_v AS
SELECT id, kc_sub, email, preferred_username, lifecycle, kind
FROM identity.user_account;

---- create above / drop below ----

CREATE OR REPLACE VIEW identity.user_read_v AS
SELECT id, kc_sub, email, preferred_username, lifecycle
FROM identity.user_account;

ALTER TABLE identity.user_account DROP COLUMN kind;
