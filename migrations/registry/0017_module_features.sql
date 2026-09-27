-- SPDX-License-Identifier: Apache-2.0

-- Declared feature keys per module, on the catalog for built-ins and apps alike (authz refuses
-- a check for a feature a module does not declare). The app registration's own copy goes:
-- the manifest column still carries the original.
ALTER TABLE platform.module_catalog ADD COLUMN features jsonb NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE platform.app_registration DROP COLUMN features;

---- create above / drop below ----

ALTER TABLE platform.app_registration ADD COLUMN features jsonb NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE platform.module_catalog DROP COLUMN features;
