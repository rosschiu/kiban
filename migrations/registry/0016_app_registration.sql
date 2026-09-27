-- SPDX-License-Identifier: Apache-2.0

-- An app registered at runtime (POST /api/platform/admin/apps): it serves itself beside Kiban,
-- so the catalog's base_path/port carry no upstream (port 0 marks "external"; the gateway never
-- proxies it). service_client_id is the Keycloak client whose client-credentials token
-- identifies the app's backend (its verified `azp`); authz lets that caller write tuples on
-- the app's own object types.
ALTER TABLE platform.module_catalog DROP CONSTRAINT module_catalog_port_check;
ALTER TABLE platform.module_catalog ADD CONSTRAINT module_catalog_port_check CHECK (port >= 0 AND port < 65536);

CREATE TABLE platform.app_registration (
    module_key        text PRIMARY KEY REFERENCES platform.module_catalog (module_key) ON DELETE CASCADE,
    service_client_id text NOT NULL UNIQUE CHECK (service_client_id ~ '^[a-z][a-z0-9_-]{1,63}$'),
    features          jsonb NOT NULL DEFAULT '[]'::jsonb,
    manifest          jsonb NOT NULL,
    registered_by     text NOT NULL,
    registered_at     timestamptz NOT NULL DEFAULT now()
);

GRANT SELECT, INSERT, UPDATE, DELETE ON platform.app_registration TO kiban_registry;

---- create above / drop below ----

REVOKE ALL ON platform.app_registration FROM kiban_registry;
DROP TABLE platform.app_registration;
ALTER TABLE platform.module_catalog DROP CONSTRAINT module_catalog_port_check;
ALTER TABLE platform.module_catalog ADD CONSTRAINT module_catalog_port_check CHECK (port > 0 AND port < 65536);
