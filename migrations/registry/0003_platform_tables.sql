-- SPDX-License-Identifier: Apache-2.0

-- Registry tables.
CREATE TABLE platform.module_catalog (
    module_key       text PRIMARY KEY CHECK (module_key ~ '^[a-z][a-z0-9_]{1,31}$'),
    display_name     text NOT NULL,
    scope_type       text NOT NULL CHECK (scope_type IN ('global', 'company')),
    mandatory        boolean NOT NULL DEFAULT false,
    base_path        text NOT NULL,
    health_path      text NOT NULL DEFAULT '/health',
    port             integer NOT NULL CHECK (port > 0 AND port < 65536),
    license_class    text NOT NULL CHECK (license_class IN ('foundation', 'open', 'commercial')),
    manifest_version text NOT NULL,
    is_active        boolean NOT NULL DEFAULT true
);

CREATE TABLE platform.module_installation (
    module_key    text PRIMARY KEY REFERENCES platform.module_catalog (module_key) ON DELETE CASCADE,
    installed     boolean NOT NULL DEFAULT false,
    enabled       boolean NOT NULL DEFAULT false,
    version       text,
    registered_at timestamptz NOT NULL DEFAULT now(),
    last_seen_at  timestamptz
);

CREATE TABLE platform.module_dependency (
    module_key            text NOT NULL REFERENCES platform.module_catalog (module_key) ON DELETE CASCADE,
    depends_on_module_key text NOT NULL REFERENCES platform.module_catalog (module_key) ON DELETE RESTRICT,
    version_range         text NOT NULL,
    PRIMARY KEY (module_key, depends_on_module_key),
    CHECK (module_key <> depends_on_module_key)
);

-- Single row, tenant-wide defaults. tenant_id is fixed to 'default' — Kiban v0
-- has no multi-tenant-deployment concept yet (a single deployment is one tenant).
CREATE TABLE platform.tenant_defaults (
    tenant_id text PRIMARY KEY DEFAULT 'default' CHECK (tenant_id = 'default'),
    locale    text NOT NULL DEFAULT 'en',
    timezone  text NOT NULL DEFAULT 'UTC',
    currency  text NOT NULL DEFAULT 'USD'
);

INSERT INTO platform.tenant_defaults (tenant_id) VALUES ('default');

GRANT SELECT, INSERT, UPDATE, DELETE ON
    platform.module_catalog,
    platform.module_installation,
    platform.module_dependency,
    platform.tenant_defaults
TO kiban_registry;

---- create above / drop below ----

REVOKE ALL ON
    platform.module_catalog,
    platform.module_installation,
    platform.module_dependency,
    platform.tenant_defaults
FROM kiban_registry;
DROP TABLE platform.tenant_defaults;
DROP TABLE platform.module_dependency;
DROP TABLE platform.module_installation;
DROP TABLE platform.module_catalog;
