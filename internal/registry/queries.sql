-- SPDX-License-Identifier: Apache-2.0

-- sqlc-generated queries for the registry service. Hand SQL for the recursive
-- dependency walk; everything else is plain CRUD sqlc handles well.

-- name: UpsertModuleCatalog :exec
-- Manifest-owned fields sync on every boot (safe to overwrite — only operator state
-- in module_installation is seed-missing-only).
INSERT INTO platform.module_catalog (
    module_key, display_name, scope_type, mandatory, base_path, health_path, port,
    license_class, manifest_version, is_active
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10
)
ON CONFLICT (module_key) DO UPDATE SET
    display_name = EXCLUDED.display_name,
    scope_type = EXCLUDED.scope_type,
    mandatory = EXCLUDED.mandatory,
    base_path = EXCLUDED.base_path,
    health_path = EXCLUDED.health_path,
    port = EXCLUDED.port,
    license_class = EXCLUDED.license_class,
    manifest_version = EXCLUDED.manifest_version,
    is_active = EXCLUDED.is_active;

-- name: SeedModuleInstallationMissing :execrows
-- Insert only when absent; NEVER overwrites existing installed/enabled.
-- ON CONFLICT DO NOTHING makes concurrent seeds (multi-replica boot) race-free.
INSERT INTO platform.module_installation (module_key, installed, enabled, version)
VALUES ($1, $2, $3, $4)
ON CONFLICT (module_key) DO NOTHING;

-- name: GetModuleCatalogEntry :one
SELECT * FROM platform.module_catalog WHERE module_key = $1;

-- name: ListModuleCatalog :many
SELECT c.*, COALESCE(i.installed, false) AS installed, COALESCE(i.enabled, false) AS enabled
FROM platform.module_catalog c
LEFT JOIN platform.module_installation i ON i.module_key = c.module_key
ORDER BY c.module_key;

-- name: ListInstallationStatusForKeys :many
-- Installation status for a module and its transitive dependency keys (order-preserving isn't
-- required; the caller indexes by module_key). Modules with no installation row yet are simply
-- absent from the result (never installed/enabled).
SELECT module_key, installed, enabled
FROM platform.module_installation
WHERE module_key = ANY(sqlc.arg(module_keys)::text[]);

-- name: ListTransitiveDependencyKeys :many
-- Transitive dependency-key closure of one module, cycle-safe: the `path` array tracks the
-- walk so far and a step is only taken if it doesn't revisit a key already on the path
-- (module_dependency.CHECK forbids self-deps, so path always starts with at least one edge).
WITH RECURSIVE deps AS (
    SELECT md0.depends_on_module_key AS dep_key, ARRAY[md0.module_key, md0.depends_on_module_key] AS path
    FROM platform.module_dependency md0
    WHERE md0.module_key = $1
    UNION
    SELECT md.depends_on_module_key, d.path || md.depends_on_module_key
    FROM platform.module_dependency md
    JOIN deps d ON md.module_key = d.dep_key
    WHERE NOT md.depends_on_module_key = ANY(d.path)
)
SELECT DISTINCT dep_key FROM deps;

-- name: SetModuleEnabled :one
UPDATE platform.module_installation
SET enabled = $2, last_seen_at = now()
WHERE module_key = $1
RETURNING module_key, installed, enabled, version, registered_at, last_seen_at;
