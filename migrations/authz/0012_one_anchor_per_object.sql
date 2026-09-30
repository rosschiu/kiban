-- SPDX-License-Identifier: Apache-2.0

-- One company anchor per object. authz.tuple's primary key spans the whole tuple, so two anchor
-- rows (`<obj>#company_module @ company_module:<A>/<M>` and `... @ company_module:<B>/<M>`)
-- both fit, and an object could be read from two companies. The grants handler refuses a second
-- anchor with 422 (internal/authz/http.go, K25); this partial unique index is the guarantee
-- behind it for every write path, including two concurrent requests. Partial on the anchor
-- shape only, so ordinary relations (many viewers per object) are untouched.
--
-- Fails to build if an installation already holds a double-anchored object; find them with:
--   SELECT object_type, object_id, count(*) FROM authz.tuple
--   WHERE relation = 'company_module' AND subject_type = 'company_module'
--   GROUP BY 1, 2 HAVING count(*) > 1;
-- and revoke the anchor that should not exist before re-running the migration.
CREATE UNIQUE INDEX tuple_one_anchor_per_object
    ON authz.tuple (object_type, object_id)
    WHERE relation = 'company_module' AND subject_type = 'company_module';

---- create above / drop below ----

DROP INDEX authz.tuple_one_anchor_per_object;
