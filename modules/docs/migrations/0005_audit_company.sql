-- SPDX-License-Identifier: Apache-2.0

-- Every docs audit event carries the company it belongs to in payload.companyId, and the
-- module-wide audit view filters on it. Backfill rows written before this rule from the
-- document they name; an event of a document that no longer exists and never carried a
-- company cannot be attributed and stays outside every company's view.
ALTER TABLE audit.docs__events DISABLE TRIGGER docs__events_append_only;
UPDATE audit.docs__events e
SET payload = e.payload || jsonb_build_object('companyId', d.company_id::text)
FROM docs.document d
WHERE e.subject = 'docs_document:' || d.id::text
  AND NOT (e.payload ? 'companyId');
ALTER TABLE audit.docs__events ENABLE TRIGGER docs__events_append_only;

CREATE INDEX docs__events_company_occurred_idx
    ON audit.docs__events ((payload->>'companyId'), occurred_at DESC);

---- create above / drop below ----

DROP INDEX audit.docs__events_company_occurred_idx;
