// SPDX-License-Identifier: Apache-2.0

package modvalidate

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func scanSQL(t *testing.T, moduleKey, sql string) []ValidationError {
	t.Helper()
	sum := sha256.Sum256([]byte(sql))
	return scanMigration(moduleKey, MigrationFile{Name: "0009_test.sql", Contents: []byte(sql), Checksum: hex.EncodeToString(sum[:])})
}

// TestScanMigration_RejectsEveryVerb is the fixture list for the statement-aware scan: every statement
// that slipped past the old leading-verb regex now fails, one fixture per verb.
func TestScanMigration_RejectsEveryVerb(t *testing.T) {
	cases := map[string]string{
		"CREATE UNLOGGED TABLE":            `CREATE UNLOGGED TABLE org.x (id int)`,
		"CREATE TEMP TABLE":                `CREATE TEMP TABLE org.x (id int)`,
		"CREATE MATERIALIZED VIEW":         `CREATE MATERIALIZED VIEW org.v AS SELECT 1`,
		"quoted schema":                    `CREATE TABLE "org".x (id int)`,
		"CREATE EXTENSION other":           `CREATE EXTENSION IF NOT EXISTS postgres_fdw`,
		"CREATE EXTENSION WITH SCHEMA":     `CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA org`,
		"DROP EXTENSION":                   `DROP EXTENSION pgcrypto`,
		"SET search_path":                  `SET search_path = org`,
		"SET ROLE":                         `SET ROLE kiban`,
		"RESET":                            `RESET search_path`,
		"CREATE POLICY":                    `CREATE POLICY p ON org.member USING (true)`,
		"CREATE ROLE":                      `CREATE ROLE evil SUPERUSER`,
		"ALTER ROLE":                       `ALTER ROLE kiban_widget SUPERUSER`,
		"DROP ROLE":                        `DROP ROLE kiban_docs`,
		"GRANT role membership":            `GRANT kiban TO kiban_widget`,
		"GRANT to other role":              `GRANT SELECT ON widget.t TO kiban_docs`,
		"GRANT to PUBLIC":                  `GRANT SELECT ON widget.t TO public`,
		"GRANT WITH GRANT OPTION":          `GRANT SELECT ON widget.t TO kiban_widget WITH GRANT OPTION`,
		"GRANT ON DATABASE":                `GRANT CONNECT ON DATABASE kiban TO kiban_widget`,
		"GRANT ON ALL TABLES IN SCHEMA":    `GRANT SELECT ON ALL TABLES IN SCHEMA org TO kiban_widget`,
		"GRANT ON SCHEMA foreign":          `GRANT USAGE ON SCHEMA org TO kiban_widget`,
		"REVOKE from other role":           `REVOKE SELECT ON widget.t FROM kiban_org`,
		"TRUNCATE foreign":                 `TRUNCATE org.member`,
		"TRUNCATE own audit table":         `TRUNCATE audit.widget__events`,
		"UPDATE foreign":                   `UPDATE org.member SET display_name = 'x'`,
		"INSERT foreign":                   `INSERT INTO org.member (id) VALUES (1)`,
		"DELETE foreign":                   `DELETE FROM org.member`,
		"DELETE USING foreign":             `DELETE FROM widget.t USING org.member m WHERE m.id = t.id`,
		"UPDATE FROM foreign":              `UPDATE widget.t SET a = m.b FROM org.member m`,
		"INSERT SELECT foreign":            `INSERT INTO widget.t SELECT id FROM org.member`,
		"WITH CTE foreign":                 `WITH x AS (SELECT id FROM org.member) INSERT INTO widget.t SELECT id FROM x`,
		"subselect foreign":                `UPDATE widget.t SET a = (SELECT count(*) FROM org.member)`,
		"CREATE TABLE public":              `CREATE TABLE public.leak (id int)`,
		"CREATE TABLE unqualified":         `CREATE TABLE leak (id int)`,
		"CREATE FUNCTION public":           `CREATE FUNCTION public.backdoor() RETURNS void AS $$ BEGIN END $$ LANGUAGE plpgsql`,
		"SECURITY DEFINER":                 `CREATE FUNCTION widget.f() RETURNS void AS $$ BEGIN END $$ LANGUAGE plpgsql SECURITY DEFINER`,
		"function SET search_path":         `CREATE FUNCTION widget.f() RETURNS void AS $$ BEGIN END $$ LANGUAGE plpgsql SET search_path = org`,
		"CREATE OR REPLACE shared fn":      `CREATE OR REPLACE FUNCTION audit.reject_mutation() RETURNS trigger AS $$ BEGIN END $$ LANGUAGE plpgsql`,
		"ALTER FUNCTION shared":            `ALTER FUNCTION audit.reject_mutation() RENAME TO x`,
		"DROP FUNCTION shared":             `DROP FUNCTION audit.reject_mutation()`,
		"ALTER FUNCTION foreign":           `ALTER FUNCTION org.f() OWNER TO kiban_widget`,
		"CREATE TRIGGER on foreign":        `CREATE TRIGGER t BEFORE UPDATE ON org.member FOR EACH ROW EXECUTE FUNCTION widget.f()`,
		"CREATE TRIGGER on unqualified":    `CREATE TRIGGER t BEFORE UPDATE ON member FOR EACH ROW EXECUTE FUNCTION widget.f()`,
		"CREATE INDEX on foreign":          `CREATE INDEX i ON org.member (id)`,
		"CREATE TYPE foreign":              `CREATE TYPE org.mood AS ENUM ('a')`,
		"CREATE SEQUENCE foreign":          `CREATE SEQUENCE org.s`,
		"CREATE VIEW foreign":              `CREATE VIEW org.v AS SELECT 1`,
		"CREATE VIEW selecting foreign":    `CREATE VIEW widget.v AS SELECT m.id FROM org.member m`,
		"CREATE SCHEMA foreign":            `CREATE SCHEMA org`,
		"CREATE SCHEMA audit not idempot.": `CREATE SCHEMA audit`,
		"CREATE SCHEMA other owner":        `CREATE SCHEMA widget AUTHORIZATION postgres`,
		"ALTER SCHEMA":                     `ALTER SCHEMA widget RENAME TO org`,
		"DROP SCHEMA foreign":              `DROP SCHEMA org CASCADE`,
		"ALTER TABLE foreign":              `ALTER TABLE org.member ADD COLUMN x int`,
		"ALTER TABLE FK to foreign":        `ALTER TABLE widget.t ADD CONSTRAINT fk FOREIGN KEY (m) REFERENCES org.member (id)`,
		"CREATE TABLE FK to foreign":       `CREATE TABLE widget.t (m uuid REFERENCES org.member (id))`,
		"ALTER TABLE OWNER TO":             `ALTER TABLE widget.t OWNER TO postgres`,
		"ALTER TABLE SET SCHEMA":           `ALTER TABLE widget.t SET SCHEMA org`,
		"ALTER TABLE unqualified":          `ALTER TABLE t ADD COLUMN x int`,
		"DROP TABLE foreign":               `DROP TABLE org.member`,
		"DROP TABLE quoted foreign":        `DROP TABLE "org"."member"`,
		"DROP TABLE unqualified":           `DROP TABLE t`,
		"DROP INDEX foreign":               `DROP INDEX org.i`,
		"DROP TRIGGER on foreign":          `DROP TRIGGER t ON org.member`,
		"audit table without prefix":       `CREATE TABLE audit.registry__events (id int)`,
		"DROP audit table without prefix":  `DROP TABLE audit.registry__events`,
		"ALTER audit table without prefix": `ALTER TABLE audit.org__events DISABLE TRIGGER ALL`,
		"GRANT on audit without prefix":    `GRANT SELECT ON audit.identity__events TO kiban_widget`,
		"other public table":               `GRANT SELECT ON public.schema_version_docs TO kiban_widget`,
		"COMMENT ON foreign":               `COMMENT ON TABLE org.member IS 'x'`,
		"COMMENT ON SCHEMA":                `COMMENT ON SCHEMA widget IS 'x'`,
		"SECURITY LABEL":                   `SECURITY LABEL ON TABLE widget.t IS 'x'`,
		"DO block":                         `DO $$ BEGIN EXECUTE 'DROP TABLE org.member'; END $$`,
		"SELECT":                           `SELECT pg_sleep(1)`,
		"COPY":                             `COPY widget.t FROM '/etc/passwd'`,
		"LOCK":                             `LOCK TABLE org.member`,
		"CALL":                             `CALL org.p()`,
		"MERGE":                            `MERGE INTO org.member m USING widget.t t ON true WHEN MATCHED THEN DELETE`,
		"ALTER DEFAULT PRIVILEGES":         `ALTER DEFAULT PRIVILEGES IN SCHEMA org GRANT SELECT ON TABLES TO kiban_widget`,
		"CREATE EVENT TRIGGER":             `CREATE EVENT TRIGGER e ON ddl_command_start EXECUTE FUNCTION widget.f()`,
		"CREATE CAST":                      `CREATE CAST (int AS text) WITH FUNCTION widget.f()`,
		"hidden in comment trick":          "/* CREATE TABLE widget.ok (id int); */ CREATE TABLE org.x (id int)",
		"multi-statement line":             `CREATE TABLE widget.ok (id int); CREATE TABLE org.x (id int)`,
	}
	for name, sql := range cases {
		t.Run(name, func(t *testing.T) {
			errs := scanSQL(t, "widget", sql)
			if !hasRule(errs, RuleMigrationCrossSchema) && !hasRule(errs, RuleMigrationUnsafeStatement) {
				t.Fatalf("expected %q to be rejected, got:\n%s", sql, joinErrs(errs))
			}
		})
	}
}

// TestScanMigration_AcceptsModuleShapes proves every statement shape the shipped modules use (and
// the sanctioned exceptions) still passes for a synthetic module.
func TestScanMigration_AcceptsModuleShapes(t *testing.T) {
	sql := `
-- SPDX-License-Identifier: Apache-2.0
CREATE SCHEMA widget AUTHORIZATION kiban;
GRANT USAGE ON SCHEMA widget TO kiban_widget;
GRANT SELECT ON public.schema_version_widget TO kiban_widget;
CREATE EXTENSION IF NOT EXISTS pgcrypto; -- gen_random_uuid()
CREATE TABLE widget.item (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id uuid NOT NULL,
    payload jsonb NOT NULL DEFAULT '{}'::jsonb,
    note text NOT NULL DEFAULT 'it''s -- not a comment; really',
    CHECK ((company_id IS NULL)::int + 1 = 1)
);
CREATE INDEX item_company_id_idx ON widget.item (company_id);
CREATE UNIQUE INDEX item_key_unique ON widget.item (company_id, note) WHERE note IS NOT NULL;
ALTER TABLE widget.item ADD COLUMN assignee uuid;
ALTER TABLE widget.item ADD CONSTRAINT item_one CHECK (assignee IS NOT NULL);
GRANT SELECT, INSERT, UPDATE, DELETE ON widget.item TO kiban_widget;
CREATE SCHEMA IF NOT EXISTS audit AUTHORIZATION kiban;
CREATE TABLE audit.widget__events (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    payload jsonb NOT NULL DEFAULT '{}'::jsonb
);
CREATE TRIGGER widget__events_append_only
    BEFORE UPDATE OR DELETE ON audit.widget__events
    FOR EACH ROW EXECUTE FUNCTION audit.reject_mutation();
CREATE TRIGGER widget__events_reject_truncate BEFORE TRUNCATE ON audit.widget__events
    FOR EACH STATEMENT EXECUTE FUNCTION audit.reject_mutation();
GRANT SELECT, INSERT ON audit.widget__events TO kiban_widget;
GRANT USAGE ON SCHEMA audit TO kiban_widget;
CREATE OR REPLACE FUNCTION widget.touch() RETURNS trigger AS $body$
BEGIN
    UPDATE org.member SET x = 1; -- opaque body: runs as the caller, never the owner
    RETURN NEW;
END;
$body$ LANGUAGE plpgsql;
ALTER TABLE audit.widget__events DISABLE TRIGGER widget__events_append_only;
UPDATE audit.widget__events e
SET payload = e.payload || jsonb_build_object('companyId', i.company_id::text)
FROM widget.item i
WHERE e.payload->>'id' = i.id::text AND NOT (e.payload ? 'companyId');
ALTER TABLE audit.widget__events ENABLE TRIGGER widget__events_append_only;
INSERT INTO widget.item (company_id) SELECT company_id FROM widget.item WHERE false;
DELETE FROM widget.item WHERE extract(epoch FROM now()) < 0;
TRUNCATE widget.item;
COMMENT ON TABLE widget.item IS 'items';
COMMENT ON COLUMN widget.item.note IS 'free text';
CREATE VIEW widget.v AS SELECT i.id, i.note FROM widget.item i;
---- create above / drop below ----
DROP VIEW widget.v;
REVOKE ALL ON audit.widget__events FROM kiban_widget;
DROP TRIGGER widget__events_append_only ON audit.widget__events;
DROP TABLE audit.widget__events;
DROP INDEX widget.item_key_unique;
DROP FUNCTION widget.touch();
DROP TABLE widget.item;
REVOKE SELECT ON public.schema_version_widget FROM kiban_widget;
REVOKE USAGE ON SCHEMA widget FROM kiban_widget;
DROP SCHEMA widget CASCADE;
`
	if errs := scanSQL(t, "widget", sql); len(errs) > 0 {
		t.Fatalf("expected the module-shaped migration to pass, got:\n%s", joinErrs(errs))
	}
}

// TestScanMigration_GrandfatheredSharedFunction: the four shipped 0003_audit.sql
// files may keep their CREATE OR REPLACE FUNCTION audit.reject_mutation(); the same statement in
// any other file (a new migration, or an edited copy) is refused.
func TestScanMigration_GrandfatheredSharedFunction(t *testing.T) {
	for _, mod := range []string{"notification", "timesheet", "docs", "helpdesk"} {
		files, loadErrs := LoadMigrationsDir(mod, repoPath(t, "modules", mod, "migrations"))
		if len(loadErrs) > 0 {
			t.Fatalf("%s: %v", mod, loadErrs)
		}
		var shipped *MigrationFile
		for i := range files {
			if files[i].Name == "0003_audit.sql" {
				shipped = &files[i]
			}
		}
		if shipped == nil {
			t.Fatalf("%s: no 0003_audit.sql", mod)
		}
		if _, ok := grandfatheredMigrations[shipped.Checksum]; !ok {
			t.Fatalf("%s/0003_audit.sql is not in grandfatheredMigrations (checksum %s)", mod, shipped.Checksum)
		}
		if errs := scanMigration(mod, *shipped); len(errs) > 0 {
			t.Fatalf("%s/0003_audit.sql must still pass:\n%s", mod, joinErrs(errs))
		}
		// The same bytes with one comment appended are no longer the shipped file.
		edited := string(shipped.Contents) + "\n-- edited\n"
		errs := scanSQL(t, mod, edited)
		if !hasRule(errs, RuleMigrationCrossSchema) || !strings.Contains(joinErrs(errs), "reject_mutation") {
			t.Fatalf("%s: an edited copy must be refused, got:\n%s", mod, joinErrs(errs))
		}
	}
}

func TestTokenize_QuotesCommentsDollars(t *testing.T) {
	toks := tokenize(`SELECT 'a''b', E'c\'d', "Quoted Id", $$x;y$$, $t$ $$ $t$, $1, 1.5 -- c
/* nested /* comment */ */ x.y`)
	var got []string
	for _, tk := range toks {
		got = append(got, tk.text)
	}
	want := []string{"select", "a'b", ",", "c'd", ",", "Quoted Id", ",", "x;y", ",", " $$ ", ",", "$", ",", "1.5", "x", ".", "y"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("tokens:\n got %q\nwant %q", got, want)
	}
	if len(splitStatements(toks)) != 1 {
		t.Fatal("a ';' inside a dollar quote must not split the statement")
	}
}
