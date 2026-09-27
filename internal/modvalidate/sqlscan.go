// SPDX-License-Identifier: Apache-2.0

package modvalidate

import (
	"maps"
	"slices"
	"strings"
)

// Statement-aware scan of a module migration. Not a SQL parser
// (pg_query_go is only a transitive `go tool sqlc` dependency here; importing it would add a cgo
// build of the whole Postgres parser to every `go build ./...` and to the service image) but a
// tokenizer — strings, comments, dollar-quotes and quoted identifiers are real tokens, so nothing
// hides behind a quote or a comment — plus a positive rule table: every statement kind a module
// migration may contain is listed below; anything else is refused by name.
//
// Known ceiling: dollar-quoted/string function bodies are opaque. A body only ever runs as its caller
// (the runtime role, no DDL rights) because SECURITY DEFINER is refused, and DO blocks (which
// would run as the migration owner) are refused outright.

type tokKind int

const (
	tIdent  tokKind = iota // unquoted (lowercased) or quoted identifier
	tString                // '...', E'...', $$...$$
	tNumber
	tPunct
)

type token struct {
	kind   tokKind
	text   string
	quoted bool // quoted identifier: text is verbatim, never a keyword
}

// tokenize splits SQL into tokens, dropping comments.
func tokenize(src string) []token {
	var out []token
	i := 0
	for i < len(src) {
		c := src[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			i++
		case c == '-' && i+1 < len(src) && src[i+1] == '-':
			for i < len(src) && src[i] != '\n' {
				i++
			}
		case c == '/' && i+1 < len(src) && src[i+1] == '*':
			depth := 0
			for i < len(src) {
				if strings.HasPrefix(src[i:], "/*") {
					depth++
					i += 2
				} else if strings.HasPrefix(src[i:], "*/") {
					depth--
					i += 2
					if depth == 0 {
						break
					}
				} else {
					i++
				}
			}
		case c == '\'' || ((c == 'e' || c == 'E') && i+1 < len(src) && src[i+1] == '\''):
			escaped := c != '\''
			if escaped {
				i++
			}
			i++ // opening quote
			var b strings.Builder
			for i < len(src) {
				if escaped && src[i] == '\\' && i+1 < len(src) {
					b.WriteByte(src[i+1])
					i += 2
					continue
				}
				if src[i] == '\'' {
					if i+1 < len(src) && src[i+1] == '\'' {
						b.WriteByte('\'')
						i += 2
						continue
					}
					i++
					break
				}
				b.WriteByte(src[i])
				i++
			}
			out = append(out, token{kind: tString, text: b.String()})
		case c == '"':
			i++
			var b strings.Builder
			for i < len(src) {
				if src[i] == '"' {
					if i+1 < len(src) && src[i+1] == '"' {
						b.WriteByte('"')
						i += 2
						continue
					}
					i++
					break
				}
				b.WriteByte(src[i])
				i++
			}
			out = append(out, token{kind: tIdent, text: b.String(), quoted: true})
		case c == '$':
			// $tag$ ... $tag$ dollar quote, or a $1 parameter, or a bare punct.
			j := i + 1
			for j < len(src) && isIdentChar(src[j]) && src[j] != '$' {
				j++
			}
			if j < len(src) && src[j] == '$' && (j == i+1 || isIdentStart(src[i+1])) {
				tag := src[i : j+1]
				end := strings.Index(src[j+1:], tag)
				if end < 0 {
					out = append(out, token{kind: tString, text: src[j+1:]})
					i = len(src)
				} else {
					out = append(out, token{kind: tString, text: src[j+1 : j+1+end]})
					i = j + 1 + end + len(tag)
				}
			} else if i+1 < len(src) && src[i+1] >= '0' && src[i+1] <= '9' {
				for i < len(src) && (src[i] == '$' || (src[i] >= '0' && src[i] <= '9')) {
					i++
				}
				out = append(out, token{kind: tNumber, text: "$"})
			} else {
				out = append(out, token{kind: tPunct, text: "$"})
				i++
			}
		case isIdentStart(c):
			j := i
			for j < len(src) && isIdentChar(src[j]) {
				j++
			}
			out = append(out, token{kind: tIdent, text: strings.ToLower(src[i:j])})
			i = j
		case c >= '0' && c <= '9':
			j := i
			for j < len(src) && (isIdentChar(src[j]) || src[j] == '.') {
				j++
			}
			out = append(out, token{kind: tNumber, text: src[i:j]})
			i = j
		default:
			out = append(out, token{kind: tPunct, text: string(c)})
			i++
		}
	}
	return out
}

func isIdentStart(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c >= 0x80
}

func isIdentChar(c byte) bool {
	return isIdentStart(c) || (c >= '0' && c <= '9') || c == '$'
}

// splitStatements cuts a token stream on top-level ';'.
func splitStatements(toks []token) [][]token {
	var out [][]token
	var cur []token
	for _, t := range toks {
		if t.kind == tPunct && t.text == ";" {
			if len(cur) > 0 {
				out = append(out, cur)
			}
			cur = nil
			continue
		}
		cur = append(cur, t)
	}
	if len(cur) > 0 {
		out = append(out, cur)
	}
	return out
}

// kw returns the unquoted keyword at i (lowercased), or "" for anything else.
func kw(ts []token, i int) string {
	if i < 0 || i >= len(ts) || ts[i].kind != tIdent || ts[i].quoted {
		return ""
	}
	return ts[i].text
}

// schemaRef is one `schema.name[.column]` reference and the token index it starts at.
type schemaRef struct {
	schema, name string
	pos          int
}

// refAt parses a possibly-qualified name at i. Returns the ref (schema "" when unqualified) and
// the index just past it (a trailing `.column` is consumed).
func refAt(ts []token, i int) (schemaRef, int) {
	if i >= len(ts) || ts[i].kind != tIdent {
		return schemaRef{pos: i}, i
	}
	r := schemaRef{name: ts[i].text, pos: i}
	i++
	if i+1 < len(ts) && ts[i].kind == tPunct && ts[i].text == "." && ts[i+1].kind == tIdent {
		r.schema, r.name = r.name, ts[i+1].text
		i += 2
		if i+1 < len(ts) && ts[i].kind == tPunct && ts[i].text == "." && ts[i+1].kind == tIdent {
			i += 2 // column
		}
	}
	return r, i
}

// allRefs returns every qualified reference in ts[from:to].
func allRefs(ts []token, from, to int) []schemaRef {
	var out []schemaRef
	for i := from; i < to; {
		r, next := refAt(ts, i)
		if next == i {
			i++
			continue
		}
		if r.schema != "" {
			out = append(out, r)
		}
		i = next
	}
	return out
}

// dmlRefs returns the qualified table references at DML table positions (INTO / UPDATE / FROM /
// JOIN / USING / ONLY) — column references like `alias.col` are never at those positions.
// Known ceiling: an expression-position function call (`SELECT other.fn()`) is not seen; such a call
// runs as the runtime role at request time anyway, never with DDL rights.
func dmlRefs(ts []token, from, to int) []schemaRef {
	var out []schemaRef
	for i := from; i < to; i++ {
		switch kw(ts, i) {
		case "into", "update", "from", "join", "using", "only":
			r, next := refAt(ts, i+1)
			if next > i+1 && r.schema != "" {
				out = append(out, r)
			}
		}
	}
	return out
}

// sqlScan holds one module's scope for a migration scan.
type sqlScan struct {
	moduleKey     string
	file          string
	grandfathered bool // this exact file is in grandfatheredMigrations
	errs          []ValidationError
}

// grandfatheredMigrations are the shipped module migrations (by sha256 of their content) that
// `CREATE OR REPLACE FUNCTION audit.reject_mutation()` before the rule forbidding replacement of a shared
// function. Only these exact bytes may still do so; any new or edited file fails. Referencing the
// function (`EXECUTE FUNCTION audit.reject_mutation()`) stays allowed for everyone.
var grandfatheredMigrations = map[string]string{
	"d6f7ea747260278ff115ac1d7597de8ef80bbccd3f40c7d6fb8cd9f48c883207": "modules/notification/migrations/0003_audit.sql",
	"dc4c983ab0fdfa989fc6bb5e11b0d841620260538123ce5c575227658298358e": "modules/timesheet/migrations/0003_audit.sql",
	"4fac26da34ae6af10d01b439e86cc0c54e84e4f2eaa4f66254f5dc6d2ed09241": "modules/docs/migrations/0003_audit.sql",
	"0aac013ce237b0395cf5680db60af67904a53837a45d37b3cc68a70af169d862": "modules/helpdesk/migrations/0003_audit.sql",
}

// sharedAuditFunction is the one platform function a module migration may reference (as a trigger
// function) outside the audit.<moduleKey>__* fence.
const sharedAuditFunction = "reject_mutation"

// allowedExtensions is exactly what the shipped modules need (gen_random_uuid()).
var allowedExtensions = map[string]bool{"pgcrypto": true}

// Positive allowlists — the rule table. Kinds not listed are refused by name.
var (
	createKinds = map[string]bool{"schema": true, "extension": true, "table": true, "index": true,
		"function": true, "procedure": true, "trigger": true, "type": true, "sequence": true,
		"view": true, "policy": true, "domain": true}
	alterKinds = map[string]bool{"table": true, "index": true, "function": true, "procedure": true,
		"trigger": true, "type": true, "sequence": true, "view": true, "policy": true, "domain": true}
	dropKinds = map[string]bool{"schema": true, "table": true, "index": true, "function": true,
		"procedure": true, "trigger": true, "type": true, "sequence": true, "view": true,
		"policy": true, "domain": true}
	commentKinds = map[string]bool{"table": true, "column": true, "index": true, "function": true,
		"procedure": true, "trigger": true, "type": true, "sequence": true, "view": true,
		"policy": true, "domain": true, "constraint": true}
	// object kinds whose name is schema-scoped (must be schema-qualified in a migration, or it
	// lands wherever search_path points — public). An index/trigger/policy name is scoped by its
	// `ON <schema.table>`, which is what gets checked instead.
	schemaScopedKinds = map[string]bool{"table": true, "function": true, "procedure": true,
		"type": true, "sequence": true, "view": true, "domain": true}
	createModifiers = map[string]bool{"or": true, "replace": true, "unique": true, "materialized": true,
		"temp": true, "temporary": true, "unlogged": true, "constraint": true, "global": true, "local": true}
)

func (s *sqlScan) fail(rule, format string, args ...any) {
	s.errs = append(s.errs, errf(s.moduleKey, rule, "migrations/"+s.file+": "+format, args...))
}

// checkRef enforces the schema fence on one qualified reference. target says the statement
// creates/alters/drops/grants/truncates the object (as opposed to merely referencing it).
func (s *sqlScan) checkRef(r schemaRef, target bool) {
	switch {
	case r.schema == s.moduleKey:
		return
	case r.schema == "audit" && strings.HasPrefix(r.name, s.moduleKey+"__"):
		return
	case r.schema == "audit" && r.name == sharedAuditFunction:
		if !target || s.grandfathered {
			return
		}
		s.fail(RuleMigrationCrossSchema, "audit.%s is a shared platform function — a module migration may reference it but never replace, alter or drop it (grandfathered only for the shipped %v)",
			r.name, sortedValues(grandfatheredMigrations))
		return
	case r.schema == "public" && r.name == "schema_version_"+s.moduleKey:
		return
	}
	s.fail(RuleMigrationCrossSchema, "%s.%s: a module migration may only touch its own schema %q, audit.%s__* objects, or public.schema_version_%s",
		r.schema, r.name, s.moduleKey, s.moduleKey, s.moduleKey)
}

// scanMigration runs the rule table over every statement of one migration file.
func scanMigration(moduleKey string, mf MigrationFile) []ValidationError {
	_, grandfathered := grandfatheredMigrations[mf.Checksum]
	s := &sqlScan{moduleKey: moduleKey, file: mf.Name, grandfathered: grandfathered}
	for _, st := range splitStatements(tokenize(string(mf.Contents))) {
		s.statement(st)
	}
	return s.errs
}

func (s *sqlScan) statement(ts []token) {
	switch kw(ts, 0) {
	case "create":
		s.create(ts)
	case "alter":
		s.alter(ts)
	case "drop":
		s.drop(ts)
	case "grant", "revoke":
		s.grant(ts)
	case "truncate":
		i := 1
		for kw(ts, i) == "table" || kw(ts, i) == "only" {
			i++
		}
		for _, r := range s.targetList(ts, i) {
			if r.schema != s.moduleKey {
				s.fail(RuleMigrationUnsafeStatement, "TRUNCATE %s.%s: a module migration may only truncate tables in its own schema %q (audit tables are append-only)", r.schema, r.name, s.moduleKey)
			}
		}
	case "insert", "update", "delete", "with":
		for _, r := range dmlRefs(ts, 0, len(ts)) {
			s.checkRef(r, true)
		}
	case "comment":
		s.comment(ts)
	default:
		s.fail(RuleMigrationUnsafeStatement, "statement %q is not allowed in a module migration (allowed: CREATE/ALTER/DROP of schema-scoped objects, GRANT/REVOKE to the module role, INSERT/UPDATE/DELETE/TRUNCATE on own tables, COMMENT ON)", strings.ToUpper(describe(ts)))
	}
}

func (s *sqlScan) create(ts []token) {
	i := 1
	for createModifiers[kw(ts, i)] {
		i++
	}
	kind := kw(ts, i)
	if !createKinds[kind] {
		s.fail(RuleMigrationUnsafeStatement, "CREATE %s is not allowed in a module migration", strings.ToUpper(describe(ts[i:])))
		return
	}
	i++
	if kw(ts, i) == "concurrently" {
		i++
	}
	ifNotExists := kw(ts, i) == "if" && kw(ts, i+1) == "not" && kw(ts, i+2) == "exists"
	if ifNotExists {
		i += 3
	}
	switch kind {
	case "schema":
		name := kw(ts, i)
		if name != s.moduleKey && !(name == "audit" && ifNotExists) {
			s.fail(RuleMigrationCrossSchema, "CREATE SCHEMA %s: a module migration may only create its own schema %q (or idempotently the shared audit schema)", name, s.moduleKey)
		}
		if kw(ts, i+1) == "authorization" && kw(ts, i+2) != "kiban" {
			s.fail(RuleMigrationUnsafeStatement, "CREATE SCHEMA %s AUTHORIZATION %s: schemas are owned by the migration owner role kiban", name, kw(ts, i+2))
		}
		return
	case "extension":
		name := kw(ts, i)
		if !allowedExtensions[name] || i+1 != len(ts) {
			s.fail(RuleMigrationUnsafeStatement, "CREATE EXTENSION %s: only `CREATE EXTENSION [IF NOT EXISTS] %v` (no WITH SCHEMA/VERSION clause) is allowed", describe(ts[i:]), sortedKeys(allowedExtensions))
		}
		return
	}
	s.forbidAnywhere(ts)
	target, next := refAt(ts, i)
	if schemaScopedKinds[kind] && target.schema == "" {
		s.fail(RuleMigrationCrossSchema, "CREATE %s %s: the name must be schema-qualified (%s.%s) — an unqualified name lands on search_path", strings.ToUpper(kind), target.name, s.moduleKey, target.name)
	}
	if target.schema != "" {
		s.checkRef(target, true)
	}
	// `ON <table>` for index/trigger/policy: the table is the real target.
	for j := next; j < len(ts); j++ {
		if kw(ts, j) == "on" {
			r, n := refAt(ts, j+1)
			if n > j+1 {
				if r.schema == "" && (kind == "index" || kind == "trigger" || kind == "policy") {
					s.fail(RuleMigrationCrossSchema, "CREATE %s %s ON %s: the table must be schema-qualified", strings.ToUpper(kind), target.name, r.name)
				} else if r.schema != "" {
					s.checkRef(r, true)
				}
			}
			break
		}
	}
	// Everything else in the statement is a reference. A query tail (CREATE VIEW ... AS SELECT,
	// CREATE TABLE ... AS SELECT) is scanned at DML positions since it carries aliases.
	end := len(ts)
	if kind == "view" || kind == "table" {
		for j := next; j < len(ts); j++ {
			if kw(ts, j) == "as" {
				end = j
				for _, r := range dmlRefs(ts, j, len(ts)) {
					s.checkRef(r, false)
				}
				break
			}
		}
	}
	for _, r := range allRefs(ts, next, end) {
		s.checkRef(r, false)
	}
}

func (s *sqlScan) alter(ts []token) {
	i := 1
	if kw(ts, i) == "materialized" {
		i++
	}
	kind := kw(ts, i)
	if !alterKinds[kind] {
		s.fail(RuleMigrationUnsafeStatement, "ALTER %s is not allowed in a module migration", strings.ToUpper(describe(ts[i:])))
		return
	}
	i++
	for kw(ts, i) == "if" || kw(ts, i) == "exists" || kw(ts, i) == "only" {
		i++
	}
	s.forbidAnywhere(ts)
	for j := i; j+1 < len(ts); j++ {
		switch {
		case kw(ts, j) == "owner" && kw(ts, j+1) == "to":
			s.fail(RuleMigrationUnsafeStatement, "ALTER ... OWNER TO: a module migration may not change object ownership")
		case kw(ts, j) == "set" && kw(ts, j+1) == "schema":
			s.fail(RuleMigrationUnsafeStatement, "ALTER ... SET SCHEMA: a module migration may not move objects between schemas")
		}
	}
	target, next := refAt(ts, i)
	if kind == "trigger" || kind == "policy" {
		// ALTER TRIGGER name ON table ...
		for j := next; j < len(ts); j++ {
			if kw(ts, j) == "on" {
				target, next = refAt(ts, j+1)
				break
			}
		}
	}
	if target.schema == "" {
		s.fail(RuleMigrationCrossSchema, "ALTER %s %s: the name must be schema-qualified", strings.ToUpper(kind), target.name)
	} else {
		s.checkRef(target, true)
	}
	for _, r := range allRefs(ts, next, len(ts)) {
		s.checkRef(r, false)
	}
}

func (s *sqlScan) drop(ts []token) {
	kind := kw(ts, 1)
	if !dropKinds[kind] {
		s.fail(RuleMigrationUnsafeStatement, "DROP %s is not allowed in a module migration", strings.ToUpper(describe(ts[1:])))
		return
	}
	i := 2
	if kw(ts, i) == "concurrently" {
		i++
	}
	if kw(ts, i) == "if" && kw(ts, i+1) == "exists" {
		i += 2
	}
	if kind == "schema" {
		if name := kw(ts, i); name != s.moduleKey {
			s.fail(RuleMigrationCrossSchema, "DROP SCHEMA %s: a module migration may only drop its own schema %q", name, s.moduleKey)
		}
		return
	}
	if kind == "trigger" || kind == "policy" {
		for j := i; j < len(ts); j++ {
			if kw(ts, j) == "on" {
				i = j + 1
				break
			}
		}
	}
	for _, r := range s.targetList(ts, i) {
		s.checkRef(r, true)
	}
}

// targetList parses `ref[, ref...]` at i, refusing unqualified names.
func (s *sqlScan) targetList(ts []token, i int) []schemaRef {
	var out []schemaRef
	for i < len(ts) {
		r, next := refAt(ts, i)
		if next == i {
			break
		}
		if r.schema == "" {
			s.fail(RuleMigrationCrossSchema, "%s: object names must be schema-qualified in a module migration", r.name)
		} else {
			out = append(out, r)
		}
		// skip a function argument list
		if next < len(ts) && ts[next].kind == tPunct && ts[next].text == "(" {
			depth := 0
			for next < len(ts) {
				if ts[next].kind == tPunct && ts[next].text == "(" {
					depth++
				} else if ts[next].kind == tPunct && ts[next].text == ")" {
					depth--
					if depth == 0 {
						next++
						break
					}
				}
				next++
			}
		}
		if next < len(ts) && ts[next].kind == tPunct && ts[next].text == "," {
			i = next + 1
			continue
		}
		break
	}
	return out
}

func (s *sqlScan) grant(ts []token) {
	verb := strings.ToUpper(kw(ts, 0))
	on := -1
	for j := range ts {
		if kw(ts, j) == "on" {
			on = j
			break
		}
	}
	if on < 0 {
		s.fail(RuleMigrationUnsafeStatement, "%s without ON: role membership grants are not allowed in a module migration", verb)
		return
	}
	for j := range ts {
		if kw(ts, j) == "grant" && kw(ts, j+1) == "option" {
			s.fail(RuleMigrationUnsafeStatement, "%s ... GRANT OPTION is not allowed in a module migration", verb)
		}
	}
	i := on + 1
	switch kw(ts, i) {
	case "schema":
		for _, r := range s.nameList(ts, i+1) {
			if r != s.moduleKey && r != "audit" {
				s.fail(RuleMigrationCrossSchema, "%s ... ON SCHEMA %s: a module migration may only grant on its own schema %q or the shared audit schema", verb, r, s.moduleKey)
			}
		}
	case "all":
		// ALL TABLES|SEQUENCES|FUNCTIONS|ROUTINES IN SCHEMA name
		j := i
		for j < len(ts) && kw(ts, j) != "schema" {
			j++
		}
		for _, r := range s.nameList(ts, j+1) {
			if r != s.moduleKey {
				s.fail(RuleMigrationCrossSchema, "%s ... ON ALL ... IN SCHEMA %s: a module migration may only grant on its own schema %q", verb, r, s.moduleKey)
			}
		}
	case "table", "sequence", "function", "procedure", "routine":
		for _, r := range s.targetList(ts, i+1) {
			s.checkRef(r, true)
		}
	case "database", "tablespace", "language", "foreign", "large", "type", "domain", "parameter":
		s.fail(RuleMigrationUnsafeStatement, "%s ... ON %s is not allowed in a module migration", verb, strings.ToUpper(kw(ts, i)))
	default:
		for _, r := range s.targetList(ts, i) {
			s.checkRef(r, true)
		}
	}
	roleKw := "to"
	if verb == "REVOKE" {
		roleKw = "from"
	}
	want := "kiban_" + s.moduleKey
	for j := on; j < len(ts); j++ {
		if kw(ts, j) == roleKw {
			for _, r := range s.nameList(ts, j+1) {
				if r != want {
					s.fail(RuleMigrationUnsafeStatement, "%s ... %s %s: a module migration may only grant to / revoke from its own runtime role %q", verb, strings.ToUpper(roleKw), r, want)
				}
			}
			break
		}
	}
}

// nameList parses a `name[, name...]` list of bare identifiers at i.
func (s *sqlScan) nameList(ts []token, i int) []string {
	var out []string
	for i < len(ts) && ts[i].kind == tIdent {
		out = append(out, ts[i].text)
		if i+1 < len(ts) && ts[i+1].kind == tPunct && ts[i+1].text == "," {
			i += 2
			continue
		}
		break
	}
	return out
}

func (s *sqlScan) comment(ts []token) {
	kind := kw(ts, 2)
	if kw(ts, 1) != "on" || !commentKinds[kind] {
		s.fail(RuleMigrationUnsafeStatement, "COMMENT ON %s is not allowed in a module migration", strings.ToUpper(describe(ts[2:])))
		return
	}
	i := 3
	if kind == "trigger" || kind == "policy" || kind == "constraint" {
		for j := i; j < len(ts); j++ {
			if kw(ts, j) == "on" {
				i = j + 1
				break
			}
		}
	}
	for _, r := range s.targetList(ts, i) {
		s.checkRef(r, true)
	}
}

// forbidAnywhere refuses clauses that change who a definition runs as or what it resolves.
func (s *sqlScan) forbidAnywhere(ts []token) {
	for j := range ts {
		switch {
		case kw(ts, j) == "security" && kw(ts, j+1) == "definer":
			s.fail(RuleMigrationUnsafeStatement, "SECURITY DEFINER is not allowed in a module migration")
		case kw(ts, j) == "search_path":
			s.fail(RuleMigrationUnsafeStatement, "search_path may not be set by a module migration")
		}
	}
}

// describe renders the first few tokens of a statement for an error message.
func describe(ts []token) string {
	var parts []string
	for i := 0; i < len(ts) && i < 3; i++ {
		parts = append(parts, ts[i].text)
	}
	return strings.Join(parts, " ")
}

func sortedKeys(m map[string]bool) []string { return slices.Sorted(maps.Keys(m)) }

func sortedValues(m map[string]string) []string { return slices.Sorted(maps.Values(m)) }
