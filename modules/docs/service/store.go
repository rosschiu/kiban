// SPDX-License-Identifier: Apache-2.0

// Store is the docs service's data access layer: a pgx pool (connected as kiban_docs, the module's own DB role)
// plus the audit writer for "audit.docs__events". Hand-written SQL against docs's own schema
// only — no sqlc codegen, same accepted v1 pattern notification's/timesheet's own Store use.
//
// AUTHORIZATION NEVER LIVES HERE (the index is NEVER authoritative). Every method in
// this file is a plain read/write of docs's own tables; the caller (http.go) is responsible for
// asking AuthzClient first and for calling the authz grants API BEFORE the corresponding Store
// write, mirroring timesheet's own store_approvers.go convention exactly (authorize, THEN
// persist the local read-side index row — never the reverse, so a failed grant never leaves a
// local row implying access that was never actually granted).
package docs

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/rosschiu/kiban/internal/audit"
	"github.com/rosschiu/kiban/modulekit"
)

// ErrIdempotencyConflict means the same Idempotency-Key was reused with a DIFFERENT payload
// (same idempotency_key_hash approach as notification's) — reject instead of silently replaying the first request's result.
var ErrIdempotencyConflict = errors.New("docs: idempotency key reused with a different payload")

// documentIdempotencyPayloadHash is the canonical payload docs.document's idempotency key binds
// to: companyID + ownerKcSub + title + body, NUL-separated and sha256-hashed — same shape as
// notification's idempotencyPayloadHash.
func documentIdempotencyPayloadHash(companyID uuid.UUID, ownerKcSub, title, body string) string {
	h := sha256.New()
	h.Write(companyID[:])
	h.Write([]byte{0})
	h.Write([]byte(ownerKcSub))
	h.Write([]byte{0})
	h.Write([]byte(title))
	h.Write([]byte{0})
	h.Write([]byte(body))
	return hex.EncodeToString(h.Sum(nil))
}

// shareIdempotencyPayloadHash is the canonical payload docs.share's idempotency key binds to:
// docID + memberID + relation, NUL-separated and sha256-hashed.
func shareIdempotencyPayloadHash(docID, memberID uuid.UUID, relation string) string {
	h := sha256.New()
	h.Write(docID[:])
	h.Write([]byte{0})
	h.Write(memberID[:])
	h.Write([]byte{0})
	h.Write([]byte(relation))
	return hex.EncodeToString(h.Sum(nil))
}

type Store struct {
	pool  *pgxpool.Pool
	audit *audit.Writer
}

func NewStore(pool *pgxpool.Pool, auditWriter *audit.Writer) *Store {
	return &Store{pool: pool, audit: auditWriter}
}

func (s *Store) Pool() *pgxpool.Pool { return s.pool }

// CheckMigrationsApplied verifies migrations have been run — it never runs them itself
// (ARCH-004: no runtime DDL, ever).
func CheckMigrationsApplied(ctx context.Context, pool *pgxpool.Pool) error {
	var version int64
	err := pool.QueryRow(ctx, `SELECT version FROM public.schema_version_docs`).Scan(&version)
	if err != nil {
		return fmt.Errorf("docs: migrations not applied (run `make migrate-docs` against this database first): %w", err)
	}
	if version <= 0 {
		return errors.New("docs: migrations table present but at version 0 — run `make migrate-docs`")
	}
	return nil
}

// ---- shared helpers -------------------------------------------------------------------------

type ValidationError struct {
	Field   string
	Message string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("docs: validation: field %s: %s", e.Field, e.Message)
}

var (
	ErrDocumentNotFound = errors.New("docs: document not found")
	ErrShareNotFound    = errors.New("docs: share not found")
)

func pgFromUUID(id uuid.UUID) pgtype.UUID {
	return pgtype.UUID{Bytes: id, Valid: true}
}

func uuidFromPg(v pgtype.UUID) uuid.UUID {
	return uuid.UUID(v.Bytes)
}

// ---- documents -------------------------------------------------------------------------------

type Document struct {
	ID         uuid.UUID
	CompanyID  uuid.UUID
	Title      string
	Body       string
	OwnerKcSub string
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

func validTitle(title string) error {
	if len(title) < 1 || len(title) > 200 {
		return &ValidationError{Field: "title", Message: "must be 1..200 characters"}
	}
	return nil
}

// FindDocumentByIdempotencyKey looks up a previously created document by (companyID,
// ownerKcSub, idempotencyKey) — the handler calls this BEFORE granting the owner authz tuple,
// so a replayed create-document request never issues a second (orphaned) grant. Returns the
// stored payload hash (empty string for a row stored without a hash) alongside the document so the caller
// can distinguish a genuine replay from a payload conflict.
func (s *Store) FindDocumentByIdempotencyKey(ctx context.Context, companyID uuid.UUID, ownerKcSub, idempotencyKey string) (Document, string, bool, error) {
	var d Document
	var pgID, pgCompanyID pgtype.UUID
	var hash *string
	err := s.pool.QueryRow(ctx, `
		SELECT id, company_id, title, body, owner_kcsub, created_at, updated_at, idempotency_key_hash
		FROM docs.document WHERE company_id = $1 AND owner_kcsub = $2 AND idempotency_key = $3`,
		pgFromUUID(companyID), ownerKcSub, idempotencyKey,
	).Scan(&pgID, &pgCompanyID, &d.Title, &d.Body, &d.OwnerKcSub, &d.CreatedAt, &d.UpdatedAt, &hash)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Document{}, "", false, nil
		}
		return Document{}, "", false, fmt.Errorf("docs: find document by idempotency key: %w", err)
	}
	d.ID, d.CompanyID = uuidFromPg(pgID), uuidFromPg(pgCompanyID)
	hashStr := ""
	if hash != nil {
		hashStr = *hash
	}
	return d, hashStr, true, nil
}

// CreateDocument persists a new document row at the given docID — the caller (handler) MUST
// already have generated docID and successfully granted `docs_document:<docID>#owner @
// user:<creatorKcSub>` (plus the company_module pointer tuple) through AuthzClient
// .GrantDocumentOwner BEFORE calling this, so a document row never exists without its owner
// tuple already in place. idempotencyKey (may be "") is persisted alongside its payload hash for
// future replay detection via FindDocumentByIdempotencyKey — this method itself does not
// replay/conflict-check (the handler already did, via FindDocumentByIdempotencyKey, before
// generating docID and granting the owner tuple).
func (s *Store) CreateDocument(ctx context.Context, docID uuid.UUID, actor string, companyID uuid.UUID, title, body, idempotencyKey string) (Document, error) {
	if err := validTitle(title); err != nil {
		return Document{}, err
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Document{}, fmt.Errorf("docs: begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	var idemKey, idemHash *string
	if idempotencyKey != "" {
		idemKey = &idempotencyKey
		h := documentIdempotencyPayloadHash(companyID, actor, title, body)
		idemHash = &h
	}

	var d Document
	var pgID, pgCompanyID pgtype.UUID
	err = tx.QueryRow(ctx, `
		INSERT INTO docs.document (id, company_id, title, body, owner_kcsub, idempotency_key, idempotency_key_hash)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id, company_id, title, body, owner_kcsub, created_at, updated_at`,
		pgFromUUID(docID), pgFromUUID(companyID), title, body, actor, idemKey, idemHash,
	).Scan(&pgID, &pgCompanyID, &d.Title, &d.Body, &d.OwnerKcSub, &d.CreatedAt, &d.UpdatedAt)
	if err != nil {
		if modulekit.IsUniqueViolation(err) {
			return Document{}, ErrIdempotencyConflict
		}
		return Document{}, fmt.Errorf("docs: create document: %w", err)
	}
	d.ID, d.CompanyID = uuidFromPg(pgID), uuidFromPg(pgCompanyID)

	if err := s.audit.Record(ctx, tx, audit.Event{
		Actor: actor, Action: "docs.document.create", Subject: "docs_document:" + d.ID.String(),
		Payload: map[string]any{"companyId": companyID.String(), "title": title},
	}); err != nil {
		return Document{}, fmt.Errorf("docs: audit document create: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return Document{}, fmt.Errorf("docs: commit: %w", err)
	}
	return d, nil
}

func (s *Store) GetDocument(ctx context.Context, companyID, docID uuid.UUID) (Document, error) {
	var d Document
	var pgID, pgCompanyID pgtype.UUID
	err := s.pool.QueryRow(ctx, `
		SELECT id, company_id, title, body, owner_kcsub, created_at, updated_at
		FROM docs.document WHERE company_id = $1 AND id = $2`,
		pgFromUUID(companyID), pgFromUUID(docID),
	).Scan(&pgID, &pgCompanyID, &d.Title, &d.Body, &d.OwnerKcSub, &d.CreatedAt, &d.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Document{}, ErrDocumentNotFound
	}
	if err != nil {
		return Document{}, fmt.Errorf("docs: get document: %w", err)
	}
	d.ID, d.CompanyID = uuidFromPg(pgID), uuidFromPg(pgCompanyID)
	return d, nil
}

func (s *Store) UpdateDocument(ctx context.Context, actor string, companyID, docID uuid.UUID, title, body string) (Document, error) {
	if err := validTitle(title); err != nil {
		return Document{}, err
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Document{}, fmt.Errorf("docs: begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	var d Document
	var pgID, pgCompanyID pgtype.UUID
	err = tx.QueryRow(ctx, `
		UPDATE docs.document SET title = $3, body = $4, updated_at = now()
		WHERE company_id = $1 AND id = $2
		RETURNING id, company_id, title, body, owner_kcsub, created_at, updated_at`,
		pgFromUUID(companyID), pgFromUUID(docID), title, body,
	).Scan(&pgID, &pgCompanyID, &d.Title, &d.Body, &d.OwnerKcSub, &d.CreatedAt, &d.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Document{}, ErrDocumentNotFound
	}
	if err != nil {
		return Document{}, fmt.Errorf("docs: update document: %w", err)
	}
	d.ID, d.CompanyID = uuidFromPg(pgID), uuidFromPg(pgCompanyID)

	if err := s.audit.Record(ctx, tx, audit.Event{
		Actor: actor, Action: "docs.document.update", Subject: "docs_document:" + d.ID.String(),
		Payload: map[string]any{"companyId": companyID.String(), "title": title},
	}); err != nil {
		return Document{}, fmt.Errorf("docs: audit document update: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return Document{}, fmt.Errorf("docs: commit: %w", err)
	}
	return d, nil
}

func (s *Store) DeleteDocument(ctx context.Context, actor string, companyID, docID uuid.UUID) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("docs: begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	tag, err := tx.Exec(ctx, `DELETE FROM docs.document WHERE company_id = $1 AND id = $2`, pgFromUUID(companyID), pgFromUUID(docID))
	if err != nil {
		return fmt.Errorf("docs: delete document: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrDocumentNotFound
	}

	if err := s.audit.Record(ctx, tx, audit.Event{
		Actor: actor, Action: "docs.document.delete", Subject: "docs_document:" + docID.String(),
		Payload: map[string]any{"companyId": companyID.String()},
	}); err != nil {
		return fmt.Errorf("docs: audit document delete: %w", err)
	}
	return tx.Commit(ctx)
}

// ListOwnedDocuments returns every document companyID/ownerKcSub created — never verified via
// authz (the owner tuple was granted atomically at create time; nothing revokes an owner's own
// relation in this module), matching the "owned" half of GET /documents.
func (s *Store) ListOwnedDocuments(ctx context.Context, companyID uuid.UUID, ownerKcSub string) ([]Document, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, company_id, title, body, owner_kcsub, created_at, updated_at
		FROM docs.document WHERE company_id = $1 AND owner_kcsub = $2 ORDER BY created_at DESC`,
		pgFromUUID(companyID), ownerKcSub,
	)
	if err != nil {
		return nil, fmt.Errorf("docs: list owned documents: %w", err)
	}
	defer rows.Close()
	return scanDocuments(rows)
}

// SharedDocumentIDsForMember returns the document ids docs.share currently lists as shared with
// memberID, in ANY relation — the CANDIDATE list for the "shared with me" half of GET
// /documents. Never authoritative on its own: the caller MUST batch-verify each id via
// AuthzClient.BatchCanObject before returning it (belt and braces: the engine is the
// source of truth).
func (s *Store) SharedDocumentIDsForMember(ctx context.Context, companyID, memberID uuid.UUID) ([]uuid.UUID, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT sh.document_id FROM docs.share sh
		JOIN docs.document d ON d.id = sh.document_id
		WHERE d.company_id = $1 AND sh.member_id = $2`,
		pgFromUUID(companyID), pgFromUUID(memberID),
	)
	if err != nil {
		return nil, fmt.Errorf("docs: list shared document ids: %w", err)
	}
	defer rows.Close()
	var out []uuid.UUID
	for rows.Next() {
		var pgID pgtype.UUID
		if err := rows.Scan(&pgID); err != nil {
			return nil, fmt.Errorf("docs: scan shared document id: %w", err)
		}
		out = append(out, uuidFromPg(pgID))
	}
	return out, rows.Err()
}

func (s *Store) GetDocumentsByIDs(ctx context.Context, companyID uuid.UUID, docIDs []uuid.UUID) ([]Document, error) {
	if len(docIDs) == 0 {
		return nil, nil
	}
	rows, err := s.pool.Query(ctx, `
		SELECT id, company_id, title, body, owner_kcsub, created_at, updated_at
		FROM docs.document WHERE company_id = $1 AND id = ANY($2) ORDER BY created_at DESC`,
		pgFromUUID(companyID), docIDsToPg(docIDs),
	)
	if err != nil {
		return nil, fmt.Errorf("docs: get documents by ids: %w", err)
	}
	defer rows.Close()
	return scanDocuments(rows)
}

func docIDsToPg(ids []uuid.UUID) []pgtype.UUID {
	out := make([]pgtype.UUID, len(ids))
	for i, id := range ids {
		out[i] = pgFromUUID(id)
	}
	return out
}

func scanDocuments(rows pgx.Rows) ([]Document, error) {
	var out []Document
	for rows.Next() {
		var d Document
		var pgID, pgCompanyID pgtype.UUID
		if err := rows.Scan(&pgID, &pgCompanyID, &d.Title, &d.Body, &d.OwnerKcSub, &d.CreatedAt, &d.UpdatedAt); err != nil {
			return nil, fmt.Errorf("docs: scan document: %w", err)
		}
		d.ID, d.CompanyID = uuidFromPg(pgID), uuidFromPg(pgCompanyID)
		out = append(out, d)
	}
	return out, rows.Err()
}

// ---- shares (read-side index only — see file header) -----------------------------------------

type Share struct {
	ID         uuid.UUID
	DocumentID uuid.UUID
	MemberID   uuid.UUID
	Relation   string
	GrantedBy  string
	CreatedAt  time.Time
}

// FindShareByIdempotencyKey looks up a previously recorded share by (docID, idempotencyKey) —
// the handler calls this BEFORE granting the authz relation tuple, so a replayed create-share
// request never issues a second (orphaned) grant. Returns the stored payload hash (empty string
// for a share recorded before this key existed) alongside the share.
func (s *Store) FindShareByIdempotencyKey(ctx context.Context, docID uuid.UUID, idempotencyKey string) (Share, string, bool, error) {
	var sh Share
	var pgID, pgDocID, pgMemberID pgtype.UUID
	var hash *string
	err := s.pool.QueryRow(ctx, `
		SELECT id, document_id, member_id, relation, granted_by, created_at, idempotency_key_hash
		FROM docs.share WHERE document_id = $1 AND idempotency_key = $2`,
		pgFromUUID(docID), idempotencyKey,
	).Scan(&pgID, &pgDocID, &pgMemberID, &sh.Relation, &sh.GrantedBy, &sh.CreatedAt, &hash)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Share{}, "", false, nil
		}
		return Share{}, "", false, fmt.Errorf("docs: find share by idempotency key: %w", err)
	}
	sh.ID, sh.DocumentID, sh.MemberID = uuidFromPg(pgID), uuidFromPg(pgDocID), uuidFromPg(pgMemberID)
	hashStr := ""
	if hash != nil {
		hashStr = *hash
	}
	return sh, hashStr, true, nil
}

// RecordShare upserts the local index row. Caller MUST have already granted
// `docs_document:<docID>#relation @ user:<targetKcSub>` through AuthzClient.GrantShare before
// calling this (store_approvers.go's own established ordering). idempotencyKey (may be "") is
// persisted alongside its payload hash for future replay detection via
// FindShareByIdempotencyKey — this method itself does not replay/conflict-check (the handler
// already did, before granting the relation tuple). NOTE: docs.share's own
// UNIQUE(document_id, member_id) upsert-in-place semantics are UNCHANGED by this — a second
// share of the SAME member always still updates that one row regardless of idempotency key; the
// key only gates whether the FIRST call for a given key is treated as a fresh grant or a replay.
func (s *Store) RecordShare(ctx context.Context, actor string, companyID, docID, memberID uuid.UUID, relation, grantedByKcSub, idempotencyKey string) (Share, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Share{}, fmt.Errorf("docs: begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	var idemKey, idemHash *string
	if idempotencyKey != "" {
		idemKey = &idempotencyKey
		h := shareIdempotencyPayloadHash(docID, memberID, relation)
		idemHash = &h
	}

	var sh Share
	var pgID, pgDocID, pgMemberID pgtype.UUID
	err = tx.QueryRow(ctx, `
		INSERT INTO docs.share (document_id, member_id, relation, granted_by, idempotency_key, idempotency_key_hash)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (document_id, member_id) DO UPDATE SET
			relation = EXCLUDED.relation, granted_by = EXCLUDED.granted_by, created_at = now(),
			idempotency_key = EXCLUDED.idempotency_key, idempotency_key_hash = EXCLUDED.idempotency_key_hash
		RETURNING id, document_id, member_id, relation, granted_by, created_at`,
		pgFromUUID(docID), pgFromUUID(memberID), relation, grantedByKcSub, idemKey, idemHash,
	).Scan(&pgID, &pgDocID, &pgMemberID, &sh.Relation, &sh.GrantedBy, &sh.CreatedAt)
	if err != nil {
		return Share{}, fmt.Errorf("docs: record share: %w", err)
	}
	sh.ID, sh.DocumentID, sh.MemberID = uuidFromPg(pgID), uuidFromPg(pgDocID), uuidFromPg(pgMemberID)

	if err := s.audit.Record(ctx, tx, audit.Event{
		Actor: actor, Action: "docs.share.grant", Subject: "docs_document:" + docID.String(),
		Payload: map[string]any{"companyId": companyID.String(), "memberId": memberID.String(), "relation": relation},
	}); err != nil {
		return Share{}, fmt.Errorf("docs: audit share grant: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return Share{}, fmt.Errorf("docs: commit: %w", err)
	}
	return sh, nil
}

// RemoveShare deletes the local index row. Caller MUST have already revoked the corresponding
// authz tuple via AuthzClient.RevokeShare before calling this.
func (s *Store) RemoveShare(ctx context.Context, actor string, companyID, docID, memberID uuid.UUID) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("docs: begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	tag, err := tx.Exec(ctx, `DELETE FROM docs.share WHERE document_id = $1 AND member_id = $2`, pgFromUUID(docID), pgFromUUID(memberID))
	if err != nil {
		return fmt.Errorf("docs: remove share: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrShareNotFound
	}

	if err := s.audit.Record(ctx, tx, audit.Event{
		Actor: actor, Action: "docs.share.revoke", Subject: "docs_document:" + docID.String(),
		Payload: map[string]any{"companyId": companyID.String(), "memberId": memberID.String()},
	}); err != nil {
		return fmt.Errorf("docs: audit share revoke: %w", err)
	}
	return tx.Commit(ctx)
}

func (s *Store) ListShares(ctx context.Context, docID uuid.UUID) ([]Share, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, document_id, member_id, relation, granted_by, created_at
		FROM docs.share WHERE document_id = $1 ORDER BY created_at ASC`,
		pgFromUUID(docID),
	)
	if err != nil {
		return nil, fmt.Errorf("docs: list shares: %w", err)
	}
	defer rows.Close()
	var out []Share
	for rows.Next() {
		var sh Share
		var pgID, pgDocID, pgMemberID pgtype.UUID
		if err := rows.Scan(&pgID, &pgDocID, &pgMemberID, &sh.Relation, &sh.GrantedBy, &sh.CreatedAt); err != nil {
			return nil, fmt.Errorf("docs: scan share: %w", err)
		}
		sh.ID, sh.DocumentID, sh.MemberID = uuidFromPg(pgID), uuidFromPg(pgDocID), uuidFromPg(pgMemberID)
		out = append(out, sh)
	}
	return out, rows.Err()
}

func (s *Store) GetShare(ctx context.Context, docID, memberID uuid.UUID) (Share, error) {
	var sh Share
	var pgID, pgDocID, pgMemberID pgtype.UUID
	err := s.pool.QueryRow(ctx, `
		SELECT id, document_id, member_id, relation, granted_by, created_at
		FROM docs.share WHERE document_id = $1 AND member_id = $2`,
		pgFromUUID(docID), pgFromUUID(memberID),
	).Scan(&pgID, &pgDocID, &pgMemberID, &sh.Relation, &sh.GrantedBy, &sh.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Share{}, ErrShareNotFound
	}
	if err != nil {
		return Share{}, fmt.Errorf("docs: get share: %w", err)
	}
	sh.ID, sh.DocumentID, sh.MemberID = uuidFromPg(pgID), uuidFromPg(pgDocID), uuidFromPg(pgMemberID)
	return sh, nil
}

// ---- audit (read-only; reads this module's own audit.docs__events table) ----------------------

type AuditEvent struct {
	OccurredAt time.Time
	Actor      string
	Action     string
	Subject    string
	Payload    map[string]any
}

// DocumentAudit returns every audit event whose subject is exactly this document (shares,
// revokes, edits, create) — the per-doc audit panel.
func (s *Store) DocumentAudit(ctx context.Context, docID uuid.UUID) ([]AuditEvent, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT occurred_at, actor, action, subject, payload
		FROM audit.docs__events WHERE subject = $1 ORDER BY occurred_at DESC LIMIT 200`,
		"docs_document:"+docID.String(),
	)
	if err != nil {
		return nil, fmt.Errorf("docs: document audit: %w", err)
	}
	defer rows.Close()
	return scanAuditEvents(rows)
}

// ModuleAudit returns a page of the company's docs__events rows (module-wide admin view —
// deliberately includes titles/actions but NEVER document body content, since this table is
// never written with body text). Every event carries its company in payload.companyId; rows
// without one belong to no company's view.
func (s *Store) ModuleAudit(ctx context.Context, companyID uuid.UUID, page, pageSize int) ([]AuditEvent, int, error) {
	page, pageSize = modulekit.ClampPage(page, pageSize)

	var total int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM audit.docs__events WHERE payload->>'companyId' = $1`, companyID.String()).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("docs: count module audit: %w", err)
	}

	rows, err := s.pool.Query(ctx, `
		SELECT occurred_at, actor, action, subject, payload
		FROM audit.docs__events WHERE payload->>'companyId' = $1
		ORDER BY occurred_at DESC LIMIT $2 OFFSET $3`,
		companyID.String(), pageSize, (page-1)*pageSize,
	)
	if err != nil {
		return nil, 0, fmt.Errorf("docs: module audit: %w", err)
	}
	defer rows.Close()
	events, err := scanAuditEvents(rows)
	return events, total, err
}

func scanAuditEvents(rows pgx.Rows) ([]AuditEvent, error) {
	var out []AuditEvent
	for rows.Next() {
		var e AuditEvent
		var payload []byte
		if err := rows.Scan(&e.OccurredAt, &e.Actor, &e.Action, &e.Subject, &payload); err != nil {
			return nil, fmt.Errorf("docs: scan audit event: %w", err)
		}
		if len(payload) > 0 {
			if err := json.Unmarshal(payload, &e.Payload); err != nil {
				return nil, fmt.Errorf("docs: decode audit payload: %w", err)
			}
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
