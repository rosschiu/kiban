// SPDX-License-Identifier: Apache-2.0

// Package notification implements the notification module service: channels,
// subscriptions, messages/inbox, and leased background delivery jobs, built solely
// against the platform's Go "SDK" packages (internal/errenv, internal/audit, internal/httpx,
// internal/obs, internal/config) plus HTTP calls to org's company-facts API — never by reaching
// into any foundation schema.
package notification

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/rosschiu/kiban/internal/audit"
	"github.com/rosschiu/kiban/modulekit"
)

// Store is the notification service's data access layer: a pgx pool (connected as
// kiban_notification) plus the audit writer for "audit.notification__events". No sqlc codegen:
// every query is hand-written SQL against notification's own schema only.
type Store struct {
	pool          *pgxpool.Pool
	audit         *audit.Writer
	claimGroup    string
	webhookPolicy *WebhookPolicy
}

// NewStore builds a Store bound to one claim_group and one webhook SSRF policy (the policy
// CreateChannel validates webhook targets against — cmd/main.go hands the same instance to the
// worker's WebhookSender so the create-time check and the delivery-time re-check agree; tests
// inject one with a custom Resolver). Claim group: every delivery_job
// this Store enqueues (SendMessage) and claims (ClaimJobs) is scoped to claimGroup, so a Store's
// worker only ever competes with other Stores/workers sharing its own group. Production always
// uses "default" (cmd/main.go's KIBAN_NOTIFICATION_CLAIM_GROUP, defaulted there); a module's own
// test suite uses a unique per-run group (dbtest_env_test.go) so it never races the live
// kiban-notification compose container's worker, which only ever polls "default".
func NewStore(pool *pgxpool.Pool, auditWriter *audit.Writer, claimGroup string, webhookPolicy *WebhookPolicy) *Store {
	if claimGroup == "" {
		claimGroup = "default"
	}
	return &Store{pool: pool, audit: auditWriter, claimGroup: claimGroup, webhookPolicy: webhookPolicy}
}

func (s *Store) Pool() *pgxpool.Pool { return s.pool }

// CheckMigrationsApplied verifies migrations have been run — it never runs them itself
// (ARCH-004: no runtime DDL, ever; migrations are applied out-of-band by `make migrate-
// notification`, as the kiban owner role) — same pattern as every other service's Store.
func CheckMigrationsApplied(ctx context.Context, pool *pgxpool.Pool) error {
	var version int64
	err := pool.QueryRow(ctx, `SELECT version FROM public.schema_version_notification`).Scan(&version)
	if err != nil {
		return fmt.Errorf(
			"notification: migrations not applied (run `make migrate-notification` against this database first): %w",
			err,
		)
	}
	if version <= 0 {
		return errors.New("notification: migrations table present but at version 0 — run `make migrate-notification`")
	}
	return nil
}

// ---- shared helpers -------------------------------------------------------------------------

type ValidationError struct {
	Field   string
	Message string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("notification: validation: field %s: %s", e.Field, e.Message)
}

var (
	ErrConflict          = errors.New("notification: conflict")
	ErrChannelNotFound   = errors.New("notification: channel not found")
	ErrMessageNotFound   = errors.New("notification: message not found")
	ErrRecipientNotFound = errors.New("notification: recipient state not found")
)

var channelKeyPattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{1,63}$`)

func validKind(kind string) bool {
	return kind == "in_app" || kind == "email" || kind == "webhook"
}

func pgFromUUID(id uuid.UUID) pgtype.UUID {
	return pgtype.UUID{Bytes: id, Valid: true}
}

func uuidFromPg(v pgtype.UUID) uuid.UUID {
	return uuid.UUID(v.Bytes)
}

// ---- channels ----------------------------------------------------------------------------

type Channel struct {
	ID        uuid.UUID
	CompanyID uuid.UUID
	Key       string
	Label     string
	Kind      string
	Target    *string
	CreatedAt time.Time
}

func (s *Store) CreateChannel(ctx context.Context, actor string, companyID uuid.UUID, key, label, kind string, target *string) (Channel, error) {
	if !channelKeyPattern.MatchString(key) {
		return Channel{}, &ValidationError{Field: "key", Message: "must match ^[a-z][a-z0-9_-]{1,63}$"}
	}
	if len(label) < 1 || len(label) > 120 {
		return Channel{}, &ValidationError{Field: "label", Message: "must be 1..120 characters"}
	}
	if !validKind(kind) {
		return Channel{Kind: kind}, &ValidationError{Field: "kind", Message: "must be one of in_app, email, webhook"}
	}
	if kind == "webhook" {
		if target == nil || *target == "" {
			return Channel{Kind: kind}, &ValidationError{Field: "target", Message: "required for kind=webhook"}
		}
		if _, err := s.webhookPolicy.Validate(ctx, *target); err != nil {
			return Channel{Kind: kind}, err
		}
	}

	var c Channel
	var pgID, pgCompanyID pgtype.UUID
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Channel{}, fmt.Errorf("notification: begin tx: %w", err)
	}
	defer tx.Rollback(ctx)

	err = tx.QueryRow(ctx, `
		INSERT INTO notification.channel (company_id, key, label, kind, target)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id, company_id, key, label, kind, target, created_at`,
		pgFromUUID(companyID), key, label, kind, target,
	).Scan(&pgID, &pgCompanyID, &c.Key, &c.Label, &c.Kind, &c.Target, &c.CreatedAt)
	if err != nil {
		if modulekit.IsUniqueViolation(err) {
			return Channel{}, ErrConflict
		}
		return Channel{}, fmt.Errorf("notification: create channel: %w", err)
	}
	c.ID, c.CompanyID = uuidFromPg(pgID), uuidFromPg(pgCompanyID)

	if err := s.audit.Record(ctx, tx, audit.Event{
		Actor: actor, Action: "notification.channel.create", Subject: "notification_channel:" + c.ID.String(),
		Payload: map[string]any{"companyId": companyID.String(), "key": key, "kind": kind},
	}); err != nil {
		return Channel{}, fmt.Errorf("notification: audit channel create: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return Channel{}, fmt.Errorf("notification: commit: %w", err)
	}
	return c, nil
}

func (s *Store) ListChannels(ctx context.Context, companyID uuid.UUID, page, pageSize int) ([]Channel, int, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = 25
	}
	if pageSize > 100 {
		pageSize = 100
	}

	var total int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM notification.channel WHERE company_id = $1`, pgFromUUID(companyID)).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("notification: count channels: %w", err)
	}

	rows, err := s.pool.Query(ctx, `
		SELECT id, company_id, key, label, kind, target, created_at
		FROM notification.channel WHERE company_id = $1
		ORDER BY created_at ASC LIMIT $2 OFFSET $3`,
		pgFromUUID(companyID), pageSize, (page-1)*pageSize,
	)
	if err != nil {
		return nil, 0, fmt.Errorf("notification: list channels: %w", err)
	}
	defer rows.Close()

	var out []Channel
	for rows.Next() {
		var c Channel
		var pgID, pgCompanyID pgtype.UUID
		if err := rows.Scan(&pgID, &pgCompanyID, &c.Key, &c.Label, &c.Kind, &c.Target, &c.CreatedAt); err != nil {
			return nil, 0, fmt.Errorf("notification: scan channel: %w", err)
		}
		c.ID, c.CompanyID = uuidFromPg(pgID), uuidFromPg(pgCompanyID)
		out = append(out, c)
	}
	return out, total, rows.Err()
}

func (s *Store) GetChannel(ctx context.Context, companyID, channelID uuid.UUID) (Channel, error) {
	var c Channel
	var pgID, pgCompanyID pgtype.UUID
	err := s.pool.QueryRow(ctx, `
		SELECT id, company_id, key, label, kind, target, created_at
		FROM notification.channel WHERE company_id = $1 AND id = $2`,
		pgFromUUID(companyID), pgFromUUID(channelID),
	).Scan(&pgID, &pgCompanyID, &c.Key, &c.Label, &c.Kind, &c.Target, &c.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Channel{}, ErrChannelNotFound
	}
	if err != nil {
		return Channel{}, fmt.Errorf("notification: get channel: %w", err)
	}
	c.ID, c.CompanyID = uuidFromPg(pgID), uuidFromPg(pgCompanyID)
	return c, nil
}

func (s *Store) DeleteChannel(ctx context.Context, actor string, companyID, channelID uuid.UUID) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("notification: begin tx: %w", err)
	}
	defer tx.Rollback(ctx)

	tag, err := tx.Exec(ctx, `DELETE FROM notification.channel WHERE company_id = $1 AND id = $2`, pgFromUUID(companyID), pgFromUUID(channelID))
	if err != nil {
		return fmt.Errorf("notification: delete channel: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrChannelNotFound
	}
	if err := s.audit.Record(ctx, tx, audit.Event{
		Actor: actor, Action: "notification.channel.delete", Subject: "notification_channel:" + channelID.String(),
		Payload: map[string]any{"companyId": companyID.String()},
	}); err != nil {
		return fmt.Errorf("notification: audit channel delete: %w", err)
	}
	return tx.Commit(ctx)
}

// ---- subscriptions -------------------------------------------------------------------------

func (s *Store) Subscribe(ctx context.Context, actor string, companyID, channelID uuid.UUID, subject string, email *string) error {
	if _, err := s.GetChannel(ctx, companyID, channelID); err != nil {
		return err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("notification: begin tx: %w", err)
	}
	defer tx.Rollback(ctx)

	_, err = tx.Exec(ctx, `
		INSERT INTO notification.subscription (channel_id, subject, email, muted)
		VALUES ($1, $2, $3, false)
		ON CONFLICT (channel_id, subject) DO UPDATE SET email = EXCLUDED.email, muted = false`,
		pgFromUUID(channelID), subject, email,
	)
	if err != nil {
		return fmt.Errorf("notification: subscribe: %w", err)
	}
	if err := s.audit.Record(ctx, tx, audit.Event{
		Actor: actor, Action: "notification.subscription.create", Subject: "notification_channel:" + channelID.String(),
		Payload: map[string]any{"companyId": companyID.String()},
	}); err != nil {
		return fmt.Errorf("notification: audit subscribe: %w", err)
	}
	return tx.Commit(ctx)
}

func (s *Store) Unsubscribe(ctx context.Context, actor string, companyID, channelID uuid.UUID, subject string) error {
	if _, err := s.GetChannel(ctx, companyID, channelID); err != nil {
		return err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("notification: begin tx: %w", err)
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx, `DELETE FROM notification.subscription WHERE channel_id = $1 AND subject = $2`, pgFromUUID(channelID), subject); err != nil {
		return fmt.Errorf("notification: unsubscribe: %w", err)
	}
	if err := s.audit.Record(ctx, tx, audit.Event{
		Actor: actor, Action: "notification.subscription.delete", Subject: "notification_channel:" + channelID.String(),
		Payload: map[string]any{"companyId": companyID.String()},
	}); err != nil {
		return fmt.Errorf("notification: audit unsubscribe: %w", err)
	}
	return tx.Commit(ctx)
}

// ---- messages / send -----------------------------------------------------------------------

type Message struct {
	ID          uuid.UUID
	CompanyID   uuid.UUID
	ChannelID   uuid.UUID
	SubjectLine string
	Body        string
	CreatedBy   string
	CreatedAt   time.Time
	ReadAt      *time.Time
}

// ErrIdempotencyConflict: idempotency keys are payload-bound (409 on conflicting reuse) — the same
// Idempotency-Key was reused on this channel with a DIFFERENT subjectLine/body, so reject instead
// of silently replaying the first request's message, which would mask exactly this class of client
// bug.
var ErrIdempotencyConflict = errors.New("notification: idempotency key reused with a different payload")

// idempotencyPayloadHash is the canonical payload the idempotency key binds to: channelID +
// subjectLine + body, NUL-separated (a byte no valid subjectLine/body can otherwise inject to
// forge a collision between e.g. subjectLine="a\x00b", body="c" and subjectLine="a", body="b\x00c")
// and sha256-hashed. channelID is included so the same key+content pair sent to two different
// channels is never treated as the same logical request.
func idempotencyPayloadHash(channelID uuid.UUID, subjectLine, body string) string {
	h := sha256.New()
	h.Write(channelID[:])
	h.Write([]byte{0})
	h.Write([]byte(subjectLine))
	h.Write([]byte{0})
	h.Write([]byte(body))
	return hex.EncodeToString(h.Sum(nil))
}

// SendMessage is the module's core write path: creates the message,
// fans it out to every non-muted subscriber's inbox (recipient_state), and enqueues delivery_job
// rows for the channel's out-of-band delivery kind (email: one job per subscriber with an email
// on file; webhook: one job at the channel's target). All in one transaction, all audited
// (state change + its audit event never split across transactions).
// Idempotency-Key (idempotencyKey, may be "") replays the SAME message + created=false when a
// prior send with the identical key AND identical payload already landed on this channel; the
// identical key with a DIFFERENT payload is ErrIdempotencyConflict (409), never a silent replay
// or a silent second send.
// validateSubjectLineAndBody is the shared boundary check both SendMessage and
// SendTargetedEvent apply to a message's subjectLine/body — factored out so the targeted-events
// path reuses the EXACT same rule rather than a second, possibly-drifting copy.
func validateSubjectLineAndBody(subjectLine, body string) error {
	if len(subjectLine) < 1 || len(subjectLine) > 200 {
		return &ValidationError{Field: "subjectLine", Message: "must be 1..200 characters"}
	}
	// subjectLine is the ONLY place a subject enters the system —
	// buildMessage (mailer.go) concatenates it directly into RFC 5322 headers with no sanitizer
	// of its own (by design), so a subject containing CR/LF (or any
	// other control character) can terminate the header block early and inject arbitrary
	// headers, including displacing the Message-Id header into the body. Reject the whole
	// CTL class (< 0x20, or 0x7f) here — there is no legitimate control character in a subject.
	for _, r := range subjectLine {
		if r < 0x20 || r == 0x7f {
			return &ValidationError{Field: "subjectLine", Message: "must not contain control characters"}
		}
	}
	if body == "" {
		return &ValidationError{Field: "body", Message: "must not be empty"}
	}
	return nil
}

func (s *Store) SendMessage(ctx context.Context, actor string, companyID, channelID uuid.UUID, subjectLine, body, idempotencyKey string) (Message, bool, error) {
	if err := validateSubjectLineAndBody(subjectLine, body); err != nil {
		return Message{}, false, err
	}

	channel, err := s.GetChannel(ctx, companyID, channelID)
	if err != nil {
		return Message{}, false, err
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Message{}, false, fmt.Errorf("notification: begin tx: %w", err)
	}
	defer tx.Rollback(ctx)

	var idemKey *string
	var payloadHash *string
	if idempotencyKey != "" {
		idemKey = &idempotencyKey
		hash := idempotencyPayloadHash(channelID, subjectLine, body)
		payloadHash = &hash
		if existing, existingHash, ok, err := findByIdempotencyKey(ctx, tx, channelID, idempotencyKey); err != nil {
			return Message{}, false, err
		} else if ok {
			if existingHash != hash {
				return Message{}, false, ErrIdempotencyConflict
			}
			if err := tx.Commit(ctx); err != nil {
				return Message{}, false, fmt.Errorf("notification: commit: %w", err)
			}
			return existing, false, nil
		}
	}

	var m Message
	var pgID, pgCompanyID, pgChannelID pgtype.UUID
	err = tx.QueryRow(ctx, `
		INSERT INTO notification.message (company_id, channel_id, subject_line, body, created_by, idempotency_key, idempotency_key_hash)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id, company_id, channel_id, subject_line, body, created_by, created_at`,
		pgFromUUID(companyID), pgFromUUID(channelID), subjectLine, body, actor, idemKey, payloadHash,
	).Scan(&pgID, &pgCompanyID, &pgChannelID, &m.SubjectLine, &m.Body, &m.CreatedBy, &m.CreatedAt)
	if err != nil {
		if modulekit.IsUniqueViolation(err) {
			return Message{}, false, ErrConflict
		}
		return Message{}, false, fmt.Errorf("notification: create message: %w", err)
	}
	m.ID, m.CompanyID, m.ChannelID = uuidFromPg(pgID), uuidFromPg(pgCompanyID), uuidFromPg(pgChannelID)

	rows, err := tx.Query(ctx, `SELECT subject, email FROM notification.subscription WHERE channel_id = $1 AND muted = false`, pgFromUUID(channelID))
	if err != nil {
		return Message{}, false, fmt.Errorf("notification: list subscribers: %w", err)
	}
	type subscriber struct {
		subject string
		email   *string
	}
	var subs []subscriber
	for rows.Next() {
		var sub subscriber
		if err := rows.Scan(&sub.subject, &sub.email); err != nil {
			rows.Close()
			return Message{}, false, fmt.Errorf("notification: scan subscriber: %w", err)
		}
		subs = append(subs, sub)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return Message{}, false, fmt.Errorf("notification: iterate subscribers: %w", err)
	}

	for _, sub := range subs {
		if _, err := tx.Exec(ctx, `INSERT INTO notification.recipient_state (message_id, subject) VALUES ($1, $2)`, pgFromUUID(m.ID), sub.subject); err != nil {
			return Message{}, false, fmt.Errorf("notification: create recipient state: %w", err)
		}
		if channel.Kind == "email" && sub.email != nil && *sub.email != "" {
			if _, err := tx.Exec(ctx, `
				INSERT INTO notification.delivery_job (message_id, kind, target, claim_group) VALUES ($1, 'email', $2, $3)`,
				pgFromUUID(m.ID), *sub.email, s.claimGroup,
			); err != nil {
				return Message{}, false, fmt.Errorf("notification: enqueue email delivery job: %w", err)
			}
		}
	}
	if channel.Kind == "webhook" && channel.Target != nil && *channel.Target != "" {
		if _, err := tx.Exec(ctx, `
			INSERT INTO notification.delivery_job (message_id, kind, target, claim_group) VALUES ($1, 'webhook', $2, $3)`,
			pgFromUUID(m.ID), *channel.Target, s.claimGroup,
		); err != nil {
			return Message{}, false, fmt.Errorf("notification: enqueue webhook delivery job: %w", err)
		}
	}

	if err := s.audit.Record(ctx, tx, audit.Event{
		Actor: actor, Action: "notification.message.send", Subject: "notification_channel:" + channelID.String(),
		Payload: map[string]any{"companyId": companyID.String(), "messageId": m.ID.String(), "recipients": len(subs)},
	}); err != nil {
		return Message{}, false, fmt.Errorf("notification: audit send: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return Message{}, false, fmt.Errorf("notification: commit: %w", err)
	}
	return m, true, nil
}

// findByIdempotencyKey also returns the stored payload hash (empty string for a legacy row that
// predates the column, which SendMessage's caller then treats as a mismatch — see its "existingHash
// != hash" check — rather than ever assuming payload equality it never actually verified).
func findByIdempotencyKey(ctx context.Context, tx pgx.Tx, channelID uuid.UUID, key string) (Message, string, bool, error) {
	var m Message
	var pgID, pgCompanyID, pgChannelID pgtype.UUID
	var hash *string
	err := tx.QueryRow(ctx, `
		SELECT id, company_id, channel_id, subject_line, body, created_by, created_at, idempotency_key_hash
		FROM notification.message WHERE channel_id = $1 AND idempotency_key = $2`,
		pgFromUUID(channelID), key,
	).Scan(&pgID, &pgCompanyID, &pgChannelID, &m.SubjectLine, &m.Body, &m.CreatedBy, &m.CreatedAt, &hash)
	if errors.Is(err, pgx.ErrNoRows) {
		return Message{}, "", false, nil
	}
	if err != nil {
		return Message{}, "", false, fmt.Errorf("notification: idempotency lookup: %w", err)
	}
	m.ID, m.CompanyID, m.ChannelID = uuidFromPg(pgID), uuidFromPg(pgCompanyID), uuidFromPg(pgChannelID)
	storedHash := ""
	if hash != nil {
		storedHash = *hash
	}
	return m, storedHash, true, nil
}

// ListInbox returns the caller's own messages (recipient_state.subject = subject), newest
// first — v1 is poll-only (Out of scope: "in-app real-time").
func (s *Store) ListInbox(ctx context.Context, companyID uuid.UUID, subject string, page, pageSize int) ([]Message, int, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = 25
	}
	if pageSize > 100 {
		pageSize = 100
	}

	var total int
	if err := s.pool.QueryRow(ctx, `
		SELECT count(*) FROM notification.recipient_state rs
		JOIN notification.message m ON m.id = rs.message_id
		WHERE rs.subject = $1 AND m.company_id = $2`,
		subject, pgFromUUID(companyID),
	).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("notification: count inbox: %w", err)
	}

	rows, err := s.pool.Query(ctx, `
		SELECT m.id, m.company_id, m.channel_id, m.subject_line, m.body, m.created_by, m.created_at, rs.read_at
		FROM notification.recipient_state rs
		JOIN notification.message m ON m.id = rs.message_id
		WHERE rs.subject = $1 AND m.company_id = $2
		ORDER BY m.created_at DESC LIMIT $3 OFFSET $4`,
		subject, pgFromUUID(companyID), pageSize, (page-1)*pageSize,
	)
	if err != nil {
		return nil, 0, fmt.Errorf("notification: list inbox: %w", err)
	}
	defer rows.Close()

	var out []Message
	for rows.Next() {
		var m Message
		var pgID, pgCompanyID, pgChannelID pgtype.UUID
		if err := rows.Scan(&pgID, &pgCompanyID, &pgChannelID, &m.SubjectLine, &m.Body, &m.CreatedBy, &m.CreatedAt, &m.ReadAt); err != nil {
			return nil, 0, fmt.Errorf("notification: scan inbox message: %w", err)
		}
		m.ID, m.CompanyID, m.ChannelID = uuidFromPg(pgID), uuidFromPg(pgCompanyID), uuidFromPg(pgChannelID)
		out = append(out, m)
	}
	return out, total, rows.Err()
}

// MarkRead sets recipient_state.read_at=now() for (messageId, subject) — the caller may only
// ever mark THEIR OWN recipient row read (subject is always the validated bearer, never a
// request field), scoped to companyID so a message from another company 404s instead of leaking
// existence.
func (s *Store) MarkRead(ctx context.Context, actor string, companyID, messageID uuid.UUID, subject string) (Message, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Message{}, fmt.Errorf("notification: begin tx: %w", err)
	}
	defer tx.Rollback(ctx)

	tag, err := tx.Exec(ctx, `
		UPDATE notification.recipient_state rs SET read_at = now()
		FROM notification.message m
		WHERE rs.message_id = m.id AND rs.message_id = $1 AND rs.subject = $2 AND m.company_id = $3 AND rs.read_at IS NULL`,
		pgFromUUID(messageID), subject, pgFromUUID(companyID),
	)
	if err != nil {
		return Message{}, fmt.Errorf("notification: mark read: %w", err)
	}
	if tag.RowsAffected() == 0 {
		// Either no such recipient row, or already read — distinguish so "already read" isn't a
		// 404 (idempotent mark-read, Design: poll-only inbox, clients retry marks freely).
		exists, err := recipientExists(ctx, tx, messageID, subject, companyID)
		if err != nil {
			return Message{}, err
		}
		if !exists {
			return Message{}, ErrRecipientNotFound
		}
	}

	if err := s.audit.Record(ctx, tx, audit.Event{
		Actor: actor, Action: "notification.message.read", Subject: "notification_message:" + messageID.String(),
		Payload: map[string]any{"companyId": companyID.String()},
	}); err != nil {
		return Message{}, fmt.Errorf("notification: audit mark read: %w", err)
	}

	var m Message
	var pgID, pgCompanyID, pgChannelID pgtype.UUID
	err = tx.QueryRow(ctx, `
		SELECT m.id, m.company_id, m.channel_id, m.subject_line, m.body, m.created_by, m.created_at, rs.read_at
		FROM notification.recipient_state rs
		JOIN notification.message m ON m.id = rs.message_id
		WHERE rs.message_id = $1 AND rs.subject = $2`,
		pgFromUUID(messageID), subject,
	).Scan(&pgID, &pgCompanyID, &pgChannelID, &m.SubjectLine, &m.Body, &m.CreatedBy, &m.CreatedAt, &m.ReadAt)
	if err != nil {
		return Message{}, fmt.Errorf("notification: reload message: %w", err)
	}
	m.ID, m.CompanyID, m.ChannelID = uuidFromPg(pgID), uuidFromPg(pgCompanyID), uuidFromPg(pgChannelID)

	if err := tx.Commit(ctx); err != nil {
		return Message{}, fmt.Errorf("notification: commit: %w", err)
	}
	return m, nil
}

// ---- targeted events ------------------------------------------------------------------------

// MembershipChecker is the seam SendTargetedEvent uses to confirm each recipient kcSub is an
// ACTIVE member of companyID before a recipient_state row is ever written for them — satisfied
// by OrgClient in production (orgclient.go), faked in tests. A non-nil error is treated
// IDENTICALLY to "not a member": the recipient is skipped, never delivered to on an unconfirmed
// membership (fail-closed — recipients that are not members are skipped, not errors, and that
// extends to "recipients we couldn't confirm," which is not the same as "confirmed
// member").
type MembershipChecker interface {
	IsActiveMember(ctx context.Context, companyID, kcSub string) (bool, error)
}

// eventsSourceModulePattern constrains sourceModule to the same module-key shape the rest of the
// platform uses, sized so "events-"+sourceModule always fits
// notification.channel.key's own CHECK (^[a-z][a-z0-9_-]{1,63}$, migrations/0002): "events-" is
// 7 chars, leaving 56 for sourceModule against the 63-char channel-key ceiling.
var eventsSourceModulePattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,55}$`)

// SendTargetedEvent is the S2S delivery primitive: another module ("your doc was
// shared", "ticket assigned to you") targets SPECIFIC recipient kcSubs, bypassing the normal
// self-subscription fan-out SendMessage uses. It auto-provisions ONE per-company system channel
// per sourceModule (key "events-<sourceModule>", kind in_app, created lazily on first use via an
// upsert — "admin-owned by convention," i.e. no end-user ever manages it through the
// channels.manage API, but this module writes no authz tuple for it either: a system channel has
// no natural owner subject, and nothing reads notification_channel-scoped authz for it since
// recipient_state is written directly here, never through the subscribe/publish path that
// authz-gates real channels) and writes notification.recipient_state rows DIRECTLY for every
// CONFIRMED recipient (checker.IsActiveMember) — an unconfirmed/non-member recipient is silently
// skipped, counted, never an error for the whole call. actor is the acting end user (the bearer
// http.go's handler already validated + authorized as an active company member) — recorded as
// the message's created_by and the audit event's Actor, same convention SendMessage uses.
func (s *Store) SendTargetedEvent(ctx context.Context, checker MembershipChecker, actor string, companyID uuid.UUID, sourceModule, subjectLine, body string, recipientKcSubs []string) (sent, skipped int, err error) {
	if !eventsSourceModulePattern.MatchString(sourceModule) {
		return 0, 0, &ValidationError{Field: "sourceModule", Message: "must match ^[a-z][a-z0-9_-]{0,55}$"}
	}
	if err := validateSubjectLineAndBody(subjectLine, body); err != nil {
		return 0, 0, err
	}
	if len(recipientKcSubs) == 0 {
		return 0, 0, &ValidationError{Field: "recipientKcSubs", Message: "must not be empty"}
	}

	// Membership confirmation happens BEFORE the transaction opens (each check is an HTTP round
	// trip to org — never held inside a DB transaction).
	confirmed := make([]string, 0, len(recipientKcSubs))
	for _, kcSub := range recipientKcSubs {
		ok, cerr := checker.IsActiveMember(ctx, companyID.String(), kcSub)
		if cerr != nil || !ok {
			skipped++
			continue
		}
		confirmed = append(confirmed, kcSub)
	}
	if len(confirmed) == 0 {
		// A valid outcome (every named recipient was unconfirmed/non-member) — not an error.
		// No channel/message is created for a send with zero real recipients.
		return 0, skipped, nil
	}

	channelKey := "events-" + sourceModule
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, 0, fmt.Errorf("notification: begin tx: %w", err)
	}
	defer tx.Rollback(ctx)

	var pgChannelID pgtype.UUID
	err = tx.QueryRow(ctx, `
		INSERT INTO notification.channel (company_id, key, label, kind, target)
		VALUES ($1, $2, $3, 'in_app', NULL)
		ON CONFLICT (company_id, key) DO UPDATE SET key = EXCLUDED.key
		RETURNING id`,
		pgFromUUID(companyID), channelKey, "Events: "+sourceModule,
	).Scan(&pgChannelID)
	if err != nil {
		return 0, 0, fmt.Errorf("notification: provision events channel: %w", err)
	}

	var pgMessageID pgtype.UUID
	err = tx.QueryRow(ctx, `
		INSERT INTO notification.message (company_id, channel_id, subject_line, body, created_by)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id`,
		pgFromUUID(companyID), pgChannelID, subjectLine, body, actor,
	).Scan(&pgMessageID)
	if err != nil {
		return 0, 0, fmt.Errorf("notification: create event message: %w", err)
	}

	for _, kcSub := range confirmed {
		if _, err := tx.Exec(ctx, `INSERT INTO notification.recipient_state (message_id, subject) VALUES ($1, $2)`, pgMessageID, kcSub); err != nil {
			return 0, 0, fmt.Errorf("notification: create event recipient state: %w", err)
		}
	}
	sent = len(confirmed)

	if err := s.audit.Record(ctx, tx, audit.Event{
		Actor: actor, Action: "notification.event.send", Subject: "notification_channel:" + uuidFromPg(pgChannelID).String(),
		Payload: map[string]any{"companyId": companyID.String(), "sourceModule": sourceModule, "sent": sent, "skipped": skipped},
	}); err != nil {
		return 0, 0, fmt.Errorf("notification: audit event send: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, 0, fmt.Errorf("notification: commit: %w", err)
	}
	return sent, skipped, nil
}

func recipientExists(ctx context.Context, tx pgx.Tx, messageID uuid.UUID, subject string, companyID uuid.UUID) (bool, error) {
	var exists bool
	err := tx.QueryRow(ctx, `
		SELECT EXISTS(
			SELECT 1 FROM notification.recipient_state rs
			JOIN notification.message m ON m.id = rs.message_id
			WHERE rs.message_id = $1 AND rs.subject = $2 AND m.company_id = $3
		)`, pgFromUUID(messageID), subject, pgFromUUID(companyID),
	).Scan(&exists)
	return exists, err
}
