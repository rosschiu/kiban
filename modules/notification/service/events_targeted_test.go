// SPDX-License-Identifier: Apache-2.0

package notification

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
)

// fakeMembershipChecker is a minimal MembershipChecker test double keyed on kcSub — errKcSubs
// simulates a genuinely-unreachable org for that one kcSub (treated identically to "not a
// member" by SendTargetedEvent, per its own doc comment).
type fakeMembershipChecker struct {
	members   map[string]bool
	errKcSubs map[string]bool
}

func (f *fakeMembershipChecker) IsActiveMember(ctx context.Context, companyID, kcSub string) (bool, error) {
	if f.errKcSubs[kcSub] {
		return false, errFakeMembershipUnreachable
	}
	return f.members[kcSub], nil
}

var errFakeMembershipUnreachable = &ValidationError{Field: "test", Message: "simulated org unreachable"}

// --- Store.SendTargetedEvent -----------------------------------------------------------------

func TestStore_SendTargetedEvent_ConfirmedRecipientsOnly(t *testing.T) {
	store := newTestStore(t)
	companyID := uuid.New()
	checker := &fakeMembershipChecker{members: map[string]bool{"alice": true, "bob": true, "eve": false}}

	sent, skipped, err := store.SendTargetedEvent(context.Background(), checker, "actor-sub", companyID,
		"evdocs", "Your doc was shared", "Alice shared a document with you.", []string{"alice", "bob", "eve"})
	if err != nil {
		t.Fatalf("SendTargetedEvent: %v", err)
	}
	if sent != 2 || skipped != 1 {
		t.Fatalf("sent=%d skipped=%d, want sent=2 skipped=1 (eve is not a member)", sent, skipped)
	}

	// The channel was auto-provisioned with the expected key/kind.
	var key, kind string
	if err := store.pool.QueryRow(context.Background(),
		`SELECT key, kind FROM notification.channel WHERE company_id = $1 AND key = 'events-evdocs'`,
		pgFromUUID(companyID)).Scan(&key, &kind); err != nil {
		t.Fatalf("query provisioned channel: %v", err)
	}
	if key != "events-evdocs" || kind != "in_app" {
		t.Fatalf("channel key=%q kind=%q, want events-evdocs/in_app", key, kind)
	}

	// alice and bob each got a recipient_state row; eve did not.
	rows, err := store.pool.Query(context.Background(), `
		SELECT rs.subject FROM notification.recipient_state rs
		JOIN notification.message m ON m.id = rs.message_id
		WHERE m.company_id = $1`, pgFromUUID(companyID))
	if err != nil {
		t.Fatalf("query recipient_state: %v", err)
	}
	defer rows.Close()
	got := map[string]bool{}
	for rows.Next() {
		var subj string
		if err := rows.Scan(&subj); err != nil {
			t.Fatalf("scan: %v", err)
		}
		got[subj] = true
	}
	if !got["alice"] || !got["bob"] || got["eve"] {
		t.Fatalf("recipient_state subjects = %v, want exactly {alice,bob}", got)
	}
}

func TestStore_SendTargetedEvent_UnconfirmedCheckerError_TreatedAsSkip(t *testing.T) {
	store := newTestStore(t)
	companyID := uuid.New()
	checker := &fakeMembershipChecker{errKcSubs: map[string]bool{"broken": true}}

	sent, skipped, err := store.SendTargetedEvent(context.Background(), checker, "actor-sub", companyID,
		"evdocs", "Subject", "Body", []string{"broken"})
	if err != nil {
		t.Fatalf("SendTargetedEvent: %v", err)
	}
	if sent != 0 || skipped != 1 {
		t.Fatalf("sent=%d skipped=%d, want sent=0 skipped=1 (checker error must be treated as skip, never delivered)", sent, skipped)
	}
}

func TestStore_SendTargetedEvent_AllSkipped_NoChannelCreated(t *testing.T) {
	store := newTestStore(t)
	companyID := uuid.New()
	checker := &fakeMembershipChecker{members: map[string]bool{}}

	sent, skipped, err := store.SendTargetedEvent(context.Background(), checker, "actor-sub", companyID,
		"evnobody", "Subject", "Body", []string{"nobody-here"})
	if err != nil {
		t.Fatalf("SendTargetedEvent: %v", err)
	}
	if sent != 0 || skipped != 1 {
		t.Fatalf("sent=%d skipped=%d, want sent=0 skipped=1", sent, skipped)
	}
	var count int
	if err := store.pool.QueryRow(context.Background(),
		`SELECT count(*) FROM notification.channel WHERE company_id = $1 AND key = 'events-evnobody'`,
		pgFromUUID(companyID)).Scan(&count); err != nil {
		t.Fatalf("count channels: %v", err)
	}
	if count != 0 {
		t.Fatalf("a channel was provisioned despite zero confirmed recipients — want none")
	}
}

func TestStore_SendTargetedEvent_Idempotent_SameChannelReused(t *testing.T) {
	store := newTestStore(t)
	companyID := uuid.New()
	checker := &fakeMembershipChecker{members: map[string]bool{"alice": true}}

	if _, _, err := store.SendTargetedEvent(context.Background(), checker, "actor-sub", companyID, "evreuse", "s1", "b1", []string{"alice"}); err != nil {
		t.Fatalf("first send: %v", err)
	}
	if _, _, err := store.SendTargetedEvent(context.Background(), checker, "actor-sub", companyID, "evreuse", "s2", "b2", []string{"alice"}); err != nil {
		t.Fatalf("second send: %v", err)
	}

	var count int
	if err := store.pool.QueryRow(context.Background(),
		`SELECT count(*) FROM notification.channel WHERE company_id = $1 AND key = 'events-evreuse'`,
		pgFromUUID(companyID)).Scan(&count); err != nil {
		t.Fatalf("count channels: %v", err)
	}
	if count != 1 {
		t.Fatalf("channel count = %d, want exactly 1 (lazy provisioning must not duplicate the channel on a second send)", count)
	}
}

func TestStore_SendTargetedEvent_ControlCharSubject_Rejected(t *testing.T) {
	store := newTestStore(t)
	checker := &fakeMembershipChecker{members: map[string]bool{"alice": true}}
	_, _, err := store.SendTargetedEvent(context.Background(), checker, "actor-sub", uuid.New(), "evctl", "bad\r\nsubject", "body", []string{"alice"})
	var verr *ValidationError
	if err == nil {
		t.Fatal("expected a ValidationError for a control-char subject, got nil")
	}
	if !asValidationError(err, &verr) || verr.Field != "subjectLine" {
		t.Fatalf("error = %v, want a subjectLine ValidationError", err)
	}
}

func TestStore_SendTargetedEvent_InvalidSourceModule_Rejected(t *testing.T) {
	store := newTestStore(t)
	checker := &fakeMembershipChecker{members: map[string]bool{"alice": true}}
	_, _, err := store.SendTargetedEvent(context.Background(), checker, "actor-sub", uuid.New(), "Not_Valid!", "s", "b", []string{"alice"})
	var verr *ValidationError
	if err == nil {
		t.Fatal("expected a ValidationError for an invalid sourceModule, got nil")
	}
	if !asValidationError(err, &verr) || verr.Field != "sourceModule" {
		t.Fatalf("error = %v, want a sourceModule ValidationError", err)
	}
}

func TestStore_SendTargetedEvent_EmptyRecipients_Rejected(t *testing.T) {
	store := newTestStore(t)
	checker := &fakeMembershipChecker{members: map[string]bool{}}
	_, _, err := store.SendTargetedEvent(context.Background(), checker, "actor-sub", uuid.New(), "evempty", "s", "b", nil)
	var verr *ValidationError
	if err == nil {
		t.Fatal("expected a ValidationError for empty recipients, got nil")
	}
	if !asValidationError(err, &verr) || verr.Field != "recipientKcSubs" {
		t.Fatalf("error = %v, want a recipientKcSubs ValidationError", err)
	}
}

// --- HTTP handler: POST /internal/notification/v1/companies/{companyId}/events ---------------

func TestHTTP_SendEvent_ActiveMember_200(t *testing.T) {
	f := newHTTPFixture(t, map[string]bool{"alice": true})
	companyID := uuid.New()
	orgSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"isMember": true, "isActive": true}})
	}))
	defer orgSrv.Close()
	f.svc.Org = NewOrgClient(orgSrv.Client(), orgSrv.URL)

	bearer := f.token(t, "alice")
	body := `{"recipientKcSubs":["bob"],"subjectLine":"Doc shared","body":"Alice shared a doc","sourceModule":"docs"}`
	rec := f.do(t, http.MethodPost, "/internal/notification/v1/companies/"+companyID.String()+"/events", bearer, body, nil)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	var out struct {
		Data struct {
			Sent    int `json:"sent"`
			Skipped int `json:"skipped"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Data.Sent != 1 || out.Data.Skipped != 0 {
		t.Fatalf("data = %+v, want sent=1 skipped=0", out.Data)
	}
}

func TestHTTP_SendEvent_NonMemberActor_403(t *testing.T) {
	f := newHTTPFixture(t, map[string]bool{}) // "alice" is NOT a member per newFakeAuthz
	companyID := uuid.New()

	bearer := f.token(t, "alice")
	body := `{"recipientKcSubs":["bob"],"subjectLine":"x","body":"y","sourceModule":"docs"}`
	rec := f.do(t, http.MethodPost, "/internal/notification/v1/companies/"+companyID.String()+"/events", bearer, body, nil)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (acting caller is not an active company member), body=%s", rec.Code, rec.Body.String())
	}
}

func TestHTTP_SendEvent_MissingBearer_401(t *testing.T) {
	f := newHTTPFixture(t, map[string]bool{"alice": true})
	rec := f.do(t, http.MethodPost, "/internal/notification/v1/companies/"+uuid.New().String()+"/events", "", `{}`, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestHTTP_SendEvent_OrgClientNil_503(t *testing.T) {
	f := newHTTPFixture(t, map[string]bool{"alice": true}) // f.svc.Org is unset (nil) by newHTTPFixture
	companyID := uuid.New()
	bearer := f.token(t, "alice")
	body := `{"recipientKcSubs":["bob"],"subjectLine":"x","body":"y","sourceModule":"docs"}`
	rec := f.do(t, http.MethodPost, "/internal/notification/v1/companies/"+companyID.String()+"/events", bearer, body, nil)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 (Org dependency unconfigured), body=%s", rec.Code, rec.Body.String())
	}
}
