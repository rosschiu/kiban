// SPDX-License-Identifier: Apache-2.0

package notification

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/google/uuid"
)

// Closes not-found/error-branch gaps the existing happy-path flows
// (TestHTTP_FullFlow / TestHTTP_ListGetUnsubscribeDeleteChannel_FullFlow) leave behind — every
// test here targets a channel/message/subscription ID the store genuinely won't find, proving
// writeStoreError's ErrChannelNotFound/ErrRecipientNotFound branches route through the HTTP layer
// correctly for handleDeleteChannel/handleSubscribe/handleUnsubscribe/handleSendMessage/
// handleMarkRead, none of which any existing test drives down its own not-found path.

type errEnvelope struct {
	Error struct {
		Code    string            `json:"code"`
		Message string            `json:"message"`
		Details map[string]string `json:"details"`
	} `json:"error"`
}

func decodeErrEnv(t *testing.T, body []byte) errEnvelope {
	t.Helper()
	var e errEnvelope
	if err := json.Unmarshal(body, &e); err != nil {
		t.Fatalf("decode error envelope: %v (body=%s)", err, body)
	}
	return e
}

func TestHTTP_DeleteChannel_UnknownChannel_404(t *testing.T) {
	subject := "kcsub-alice"
	f := newHTTPFixture(t, map[string]bool{subject: true})
	companyID := uuid.NewString()
	tok := f.token(t, subject)

	rec := f.do(t, http.MethodDelete, "/api/notification/v1/companies/"+companyID+"/channels/"+uuid.NewString(), tok, "", nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", rec.Code, rec.Body.String())
	}
	if e := decodeErrEnv(t, rec.Body.Bytes()); e.Error.Code != "NOT_FOUND" {
		t.Fatalf("error = %+v", e.Error)
	}
}

func TestHTTP_Subscribe_UnknownChannel_404(t *testing.T) {
	subject := "kcsub-alice"
	f := newHTTPFixture(t, map[string]bool{subject: true})
	companyID := uuid.NewString()
	tok := f.token(t, subject)

	rec := f.do(t, http.MethodPost, fmt.Sprintf("/api/notification/v1/companies/%s/channels/%s/subscriptions", companyID, uuid.NewString()), tok, "", nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHTTP_Unsubscribe_UnknownChannel_404(t *testing.T) {
	subject := "kcsub-alice"
	f := newHTTPFixture(t, map[string]bool{subject: true})
	companyID := uuid.NewString()
	tok := f.token(t, subject)

	rec := f.do(t, http.MethodDelete, fmt.Sprintf("/api/notification/v1/companies/%s/channels/%s/subscriptions/me", companyID, uuid.NewString()), tok, "", nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHTTP_SendMessage_UnknownChannel_404(t *testing.T) {
	subject := "kcsub-alice"
	f := newHTTPFixture(t, map[string]bool{subject: true})
	companyID := uuid.NewString()
	tok := f.token(t, subject)

	body := fmt.Sprintf(`{"channelId":%q,"subjectLine":"Hi","body":"There"}`, uuid.NewString())
	rec := f.do(t, http.MethodPost, "/api/notification/v1/companies/"+companyID+"/messages", tok, body, map[string]string{"Content-Type": "application/json"})
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestHTTP_SendMessage_InvalidChannelUUID_400 covers handleSendMessage's own uuid.Parse branch
// (distinct from parsePathUUID's — this one parses a BODY field, not a path segment).
func TestHTTP_SendMessage_InvalidChannelUUID_400(t *testing.T) {
	subject := "kcsub-alice"
	f := newHTTPFixture(t, map[string]bool{subject: true})
	companyID := uuid.NewString()
	tok := f.token(t, subject)

	body := `{"channelId":"not-a-uuid","subjectLine":"Hi","body":"There"}`
	rec := f.do(t, http.MethodPost, "/api/notification/v1/companies/"+companyID+"/messages", tok, body, map[string]string{"Content-Type": "application/json"})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
	if e := decodeErrEnv(t, rec.Body.Bytes()); e.Error.Details["field"] != "channelId" {
		t.Fatalf("error = %+v", e.Error)
	}
}

// TestHTTP_SendMessage_OversizedIdempotencyKey_400 covers handleSendMessage's Idempotency-Key
// length-limit branch.
func TestHTTP_SendMessage_OversizedIdempotencyKey_400(t *testing.T) {
	subject := "kcsub-alice"
	f := newHTTPFixture(t, map[string]bool{subject: true})
	companyID := uuid.NewString()
	tok := f.token(t, subject)

	createBody := `{"key":"oversized-key-chan","label":"Oversized","kind":"in_app"}`
	rec := f.do(t, http.MethodPost, "/api/notification/v1/companies/"+companyID+"/channels", tok, createBody, map[string]string{"Content-Type": "application/json"})
	var createEnv struct {
		Data channelWire `json:"data"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &createEnv)

	longKey := ""
	for i := 0; i < 201; i++ {
		longKey += "k"
	}
	sendBody := fmt.Sprintf(`{"channelId":%q,"subjectLine":"Hi","body":"There"}`, createEnv.Data.ID)
	rec = f.do(t, http.MethodPost, "/api/notification/v1/companies/"+companyID+"/messages", tok, sendBody, map[string]string{"Content-Type": "application/json", "Idempotency-Key": longKey})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHTTP_MarkRead_UnknownMessage_404(t *testing.T) {
	subject := "kcsub-alice"
	f := newHTTPFixture(t, map[string]bool{subject: true})
	companyID := uuid.NewString()
	tok := f.token(t, subject)

	rec := f.do(t, http.MethodPost, fmt.Sprintf("/api/notification/v1/companies/%s/messages/%s/read", companyID, uuid.NewString()), tok, "", nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", rec.Code, rec.Body.String())
	}
	if e := decodeErrEnv(t, rec.Body.Bytes()); e.Error.Code != "NOT_FOUND" {
		t.Fatalf("error = %+v", e.Error)
	}
}

// TestHTTP_ListInbox_Pagination covers handleListInbox's page/pageSize query-param branch (no
// existing test passes explicit paging params).
func TestHTTP_ListInbox_Pagination(t *testing.T) {
	subject := "kcsub-alice"
	f := newHTTPFixture(t, map[string]bool{subject: true})
	companyID := uuid.NewString()
	tok := f.token(t, subject)

	createBody := `{"key":"paging-chan","label":"Paging","kind":"in_app"}`
	rec := f.do(t, http.MethodPost, "/api/notification/v1/companies/"+companyID+"/channels", tok, createBody, map[string]string{"Content-Type": "application/json"})
	var createEnv struct {
		Data channelWire `json:"data"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &createEnv)
	f.do(t, http.MethodPost, fmt.Sprintf("/api/notification/v1/companies/%s/channels/%s/subscriptions", companyID, createEnv.Data.ID), tok, "", nil)

	for i := 0; i < 3; i++ {
		sendBody := fmt.Sprintf(`{"channelId":%q,"subjectLine":"Hi %d","body":"There"}`, createEnv.Data.ID, i)
		f.do(t, http.MethodPost, "/api/notification/v1/companies/"+companyID+"/messages", tok, sendBody, map[string]string{"Content-Type": "application/json"})
	}

	rec = f.do(t, http.MethodGet, "/api/notification/v1/companies/"+companyID+"/messages?page=1&pageSize=2", tok, "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("list inbox page 1: %d %s", rec.Code, rec.Body.String())
	}
	var page struct {
		Data struct {
			Items      []messageWire `json:"items"`
			Total      int           `json:"total"`
			Page       int           `json:"page"`
			PageSize   int           `json:"pageSize"`
			TotalPages int           `json:"totalPages"`
		} `json:"data"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &page)
	if page.Data.Total != 3 || len(page.Data.Items) != 2 || page.Data.TotalPages != 2 {
		t.Fatalf("page 1 = %+v", page.Data)
	}
}
