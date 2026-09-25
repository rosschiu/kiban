// SPDX-License-Identifier: Apache-2.0

package modulekit

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNotificationClient_SendEvent_Success_SendsExpectedPayload(t *testing.T) {
	var got SendEventRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/internal/notification/v1/companies/company-1/events" || r.Method != http.MethodPost {
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer tok" {
			t.Errorf("Authorization = %q", r.Header.Get("Authorization"))
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatal(err)
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"sent": 1, "skipped": 0}})
	}))
	defer srv.Close()

	c := NewNotificationClient(srv.Client(), srv.URL, testModule)
	if err := c.SendEvent(t.Context(), "Bearer tok", "company-1", "kcsub-x", "New comment", "body text"); err != nil {
		t.Fatalf("SendEvent: %v", err)
	}
	if len(got.RecipientKcSubs) != 1 || got.RecipientKcSubs[0] != "kcsub-x" || got.SourceModule != testModule || got.SubjectLine != "New comment" || got.Body != "body text" {
		t.Fatalf("got = %+v", got)
	}
}

func TestNotificationClient_SendEvent_NonOKStatus_Errors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := NewNotificationClient(srv.Client(), srv.URL, testModule)
	err := c.SendEvent(t.Context(), "Bearer tok", "company-1", "kcsub-x", "subj", "body")
	if err == nil || err.Error() != testModule+": notification event request: HTTP 500" {
		t.Fatalf("err = %v", err)
	}
}

func TestNotificationClient_SendEvent_TransportError_Errors(t *testing.T) {
	c := NewNotificationClient(&http.Client{Timeout: 200 * time.Millisecond}, "http://127.0.0.1:1", testModule)
	err := c.SendEvent(t.Context(), "Bearer tok", "company-1", "kcsub-x", "subj", "body")
	if err == nil || !strings.HasPrefix(err.Error(), testModule+": notification event request: ") {
		t.Fatalf("err = %v", err)
	}
}
