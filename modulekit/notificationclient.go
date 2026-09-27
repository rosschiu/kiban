// SPDX-License-Identifier: Apache-2.0

package modulekit

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
)

// NotificationClient calls notification's S2S targeted-events endpoint (POST
// /internal/notification/v1/companies/{companyId}/events). Returns an error only on a genuine
// transport/non-200 failure — callers decide independently whether to log-and-continue
// (notification must never be a hard dependency for a module's own writes).
type NotificationClient struct {
	baseURL   string
	client    *http.Client
	moduleKey string
}

// NewNotificationClient returns a client whose events carry moduleKey as sourceModule and whose
// errors are prefixed with it.
func NewNotificationClient(client *http.Client, baseURL, moduleKey string) *NotificationClient {
	return &NotificationClient{baseURL: baseURL, client: client, moduleKey: moduleKey}
}

// SendEventRequest is the targeted-events request body.
type SendEventRequest struct {
	RecipientKcSubs []string `json:"recipientKcSubs"`
	SubjectLine     string   `json:"subjectLine"`
	Body            string   `json:"body"`
	SourceModule    string   `json:"sourceModule"`
}

// SendEvent fires one targeted notification event to a single recipient kcSub, forwarding the
// acting user's own bearer verbatim.
func (c *NotificationClient) SendEvent(ctx context.Context, rawBearer, companyID, recipientKcSub, subjectLine, body string) error {
	req := SendEventRequest{RecipientKcSubs: []string{recipientKcSub}, SubjectLine: subjectLine, Body: body, SourceModule: c.moduleKey}
	u := fmt.Sprintf("%s/internal/notification/v1/companies/%s/events", c.baseURL, url.PathEscape(companyID))
	return postJSON(ctx, c.client, c.moduleKey, u, rawBearer, "notification event", req, nil)
}
