// SPDX-License-Identifier: Apache-2.0

package helpdesk

import (
	"context"
	"net/http"

	"github.com/rosschiu/kiban/modulekit"
)

// NotificationClient delivers "a ticket was assigned to you" / "a ticket's status changed" / "a
// new comment on your ticket" notices through notification's S2S targeted-events endpoint.
// Notification events are non-fatal on failure: every call site in http.go treats a SendEvent
// error as log-and-continue, never a request failure.
type NotificationClient struct {
	*modulekit.NotificationClient
}

func NewNotificationClient(client *http.Client, baseURL string) *NotificationClient {
	return &NotificationClient{modulekit.NewNotificationClient(client, baseURL, "helpdesk")}
}

type sendEventRequestWire = modulekit.SendEventRequest

// SendEvent is modulekit's SendEvent with one helpdesk rule on top: an empty recipient (a member
// with no linked user) is a no-op, not an error and not a round trip.
func (c *NotificationClient) SendEvent(ctx context.Context, rawBearer, companyID, recipientKcSub, subjectLine, body string) error {
	if recipientKcSub == "" {
		return nil // no linked user to notify — not an error, nothing to do
	}
	return c.NotificationClient.SendEvent(ctx, rawBearer, companyID, recipientKcSub, subjectLine, body)
}
