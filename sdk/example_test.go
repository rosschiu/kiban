// SPDX-License-Identifier: Apache-2.0

package sdk_test

// The public "Integrate your app" page's backend samples for Go. They compile with the
// package; the live test in internal/gateway runs the same calls against a real stack.

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/rosschiu/kiban/sdk"
)

// 5. Create the client once at startup.
func newBackend(ctx context.Context, gatewayURL, clientSecret string) (*sdk.Client, error) {
	return sdk.New(ctx, sdk.Config{GatewayURL: gatewayURL, ClientID: "tokidesk-backend", ClientSecret: clientSecret})
}

// 6. Verify the user's token on every request.
func requireUser(ctx context.Context, kiban *sdk.Client, r *http.Request) (string, error) {
	bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if bearer == "" {
		return "", errors.New("login required")
	}
	return kiban.VerifyUserToken(ctx, bearer)
}

// 7. Ask before every read and write, with the user's own bearer.
func canViewTicket(ctx context.Context, kiban *sdk.Client, bearer, companyID, ticketID string) (bool, error) {
	d, err := kiban.Can(ctx, bearer, sdk.CanRequest{
		FeatureKey: "tokidesk.ticket.view", ModuleKey: "tokidesk", CompanyID: companyID,
		Object: &struct {
			Type string `json:"type"`
			ID   string `json:"id"`
		}{Type: "ticket", ID: ticketID},
		Relation: "viewer",
	})
	return d.Allowed, err
}

// 8. Write tuples when things happen.
func onTicketCreated(ctx context.Context, kiban *sdk.Client, companyID, ticketID, creatorSubject string) error {
	return kiban.Grant(ctx, companyID,
		sdk.AnchorTuple("tokidesk", "ticket", ticketID, companyID),
		sdk.Tuple{ObjectType: "ticket", ObjectID: ticketID, Relation: "viewer", SubjectType: "user", SubjectID: creatorSubject},
	)
}

// 9. Look the member up.
func memberIDOf(ctx context.Context, kiban *sdk.Client, companyID, subject string) (string, bool, error) {
	f, err := kiban.MemberBySubject(ctx, companyID, subject)
	if err != nil || !f.IsMember || !f.IsActive || f.MemberID == nil {
		return "", false, err
	}
	return *f.MemberID, true, nil
}

// 10. A background job asks for itself.
func mayRunReminders(ctx context.Context, kiban *sdk.Client, companyID string) (bool, error) {
	d, err := kiban.CanService(ctx, sdk.CanRequest{FeatureKey: "tokidesk.reminders.run", ModuleKey: "tokidesk", CompanyID: companyID})
	return d.Allowed, err
}

var _ = []any{newBackend, requireUser, canViewTicket, onTicketCreated, memberIDOf, mayRunReminders}
