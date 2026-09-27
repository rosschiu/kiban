// SPDX-License-Identifier: Apache-2.0

package docs

import (
	"net/http"

	"github.com/rosschiu/kiban/modulekit"
)

// NotificationClient delivers "<name> shared '<title>' with you" / "your access to '<title>' was
// revoked" notices through notification's S2S targeted-events endpoint. Non-fatal if notification
// is down: every call site in store.go treats a SendEvent error as log-and-continue, never a
// share/revoke failure.
type NotificationClient = modulekit.NotificationClient

func NewNotificationClient(client *http.Client, baseURL string) *NotificationClient {
	return modulekit.NewNotificationClient(client, baseURL, "docs")
}
