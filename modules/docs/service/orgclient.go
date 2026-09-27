// SPDX-License-Identifier: Apache-2.0

package docs

import (
	"net/http"

	"github.com/rosschiu/kiban/modulekit"
)

// OrgClient reads org's member facts (modules consume the foundation's facts through APIs only —
// never a direct join into org's schema): the caller's OWN member id (docs.share is keyed by
// member_id) and a share target's memberId resolved to its linked user's kcSub (422 if none).
type OrgClient = modulekit.OrgClient

func NewOrgClient(client *http.Client, baseURL string) *OrgClient {
	return modulekit.NewOrgClient(client, baseURL, "docs")
}
