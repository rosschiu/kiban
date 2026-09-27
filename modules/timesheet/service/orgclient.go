// SPDX-License-Identifier: Apache-2.0

package timesheet

import (
	"net/http"

	"github.com/rosschiu/kiban/modulekit"
)

// OrgClient reads org's member facts (modules consume the foundation's facts through APIs only —
// never a direct join into org's schema): the caller's own member id for entries/submissions and
// a target memberId's linked kcSub for approver grants.
type OrgClient = modulekit.OrgClient

func NewOrgClient(client *http.Client, baseURL string) *OrgClient {
	return modulekit.NewOrgClient(client, baseURL, "timesheet")
}
