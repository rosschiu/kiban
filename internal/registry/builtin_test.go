// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"encoding/json"
	"testing"

	notificationartifacts "github.com/rosschiu/kiban/modules/notification"
	timesheetartifacts "github.com/rosschiu/kiban/modules/timesheet"
)

func TestAuthzRelationsSection_ExtractsRelationsKey(t *testing.T) {
	full := []byte(`{"moduleKey":"x","relations":{"foo":{"bar":{"this":true}}}}`)
	got, err := authzRelationsSection(full)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(got, &m); err != nil {
		t.Fatalf("extracted relations isn't valid JSON: %v", err)
	}
	if _, ok := m["foo"]; !ok {
		t.Errorf("expected extracted relations to contain %q, got %s", "foo", got)
	}
}

// TestAuthzRelationsSection_MissingKey_ReturnsNil — a genuinely absent "relations" key is
// not an authoring error. timesheet is a module whose entire access-tier surface
// references the platform base model's own relations (company_module#admin/#submitter/#approver)
// and therefore declares none of its own — see modules/timesheet/authz.fragment.json's _comment
// and authzRelationsSection's own comment. registry.upsertAuthzFragment already treats a nil/
// empty fragment as a documented no-op ("not every module declares one"), so this changes nothing
// about what gets installed for a module that DOES declare relations, like notification.
func TestAuthzRelationsSection_MissingKey_ReturnsNil(t *testing.T) {
	got, err := authzRelationsSection([]byte(`{"moduleKey":"x"}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != nil {
		t.Fatalf("expected nil relations for a fragment with no \"relations\" key, got %s", got)
	}
}

func TestAuthzRelationsSection_InvalidJSON_Errors(t *testing.T) {
	_, err := authzRelationsSection([]byte(`not json`))
	if err == nil {
		t.Fatal("expected an error for invalid JSON")
	}
}

func TestNotificationAuthzRelations_LoadsFromRealFragment(t *testing.T) {
	// The real embedded artifact must extract cleanly — proves notificationAuthzRelations'
	// package-level init (mustAuthzRelations) doesn't panic against the actual shipped fragment.
	got, err := authzRelationsSection(notificationartifacts.AuthzFragmentJSON)
	if err != nil {
		t.Fatalf("unexpected error extracting the real notification fragment: %v", err)
	}
	if len(got) == 0 {
		t.Fatal("expected a non-empty relations section")
	}
	if len(notificationAuthzRelations) == 0 {
		t.Fatal("notificationAuthzRelations (package-level var) must be non-empty")
	}
}

func TestTimesheetAuthzRelations_LoadsFromRealFragment(t *testing.T) {
	// The real embedded artifact extracts cleanly to nil (no "relations" key) — proves
	// timesheetAuthzRelations' package-level init (mustAuthzRelations) doesn't panic against the
	// actual shipped fragment, and registry.upsertAuthzFragment's nil-is-a-no-op path is what
	// actually installs (or rather, deliberately doesn't install) this module's own relations.
	got, err := authzRelationsSection(timesheetartifacts.AuthzFragmentJSON)
	if err != nil {
		t.Fatalf("unexpected error extracting the real timesheet fragment: %v", err)
	}
	if got != nil {
		t.Fatalf("expected nil relations for timesheet's fragment (declares none of its own), got %s", got)
	}
	if timesheetAuthzRelations != nil {
		t.Fatal("timesheetAuthzRelations (package-level var) must be nil")
	}
}
