// SPDX-License-Identifier: Apache-2.0

package org

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// mustCreateCompany creates a company-typed root org unit with a unique code, failing the test
// on error.
func mustCreateCompany(t *testing.T, store *Store, code string) OrgUnit {
	t.Helper()
	unit, err := store.CreateOrgUnit(context.Background(), "test-actor", "company", nil, code, "Test Company "+code, true)
	if err != nil {
		t.Fatalf("create company %s: %v", code, err)
	}
	return unit
}

// mustCreateUnit creates a non-root org unit under parentID.
func mustCreateUnit(t *testing.T, store *Store, typeKey string, parentID uuid.UUID, code string) OrgUnit {
	t.Helper()
	unit, err := store.CreateOrgUnit(context.Background(), "test-actor", typeKey, &parentID, code, "Test Unit "+code, true)
	if err != nil {
		t.Fatalf("create unit %s: %v", code, err)
	}
	return unit
}

// mustCreateMember creates a member in companyID with a unique code.
func mustCreateMember(t *testing.T, store *Store, companyID uuid.UUID, code string) Member {
	t.Helper()
	m, err := store.CreateMember(context.Background(), "test-actor", companyID, code, "Test Member "+code, "", true)
	if err != nil {
		t.Fatalf("create member %s: %v", code, err)
	}
	return m
}

// mustCreatePosition creates a position in companyID at orgUnitID with a unique code.
func mustCreatePosition(t *testing.T, store *Store, companyID, orgUnitID uuid.UUID, code string) Position {
	t.Helper()
	p, err := store.CreatePosition(context.Background(), "test-actor", companyID, code, "Test Position "+code, orgUnitID)
	if err != nil {
		t.Fatalf("create position %s: %v", code, err)
	}
	return p
}

func date(s string) time.Time {
	t, err := time.Parse("2006-01-02", s)
	if err != nil {
		panic(err)
	}
	return t
}

// fakeIdentityChecker is a minimal Store.IdentityStateChecker for tests that don't need to
// exercise the real HTTP round trip (member_test.go / http_test.go cover that path directly).
type fakeIdentityChecker struct {
	exists map[string]bool
	err    error
}

func (f *fakeIdentityChecker) UserExists(ctx context.Context, kcSub string) (bool, error) {
	if f.err != nil {
		return false, f.err
	}
	return f.exists[kcSub], nil
}

// mustCreateIdentityUser inserts a minimal identity.user_account row directly via the admin
// pool (org's own store has no write path into identity's schema — cross-schema WRITES stay
// forbidden; this is test fixture setup only) and returns its internal id.
func mustCreateIdentityUser(t *testing.T, admin *pgxpool.Pool, kcSub string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	err := admin.QueryRow(context.Background(),
		`INSERT INTO identity.user_account (kc_sub, email, preferred_username) VALUES ($1, $2, $3) RETURNING id`,
		kcSub, kcSub+"@example.com", kcSub,
	).Scan(&id)
	if err != nil {
		t.Fatalf("create identity user %s: %v", kcSub, err)
	}
	return id
}

// mustToday is the store's own tenant-timezone "today" (Store.today on the pool), failing the
// test on error — tests compare against the clock the store actually stamps with.
func mustToday(t *testing.T, store *Store) time.Time {
	t.Helper()
	d, err := store.today(context.Background(), store.pool)
	if err != nil {
		t.Fatalf("today: %v", err)
	}
	return d
}
