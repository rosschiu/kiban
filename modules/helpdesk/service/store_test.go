// SPDX-License-Identifier: Apache-2.0

package helpdesk

import (
	"context"
	"strings"
	"testing"
)

// Direct tests for CheckMigrationsApplied and ValidationError.Error(), like the equivalent tests
// for other modules' Store (e.g. modules/notification/service/store_test.go,
// modules/timesheet/service/store_live_test.go).

func TestCheckMigrationsApplied_Success(t *testing.T) {
	pool := newTestPool(t)
	if err := CheckMigrationsApplied(context.Background(), pool); err != nil {
		t.Fatalf("expected migrations applied, got: %v", err)
	}
}

func TestValidationError_Error(t *testing.T) {
	err := &ValidationError{Field: "title", Message: "must be 1..200 characters"}
	got := err.Error()
	if !strings.Contains(got, "title") || !strings.Contains(got, "must be 1..200 characters") {
		t.Fatalf("Error() = %q, want it to mention the field and message", got)
	}
}
