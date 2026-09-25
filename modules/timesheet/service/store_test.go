// SPDX-License-Identifier: Apache-2.0

package timesheet

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestIsoMonday(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"monday stays monday", "2026-08-10", "2026-08-10"}, // 2026-08-10 is a Monday
		{"tuesday rolls back", "2026-08-11", "2026-08-10"},
		{"sunday rolls back to prior monday", "2026-08-16", "2026-08-10"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in, _ := time.Parse("2006-01-02", tc.in)
			want, _ := time.Parse("2006-01-02", tc.want)
			got := isoMonday(in)
			if !got.Equal(want) {
				t.Errorf("isoMonday(%s) = %s, want %s", tc.in, got.Format("2006-01-02"), tc.want)
			}
		})
	}
}

func TestValidateHours(t *testing.T) {
	cfg := defaultConfig(uuid.New()) // enforceBillableWithinActual=true, allowAboveEight=false

	cases := []struct {
		name           string
		real, billable float64
		wantErrField   string
	}{
		{"valid", 8, 6, ""},
		{"real too high", 25, 0, "realHours"},
		{"real negative", -1, 0, "realHours"},
		{"billable too high", 10, 25, "billableHours"},
		{"billable exceeds real", 4, 5, "billableHours"},
		{"billable exceeds eight cap", 10, 8.5, "billableHours"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateHours(cfg, tc.real, tc.billable)
			if tc.wantErrField == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			verr, ok := err.(*ValidationError)
			if !ok {
				t.Fatalf("expected *ValidationError, got %v", err)
			}
			if verr.Field != tc.wantErrField {
				t.Errorf("field = %q, want %q", verr.Field, tc.wantErrField)
			}
		})
	}
}

func TestValidateHours_AllowAboveEightConfigured(t *testing.T) {
	cfg := defaultConfig(uuid.New())
	cfg.AllowBillableAboveEightHours = true
	if err := validateHours(cfg, 10, 9); err != nil {
		t.Fatalf("expected no error with allowBillableAboveEightHours=true, got %v", err)
	}
}

func TestValidateHours_DisableEnforceBillableWithinActual(t *testing.T) {
	cfg := defaultConfig(uuid.New())
	cfg.EnforceBillableWithinActual = false
	cfg.AllowBillableAboveEightHours = true
	if err := validateHours(cfg, 2, 6); err != nil {
		t.Fatalf("expected no error with enforceBillableWithinActual=false, got %v", err)
	}
}

func TestValidateWeekWindow(t *testing.T) {
	cfg := defaultConfig(uuid.New()) // 4 previous, 1 future
	now, _ := time.Parse("2006-01-02", "2026-08-10")

	inWindow, _ := time.Parse("2006-01-02", "2026-07-20") // 3 weeks back
	if err := validateWeekWindow(cfg, now, inWindow); err != nil {
		t.Errorf("expected in-window date to pass, got %v", err)
	}

	tooOld, _ := time.Parse("2006-01-02", "2026-06-01") // > 4 weeks back
	if err := validateWeekWindow(cfg, now, tooOld); err == nil {
		t.Errorf("expected too-old date to fail")
	}

	tooFuture, _ := time.Parse("2006-01-02", "2026-09-01") // > 1 week ahead
	if err := validateWeekWindow(cfg, now, tooFuture); err == nil {
		t.Errorf("expected too-far-future date to fail")
	}
}

func TestValidateProject(t *testing.T) {
	if err := validateProject("PROJ-1", "Project One", "active"); err != nil {
		t.Errorf("expected valid project, got %v", err)
	}
	if err := validateProject("bad code", "Project One", "active"); err == nil {
		t.Errorf("expected code validation error")
	}
	if err := validateProject("PROJ-1", "", "active"); err == nil {
		t.Errorf("expected name validation error")
	}
	if err := validateProject("PROJ-1", "Project One", "bogus"); err == nil {
		t.Errorf("expected status validation error")
	}
}
