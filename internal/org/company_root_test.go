// SPDX-License-Identifier: Apache-2.0

package org

import (
	"testing"

	"github.com/google/uuid"
)

func TestCheckCompanyIsRoot(t *testing.T) {
	id := uuid.New()
	if err := checkCompanyIsRoot(true, nil); err != nil {
		t.Fatalf("company root: %v", err)
	}
	if err := checkCompanyIsRoot(false, &id); err != nil {
		t.Fatalf("non-company under parent: %v", err)
	}
	if err := checkCompanyIsRoot(true, &id); err == nil {
		t.Fatal("company with a parent must be rejected")
	}
	if err := checkCompanyIsRoot(false, nil); err == nil {
		t.Fatal("non-company root must be rejected")
	}
}
