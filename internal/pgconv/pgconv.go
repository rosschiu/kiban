// SPDX-License-Identifier: Apache-2.0

// Package pgconv holds the nullable-column conversions every pgx-backed store repeats.
package pgconv

import (
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

func UUIDPtrFromPg(v pgtype.UUID) *uuid.UUID {
	if !v.Valid {
		return nil
	}
	id := uuid.UUID(v.Bytes)
	return &id
}

func DerefStr(v *string) string {
	if v == nil {
		return ""
	}
	return *v
}

func StrOrNil(v string) *string {
	if v == "" {
		return nil
	}
	return &v
}
