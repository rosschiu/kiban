// SPDX-License-Identifier: Apache-2.0

// org's own half of the default module-access grant writer. On the PRODUCTION
// company-creation path (POST /internal/org/units, org.Store.CreateOrgUnit, when the created
// unit's type is org.org_unit_type.is_company = true), every currently installed+enabled module
// gets `company_module:<newCompanyId>/<moduleKey>#system @ system:platform` defaulted,
// default-ONCE, through authz's own audited authz/store.EnsureDefaultGrant — in the SAME
// transaction as the org_unit insert and its audit record, so a brand new company is never left
// with zero admins even transiently. Runs on org's OWN pool/role (kiban_org), which
// migrations/registry/0007 and migrations/authz/0005 grant exactly the cross-schema read
// (platform.module_installation) and write (authz.tuple/grant_ledger/default_grant) access this
// needs.
package org

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"

	authzstore "github.com/rosschiu/kiban/internal/authz/store"
)

const defaultGrantActor = "org-default"

// enabledModuleKeysTx lists every module_key currently installed AND enabled, read INSIDE the
// caller's own transaction — platform.module_installation is registry-owned; kiban_org has
// read-only cross-schema access to it (migrations/registry/0007).
func enabledModuleKeysTx(ctx context.Context, tx pgx.Tx) ([]string, error) {
	rows, err := tx.Query(ctx, `
		SELECT module_key FROM platform.module_installation
		WHERE installed = true AND enabled = true
		ORDER BY module_key`)
	if err != nil {
		return nil, fmt.Errorf("org: list enabled modules for default grant: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var key string
		if err := rows.Scan(&key); err != nil {
			return nil, err
		}
		out = append(out, key)
	}
	return out, rows.Err()
}

// defaultGrantNewCompanyTx grants every currently installed+enabled module's default
// company_module tuple for a brand new company, inside tx (the SAME transaction as the org_unit
// insert that created it) — atomic: the company either comes into existence WITH its default
// admin facts, or not at all.
func defaultGrantNewCompanyTx(ctx context.Context, tx pgx.Tx, companyID string) error {
	moduleKeys, err := enabledModuleKeysTx(ctx, tx)
	if err != nil {
		return err
	}
	for _, moduleKey := range moduleKeys {
		if _, err := authzstore.EnsureDefaultGrant(ctx, tx, defaultGrantActor, "", companyID, moduleKey); err != nil {
			return fmt.Errorf("org: default module-access grant module %s: %w", moduleKey, err)
		}
	}
	return nil
}
