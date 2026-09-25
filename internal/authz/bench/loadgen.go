// SPDX-License-Identifier: Apache-2.0

//go:build bench

// Package bench is the engine latency benchmark (`make bench-authz`), exercising the
// CONCURRENT internal/authz/engine.Engine.BatchCan. Loadgen is deterministic: fixed
// cardinalities, fixed seed (42), target table authz.tuple.
package bench

import (
	"context"
	"fmt"
	"math/rand"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Loadgen builds a ~1.05M-tuple synthetic dataset over the real model.fga shapes.
type Loadgen struct {
	Seed                 int64
	Companies            int
	MembersPerCompany    int
	RoleTuplesPerCompany int
	BusinessPerCompany   int
	HotCompanyIndex      int
	HotMembers           int
	HotBusiness          int
}

// DefaultLoadgen is the reference dataset shape: 1,000 companies, HOT company at index 999
// with 5,000 members / 20,000 business objects.
var DefaultLoadgen = Loadgen{
	Seed:                 42,
	Companies:            1000,
	MembersPerCompany:    200,
	RoleTuplesPerCompany: 40,
	BusinessPerCompany:   300,
	HotCompanyIndex:      999,
	HotMembers:           5000,
	HotBusiness:          20000,
}

var moduleKeys = []string{"m1", "m2", "m3", "m4", "m5"}
var roleRelations = []string{"editor", "submitter", "approver", "viewer"}

// GeneratedIDs is the handful of IDs bench_test.go needs to build check vectors against the
// HOT company without re-deriving the generator's internal ID scheme.
type GeneratedIDs struct {
	HotCompanyID       string
	HotCompanyAdminID  string
	HotCompanyModuleID string
	HotBusinessIDs     []string
	HotGrantees        []string
	OtherCompanyBiz    []string
}

// TupleCounts totals rows generated per shape, computed from what was actually generated.
type TupleCounts struct {
	CompanyModuleParent int
	CompanyAdmin        int
	MemberCompanyModule int
	MemberMappedUser    int
	RoleTuples          int
	BusinessCompanyMod  int
	BusinessDirectGrant int
}

func (c TupleCounts) Total() int {
	return c.CompanyModuleParent + c.CompanyAdmin + c.MemberCompanyModule + c.MemberMappedUser +
		c.RoleTuples + c.BusinessCompanyMod + c.BusinessDirectGrant
}

type rowBuf struct {
	rows [][]any
}

func (b *rowBuf) add(objType, objID, rel, subjType, subjID, subjRel string) {
	b.rows = append(b.rows, []any{objType, objID, rel, subjType, subjID, subjRel})
}

// Generate builds the full tuple set in memory (sequential, deterministic).
func (lg Loadgen) Generate() ([][]any, TupleCounts, GeneratedIDs) {
	rng := rand.New(rand.NewSource(lg.Seed))
	buf := &rowBuf{}
	var counts TupleCounts
	var ids GeneratedIDs

	sampleEvery := 137

	for ci := 0; ci < lg.Companies; ci++ {
		companyID := fmt.Sprintf("c%04d", ci)
		companyAdminUser := companyID + "/admin"
		buf.add("company", companyID, "admin", "user", companyAdminUser, "")
		counts.CompanyAdmin++

		isHot := ci == lg.HotCompanyIndex
		members := lg.MembersPerCompany
		business := lg.BusinessPerCompany
		if isHot {
			members = lg.HotMembers
			business = lg.HotBusiness
		}

		companyModuleIDs := make([]string, len(moduleKeys))
		for mi, mk := range moduleKeys {
			cmID := companyID + "/" + mk
			companyModuleIDs[mi] = cmID
			buf.add("company_module", cmID, "company", "company", companyID, "")
			counts.CompanyModuleParent++
		}

		for r := 0; r < lg.RoleTuplesPerCompany; r++ {
			cm := companyModuleIDs[r%len(companyModuleIDs)]
			rel := roleRelations[r%len(roleRelations)]
			user := fmt.Sprintf("%s/role-user-%d", companyID, r)
			buf.add("company_module", cm, rel, "user", user, "")
			counts.RoleTuples++
		}

		for mi := 0; mi < members; mi++ {
			memberID := fmt.Sprintf("%s/member-%05d", companyID, mi)
			cm := companyModuleIDs[rng.Intn(len(companyModuleIDs))]
			buf.add("member", memberID, "company_module", "company_module", cm, "")
			counts.MemberCompanyModule++
			mappedUser := memberID + "/user"
			buf.add("member", memberID, "mapped_user", "user", mappedUser, "")
			counts.MemberMappedUser++
		}

		for bi := 0; bi < business; bi++ {
			bizID := fmt.Sprintf("%s/te-%05d", companyID, bi)
			cm := companyModuleIDs[rng.Intn(len(companyModuleIDs))]
			buf.add("timesheet_entry", bizID, "company_module", "company_module", cm, "")
			counts.BusinessCompanyMod++
			grantee := bizID + "/grantee"
			buf.add("timesheet_entry", bizID, "viewer", "user", grantee, "")
			counts.BusinessDirectGrant++

			if isHot && bi%sampleEvery == 0 {
				ids.HotBusinessIDs = append(ids.HotBusinessIDs, bizID)
				ids.HotGrantees = append(ids.HotGrantees, grantee)
			}
			if !isHot && ci == 0 && bi < 50 {
				ids.OtherCompanyBiz = append(ids.OtherCompanyBiz, bizID)
			}
		}

		if isHot {
			ids.HotCompanyID = companyID
			ids.HotCompanyAdminID = companyAdminUser
			ids.HotCompanyModuleID = companyModuleIDs[0]
		}
	}

	return buf.rows, counts, ids
}

var tupleColumns = []string{"object_type", "object_id", "relation", "subject_type", "subject_id", "subject_relation"}

// Load truncates any prior loadgen output (rows outside the 'vec-' fixture namespace) and
// COPYs the given rows into authz.tuple, via a plain *pgx.Conn acquired from the pool (COPY
// needs a dedicated connection, not pool-shared).
func Load(ctx context.Context, pool *pgxpool.Pool, rows [][]any) (int64, error) {
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return 0, fmt.Errorf("acquire conn for load: %w", err)
	}
	defer conn.Release()

	if _, err := conn.Exec(ctx, `DELETE FROM authz.tuple WHERE object_id NOT LIKE 'vec-%' AND subject_id NOT LIKE 'vec-%'`); err != nil {
		return 0, fmt.Errorf("clear prior loadgen rows: %w", err)
	}
	n, err := conn.Conn().CopyFrom(ctx, pgx.Identifier{"authz", "tuple"}, tupleColumns, pgx.CopyFromRows(rows))
	if err != nil {
		return n, fmt.Errorf("COPY authz.tuple: %w", err)
	}
	return n, nil
}
