// SPDX-License-Identifier: Apache-2.0

//go:build harness

package harness

import (
	"fmt"
	"math/rand"
)

// smallLoadgen builds a much smaller-scale version of internal/authz/bench's dataset shapes —
// the harness only needs enough diversity for 5,000 checks to exercise every relation path,
// not the bench's 1M-tuple perf-testing scale. Every tuple here uses a plain "user" direct
// subject (never a userset subject), so every tuple is writable into OpenFGA without hitting
// the DSL's bracket restrictions (see translate.go's doc comment).
type smallLoadgen struct {
	Seed              int64
	Companies         int
	MembersPerCompany int
	RolesPerCompany   int
	BizPerCompany     int
	HotIndex          int
	HotMembers        int
	HotBiz            int
}

var defaultSmallLoadgen = smallLoadgen{
	Seed: 7, Companies: 20, MembersPerCompany: 30, RolesPerCompany: 12, BizPerCompany: 40,
	HotIndex: 19, HotMembers: 150, HotBiz: 300,
}

var smallModuleKeys = []string{"m1", "m2", "m3"}
var smallRoleRelations = []string{"editor", "submitter", "approver", "viewer"}

type smallIDs struct {
	HotCompanyID      string
	HotCompanyAdminID string
	HotBizIDs         []string
	HotGrantees       []string
	OtherCompanyBiz   []string
}

// Generate returns tuples in the same [][6]string shape both loaders (Postgres COPY, OpenFGA
// write) can consume directly.
func (lg smallLoadgen) Generate() ([][6]string, smallIDs) {
	rng := rand.New(rand.NewSource(lg.Seed))
	var rows [][6]string
	var ids smallIDs
	add := func(ot, oid, rel, st, sid, srel string) { rows = append(rows, [6]string{ot, oid, rel, st, sid, srel}) }

	for ci := 0; ci < lg.Companies; ci++ {
		companyID := fmt.Sprintf("hc%03d", ci)
		adminUser := companyID + "/admin"
		add("company", companyID, "admin", "user", adminUser, "")

		isHot := ci == lg.HotIndex
		members, biz := lg.MembersPerCompany, lg.BizPerCompany
		if isHot {
			members, biz = lg.HotMembers, lg.HotBiz
		}

		cms := make([]string, len(smallModuleKeys))
		for mi, mk := range smallModuleKeys {
			cm := companyID + "/" + mk
			cms[mi] = cm
			add("company_module", cm, "company", "company", companyID, "")
		}
		for r := 0; r < lg.RolesPerCompany; r++ {
			cm := cms[r%len(cms)]
			rel := smallRoleRelations[r%len(smallRoleRelations)]
			user := fmt.Sprintf("%s/role-%d", companyID, r)
			add("company_module", cm, rel, "user", user, "")
		}
		for mi := 0; mi < members; mi++ {
			memberID := fmt.Sprintf("%s/mem-%04d", companyID, mi)
			cm := cms[rng.Intn(len(cms))]
			add("member", memberID, "company_module", "company_module", cm, "")
			add("member", memberID, "mapped_user", "user", memberID+"/user", "")
		}
		for bi := 0; bi < biz; bi++ {
			bizID := fmt.Sprintf("%s/te-%04d", companyID, bi)
			cm := cms[rng.Intn(len(cms))]
			add("timesheet_entry", bizID, "company_module", "company_module", cm, "")
			grantee := bizID + "/grantee"
			add("timesheet_entry", bizID, "viewer", "user", grantee, "")
			if isHot && bi%7 == 0 {
				ids.HotBizIDs = append(ids.HotBizIDs, bizID)
				ids.HotGrantees = append(ids.HotGrantees, grantee)
			}
			if !isHot && ci == 0 && bi < 20 {
				ids.OtherCompanyBiz = append(ids.OtherCompanyBiz, bizID)
			}
		}
		if isHot {
			ids.HotCompanyID = companyID
			ids.HotCompanyAdminID = adminUser
		}
	}
	return rows, ids
}
