// SPDX-License-Identifier: Apache-2.0

package modulekit

import "testing"

func TestAuthzClient_AnchorTuple(t *testing.T) {
	c := NewAuthzClient(nil, "http://authz", "docs")
	got := c.AnchorTuple("docs_document", "doc-1", "co-1")
	want := Tuple{ObjectType: "docs_document", ObjectID: "doc-1", Relation: "company_module", SubjectType: "company_module", SubjectID: "co-1/docs"}
	if got != want {
		t.Fatalf("AnchorTuple = %+v, want %+v", got, want)
	}
}
