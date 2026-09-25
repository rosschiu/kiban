// SPDX-License-Identifier: Apache-2.0

package httpx

import (
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwt"
)

func unsignedToken(t *testing.T, sub string) string {
	t.Helper()
	b := jwt.NewBuilder()
	if sub != "" {
		b = b.Subject(sub)
	}
	tok, err := b.Build()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := jwt.Sign(tok, jwt.WithInsecureNoSignature())
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestSubjectFromBearer(t *testing.T) {
	cases := map[string]string{
		"":                                    "",
		"Basic abc":                           "",
		"Bearer ":                             "",
		"Bearer not-a-jwt":                    "",
		"Bearer " + unsignedToken(t, ""):      "",
		"Bearer " + unsignedToken(t, "kc-42"): "kc-42",
	}
	for in, want := range cases {
		if got := SubjectFromBearer(in); got != want {
			t.Errorf("SubjectFromBearer(%q) = %q, want %q", in, got, want)
		}
	}
}
