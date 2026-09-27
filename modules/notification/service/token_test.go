// SPDX-License-Identifier: Apache-2.0

package notification

import (
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rosschiu/kiban/modulekit/kittest"
)

// testIssuer adapts modulekit/kittest's JWKS issuer to the names this package's tests use.
type testIssuer struct {
	*kittest.Issuer
	jwksServer *httptest.Server
}

func newTestIssuer(t *testing.T) *testIssuer {
	i := kittest.NewIssuer(t)
	return &testIssuer{Issuer: i, jwksServer: i.JWKS}
}

func (ti *testIssuer) sign(t *testing.T, issuer, audience, sub string, exp time.Time) string {
	return ti.Sign(t, issuer, audience, sub, exp)
}

const (
	testIssuerName = "test-issuer"
	testAudience   = "kiban-api"
)
