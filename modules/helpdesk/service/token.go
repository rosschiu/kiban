// SPDX-License-Identifier: Apache-2.0

package helpdesk

import (
	"context"

	"github.com/rosschiu/kiban/modulekit"
)

// NewTokenVerifier wires modulekit's bearer verifier under this module's error prefix.
func NewTokenVerifier(ctx context.Context, jwksURL, issuer, audience string) (*modulekit.TokenVerifier, error) {
	return modulekit.NewTokenVerifier(ctx, jwksURL, issuer, audience, "helpdesk")
}
