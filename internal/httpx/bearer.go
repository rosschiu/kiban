// SPDX-License-Identifier: Apache-2.0

package httpx

import (
	"strings"

	"github.com/lestrrat-go/jwx/v3/jwt"
)

// SubjectFromBearer returns the `sub` claim of an "Authorization: Bearer <jwt>" value WITHOUT
// verifying the signature, or "" when absent/malformed. It exists for audit ATTRIBUTION only:
// callers must already have had the bearer verified by the authz decision (or the gateway)
// before acting on it — this helper never grants anything, it only names the actor in audit
// rows so they stop reading "unauthenticated".
func SubjectFromBearer(rawBearer string) string {
	const prefix = "Bearer "
	if !strings.HasPrefix(rawBearer, prefix) {
		return ""
	}
	tok := strings.TrimSpace(strings.TrimPrefix(rawBearer, prefix))
	if tok == "" {
		return ""
	}
	parsed, err := jwt.ParseInsecure([]byte(tok))
	if err != nil {
		return ""
	}
	sub, ok := parsed.Subject()
	if !ok {
		return ""
	}
	return sub
}

// ActorFor derives the audited actor for a mutation: the server-derived subject when the
// handler has one, else the bearer's `sub` claim (record-keeping ONLY — the authorization
// decision has already been made by the time an actor string is needed), else "unauthenticated".
func ActorFor(subject, rawBearer string) string {
	if subject != "" {
		return subject
	}
	if sub := SubjectFromBearer(rawBearer); sub != "" {
		return sub
	}
	return "unauthenticated"
}
