// SPDX-License-Identifier: Apache-2.0

package fragment

import (
	"context"

	"github.com/rosschiu/kiban/internal/authz/engine"
)

// Check answers a relation check against a Loaded effective model, with disabled-module inertness: an object type
// that no known fragment (active or not) ever declared is a genuine UNKNOWN_TYPE error
// (fail-closed, same as the raw engine); an object type that IS declared by some fragment but
// whose module is currently unknown/disabled (so it never made it into l.Model) answers false —
// never errors, never allows. A type present in l.Model is checked normally by the engine.
func Check(ctx context.Context, en *engine.Engine, l Loaded, objType, objID, rel, subjType, subjID string) (bool, error) {
	if _, ok := l.Model[objType]; !ok {
		if l.AllowedTypes[objType] {
			// Known to a module fragment, but that module isn't currently active/known —
			// disabled-module inertness: false, not an error.
			return false, nil
		}
		// Not declared anywhere — let the engine's own fail-closed UNKNOWN_TYPE error surface.
	}
	engineWithModel := &engine.Engine{Pool: en.Pool, Model: l.Model}
	return engineWithModel.Check(ctx, objType, objID, rel, subjType, subjID)
}
