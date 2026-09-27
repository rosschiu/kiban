// SPDX-License-Identifier: Apache-2.0

// Package notificationartifacts embeds notification's module-contract artifacts that a Go binary
// needs at compile time (the registry's install path needs the module's authz.fragment.json bytes
// to seed authz.model_fragment, and cmd/registry's container has no filesystem access to modules/
// at runtime). Co-located with the artifact file itself so there is exactly one copy — go:embed
// can't reach outside its own package directory, which is why this small package exists here
// rather than a hand-copy under cmd/registry.
package notificationartifacts

import _ "embed"

//go:embed authz.fragment.json
var AuthzFragmentJSON []byte

// ManifestJSON is the module's module.manifest.json bytes, embedded for the same reason as
// AuthzFragmentJSON above: cmd/registry's container has no filesystem access to modules/ at
// runtime, and the registry's builtinModules literal must not hand-copy version/metadata that
// can drift from the manifest; sourcing from this embed makes that drift structurally impossible
// instead of relying on a human to keep two literals in sync.
//
//go:embed module.manifest.json
var ManifestJSON []byte
