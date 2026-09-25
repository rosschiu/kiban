// SPDX-License-Identifier: Apache-2.0

// Package docsartifacts embeds the module's contract artifacts that a Go binary needs at compile
// time. The registry's install path needs the authz.fragment.json bytes to seed
// authz.model_fragment, and cmd/registry's container has no filesystem access to modules/ at
// runtime. The embed sits next to the artifact file so there is exactly one copy.
package docsartifacts

import _ "embed"

//go:embed authz.fragment.json
var AuthzFragmentJSON []byte

// ManifestJSON is the module's module.manifest.json bytes, embedded for the same reason as
// AuthzFragmentJSON above. The registry's builtinModules literal reads version and metadata from
// this embed instead of hand-copying them, so they cannot drift from the manifest.
//
//go:embed module.manifest.json
var ManifestJSON []byte
