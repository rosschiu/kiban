// SPDX-License-Identifier: Apache-2.0

// Package licensetext embeds the canonical full-text license bodies a module manifest's license
// class may declare. internal/modvalidate hashes a module's own LICENSE file against these for an
// exact identity check, so a manifest cannot declare one SPDX id while shipping a different
// license text. go:embed cannot reach outside its own package directory, which is why this small
// package sits next to the files it embeds rather than under internal/modvalidate.
package licensetext

import _ "embed"

// Apache20 is the canonical foundation-class and open-class (Apache-2.0 choice) license text
// (identical to /LICENSE and every modules/*/LICENSE; see internal/modvalidate/license.go's
// identity check).
//
//go:embed Apache-2.0.txt
var Apache20 []byte

// MIT is the canonical open-class (MIT choice) license text.
//
//go:embed MIT.txt
var MIT []byte
