// SPDX-License-Identifier: Apache-2.0
package modvalidate

import (
	"os"
	"path/filepath"
	"strings"

	licensetext "github.com/rosschiu/kiban/licenses"
)

// canonicalLicenseText maps a canonical SPDX id (licenseClassAllowedSPDX's values, manifest.go)
// to the exact license body a module's own LICENSE file must byte-match (a loose substring match
// such as "Apache License" alone would let a wrong SPDX id pass). These are go:embed'd from
// licenses/*.txt at the repo root — see licenses/embed.go's own doc comment for why that package
// lives there rather than under this one.
var canonicalLicenseText = map[string][]byte{
	"Apache-2.0": licensetext.Apache20,
	"MIT":        licensetext.MIT,
}

// normalizeLicenseText trims leading/trailing whitespace and normalizes line endings so a
// harmless CRLF/trailing-newline difference is never mistaken for a real drift between a
// module's LICENSE file and the canonical text — validation is about catching real class/text
// mismatches, not policing whitespace.
func normalizeLicenseText(b []byte) string {
	s := strings.ReplaceAll(string(b), "\r\n", "\n")
	return strings.TrimSpace(s)
}

// validateLicenseFile implements the license-file-class-mismatch rule: every module directory must carry its own LICENSE file, that
// file's content must be an EXACT identity match (SPDX-id-line present implicitly, since it's
// part of the canonical text, plus a whitespace-normalized full-text match — not just a loose
// substring) against the canonical text for the manifest's declared, canonically-valid
// license.spdx (manifest.go's licenseClassAllowedSPDX already rejects a class/spdx combination
// that isn't canonical before this ever runs). Wired into both `make license-check` and
// `make validate-modules` (ValidateModule below) so the check is never bypassable by running one
// gate without the other.
func validateLicenseFile(moduleKey, dir string, lic ManifestLicense) []ValidationError {
	if lic.Class == "" {
		// license-class-invalid (manifest.go) already reports this; don't double-report here.
		return nil
	}

	path := filepath.Join(dir, "LICENSE")
	data, err := os.ReadFile(path)
	if err != nil {
		return []ValidationError{errf(moduleKey, RuleLicenseFileClassMismatch,
			"%s: missing (module.manifest.json declares license.class %q)", path, lic.Class)}
	}

	canonical, ok := canonicalLicenseText[lic.SPDX]
	if !ok {
		// license-spdx-invalid (manifest.go) already reports the unknown/non-canonical spdx
		// value; without a canonical text to compare against, there is nothing more to check here.
		return nil
	}

	if normalizeLicenseText(data) != normalizeLicenseText(canonical) {
		return []ValidationError{errf(moduleKey, RuleLicenseFileClassMismatch,
			"%s: does not byte-match the canonical %s license text (licenses/%s.txt) — module.manifest.json declares license.class %q, license.spdx %q",
			path, lic.SPDX, lic.SPDX, lic.Class, lic.SPDX)}
	}
	return nil
}
