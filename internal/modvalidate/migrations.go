// SPDX-License-Identifier: Apache-2.0

package modvalidate

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
)

// ChecksumLedgerFile is the committed lockfile every migrations directory carries
// (`<module>/migrations/checksums.json`, and `migrations/<tree>/checksums.json`
// for the four foundation trees): filename -> sha256 of shipped content. The ledger lists EVERY
// migration file: a changed hash, a ledger entry with no file (deleted or renamed), or a file with
// no ledger entry is a failure. The ledger is refreshed explicitly via WriteChecksumLedger
// (`modvalidate -write-checksums <dir>`) when a new migration is added — a shipped file is never
// rewritten, a new one is appended.
const ChecksumLedgerFile = "checksums.json"

type checksumLedger struct {
	Checksums map[string]string `json:"checksums"`
}

func loadChecksumLedger(migrationsDir string) (checksumLedger, error) {
	path := filepath.Join(migrationsDir, ChecksumLedgerFile)
	data, err := os.ReadFile(path)
	if err != nil {
		return checksumLedger{}, err
	}
	var l checksumLedger
	if err := json.Unmarshal(data, &l); err != nil {
		return checksumLedger{}, fmt.Errorf("%s: %w", path, err)
	}
	if l.Checksums == nil {
		l.Checksums = map[string]string{}
	}
	return l, nil
}

// WriteChecksumLedger (re)writes the checksum ledger for a module's current migration set.
func WriteChecksumLedger(dir string, mod *Module) error {
	return WriteChecksumLedgerDir(filepath.Join(dir, "migrations"), mod.Migrations)
}

// WriteChecksumLedgerDir (re)writes the checksum ledger of a bare migrations directory (a
// foundation tree such as migrations/registry).
func WriteChecksumLedgerDir(migrationsDir string, files []MigrationFile) error {
	l := checksumLedger{Checksums: map[string]string{}}
	for _, mf := range files {
		l.Checksums[mf.Name] = mf.Checksum
	}
	buf, err := json.MarshalIndent(l, "", "  ")
	if err != nil {
		return err
	}
	buf = append(buf, '\n')
	return os.WriteFile(filepath.Join(migrationsDir, ChecksumLedgerFile), buf, 0o644)
}

// LoadMigrationsDir reads every *.sql file of a migrations directory (sorted by name) with its
// sha256. key is the owner used in error attribution (module key or foundation tree name).
func LoadMigrationsDir(key, migrationsDir string) ([]MigrationFile, []ValidationError) {
	entries, err := os.ReadDir(migrationsDir)
	if err != nil {
		return nil, []ValidationError{errf(key, "load-migrations", "%s: %v", migrationsDir, err)}
	}
	var errs []ValidationError
	var names []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		names = append(names, e.Name())
	}
	sort.Strings(names)
	var files []MigrationFile
	for _, name := range names {
		data, err := os.ReadFile(filepath.Join(migrationsDir, name))
		if err != nil {
			errs = append(errs, errf(key, "load-migrations", "%s: %v", name, err))
			continue
		}
		sum := sha256.Sum256(data)
		files = append(files, MigrationFile{Name: name, Contents: data, Checksum: hex.EncodeToString(sum[:])})
	}
	return files, errs
}

// ValidateMigrationsDir runs the artifact-only migration rules (filename shape, strict order,
// ledger completeness and immutability) over a bare migrations directory — the foundation trees'
// gate (`make validate-migrations`). The cross-schema rule table does not apply: foundation trees
// own the shared schemas and roles by design.
func ValidateMigrationsDir(key, migrationsDir string) []ValidationError {
	files, errs := LoadMigrationsDir(key, migrationsDir)
	if len(errs) > 0 {
		return errs
	}
	return validateMigrationLayout(key, migrationsDir, files)
}

// validateMigrations runs every module migrations/ contract rule automatable from the artifacts
// alone: layout + ledger (validateMigrationLayout) and the per-statement cross-schema/unsafe-op
// rule table (sqlscan.go).
func validateMigrations(moduleKey string, dir string, files []MigrationFile) []ValidationError {
	errs := validateMigrationLayout(moduleKey, dir, files)
	for _, mf := range files {
		errs = append(errs, scanMigration(moduleKey, mf)...)
	}
	return errs
}

func validateMigrationLayout(key string, dir string, files []MigrationFile) []ValidationError {
	var errs []ValidationError

	seenNum := map[string]string{} // number -> filename, duplicate-number detection
	var numbersInFileOrder []string
	for _, mf := range files {
		matches := migrationFilenamePattern.FindStringSubmatch(mf.Name)
		if matches == nil {
			errs = append(errs, errf(key, RuleMigrationFilename,
				"migrations/%s: filename must match NNNN_description.sql (lowercase, numeric prefix)", mf.Name))
			continue
		}
		num := matches[1]
		if prev, dup := seenNum[num]; dup {
			errs = append(errs, errf(key, RuleMigrationOrder,
				"migrations: duplicate migration number %s (%s and %s)", num, prev, mf.Name))
		}
		seenNum[num] = mf.Name
		numbersInFileOrder = append(numbersInFileOrder, num)
	}

	sorted := append([]string(nil), numbersInFileOrder...)
	sort.Strings(sorted)
	for i := range sorted {
		if sorted[i] != numbersInFileOrder[i] {
			errs = append(errs, errf(key, RuleMigrationOrder,
				"migrations: filenames are not in strict numeric order (found %v, expected %v)", numbersInFileOrder, sorted))
			break
		}
	}

	ledger, err := loadChecksumLedger(dir)
	if err != nil {
		if os.IsNotExist(err) {
			errs = append(errs, errf(key, RuleMigrationChecksum,
				"migrations: %s is missing — every migrations directory carries a ledger (run `modvalidate -write-checksums <dir>` when a migration is added)", ChecksumLedgerFile))
		} else {
			errs = append(errs, errf(key, RuleMigrationChecksum, "migrations: %v", err))
		}
		return errs
	}
	onDisk := map[string]bool{}
	for _, mf := range files {
		onDisk[mf.Name] = true
		shipped, known := ledger.Checksums[mf.Name]
		if !known {
			errs = append(errs, errf(key, RuleMigrationChecksum,
				"migrations/%s: not recorded in %s — run `modvalidate -write-checksums <dir>` to record the new migration", mf.Name, ChecksumLedgerFile))
			continue
		}
		if shipped != mf.Checksum {
			errs = append(errs, errf(key, RuleMigrationChecksum,
				"migrations/%s: content checksum %s does not match the shipped checksum %s recorded in %s — shipped migrations are immutable, write a new file instead",
				mf.Name, mf.Checksum, shipped, ChecksumLedgerFile))
		}
	}
	for _, name := range slices.Sorted(maps.Keys(ledger.Checksums)) {
		if !onDisk[name] {
			errs = append(errs, errf(key, RuleMigrationChecksum,
				"migrations/%s: recorded in %s but missing on disk — shipped migrations may not be deleted or renamed", name, ChecksumLedgerFile))
		}
	}

	return errs
}
