// SPDX-License-Identifier: Apache-2.0

// Command modvalidate is the module-artifact validator: it loads one or more module
// directories, validates every artifact against the module contract's reject list, and exits
// non-zero on the first batch that has any named error. Wired as `make validate-modules`
// (validates modules/*/) and into `make check`. A directory with no module.manifest.json is
// treated as a bare migrations tree (migrations/registry etc. — `make validate-migrations`):
// only the filename/order/ledger rules apply there.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/rosschiu/kiban/internal/modvalidate"
)

func isModuleDir(dir string) bool {
	_, err := os.Stat(filepath.Join(dir, "module.manifest.json"))
	return err == nil
}

func runModvalidate(args []string) int {
	fs := flag.NewFlagSet("modvalidate", flag.ContinueOnError)
	catalogPath := fs.String("catalog", "", "optional external catalog snapshot JSON (cross-catalog duplicate and dependency checks against modules outside this batch)")
	writeChecksums := fs.String("write-checksums", "", "write/refresh the migration checksum ledger for the named module directory (or bare migrations directory), then exit (no validation run)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: dev modvalidate [-catalog snapshot.json] [-write-checksums dir] <module-dir|migrations-dir> [...]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}

	if *writeChecksums != "" {
		dir := filepath.Clean(*writeChecksums)
		var err error
		var n int
		if isModuleDir(dir) {
			mod, loadErrs := modvalidate.LoadModule(dir)
			if mod == nil {
				for _, e := range loadErrs {
					fmt.Fprintln(os.Stderr, e.Error())
				}
				return 1
			}
			n, err = len(mod.Migrations), modvalidate.WriteChecksumLedger(dir, mod)
		} else {
			files, loadErrs := modvalidate.LoadMigrationsDir(filepath.Base(dir), dir)
			if len(loadErrs) > 0 {
				for _, e := range loadErrs {
					fmt.Fprintln(os.Stderr, e.Error())
				}
				return 1
			}
			n, err = len(files), modvalidate.WriteChecksumLedgerDir(dir, files)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "write-checksums: %v\n", err)
			return 1
		}
		fmt.Printf("wrote checksum ledger for %s (%d migrations)\n", dir, n)
		return 0
	}

	dirs := fs.Args()
	if len(dirs) == 0 {
		fs.Usage()
		return 2
	}

	snapshot, err := modvalidate.LoadCatalogSnapshot(*catalogPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}

	var modules []*modvalidate.Module
	var trees []string
	exitCode := 0
	for _, dir := range dirs {
		clean := filepath.Clean(dir)
		if !isModuleDir(clean) {
			key := filepath.Base(clean)
			trees = append(trees, key)
			for _, e := range modvalidate.ValidateMigrationsDir(key, clean) {
				fmt.Println(e.Error())
				exitCode = 1
			}
			continue
		}
		mod, loadErrs := modvalidate.LoadModule(clean)
		for _, e := range loadErrs {
			fmt.Println(e.Error())
			exitCode = 1
		}
		if mod == nil {
			continue
		}
		modules = append(modules, mod)
	}

	if len(modules) > 0 {
		errs := modvalidate.ValidateBatch(modules, snapshot)
		sort.Slice(errs, func(i, j int) bool {
			if errs[i].ModuleKey != errs[j].ModuleKey {
				return errs[i].ModuleKey < errs[j].ModuleKey
			}
			return errs[i].Rule < errs[j].Rule
		})
		for _, e := range errs {
			fmt.Println(e.Error())
		}
		if len(errs) > 0 {
			exitCode = 1
		}
	}

	if exitCode == 0 {
		names := make([]string, 0, len(modules))
		for _, m := range modules {
			names = append(names, m.ModuleKey)
		}
		fmt.Printf("modvalidate: PASS (%d module(s): %v; %d migration tree(s): %v)\n", len(modules), names, len(trees), trees)
	} else {
		fmt.Println("modvalidate: FAIL")
	}
	return exitCode
}
