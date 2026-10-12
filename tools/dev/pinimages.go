// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
)

// pinnedFiles hold every `FROM <ref>` and `image: <ref>` that names a third-party image.
var pinnedFiles = []string{
	"infra/Dockerfile.service",
	"infra/keycloak-build/Dockerfile",
	"deploy/k8s/demo-reset/Dockerfile",
	"infra/compose.yaml",
	"deploy/k8s/base/postgres.yaml",
}

var (
	imageRefLine = regexp.MustCompile(`^(FROM|[[:space:]]*image:)[[:space:]]+([^[:space:]]+)`)
	digestSuffix = regexp.MustCompile(`@sha256:[0-9a-f]*$`)
	sha256Digest = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

// runPinImages is `make pin-images`: every third-party base image reference is rewritten to
// `<ref>@sha256:<digest>`, the tag's current multi-arch index digest from `docker buildx
// imagetools inspect`. First-party `kiban-*` images, `${...}`-templated refs and build-stage
// names (no tag) are left alone. The tag stays as the human-readable intent; the digest is
// what gets pulled. Run `make quickstart-compose` afterwards to carry the postgres pin over.
func runPinImages(args []string) int {
	if len(args) > 0 {
		fmt.Fprintln(os.Stderr, "usage: dev pin-images")
		return 2
	}
	refs := map[string]bool{}
	contents := map[string]string{}
	for _, f := range pinnedFiles {
		data, err := os.ReadFile(f)
		if errors.Is(err, os.ErrNotExist) {
			continue // an optional file (deploy/k8s/demo-reset is not in every checkout)
		}
		if err != nil {
			return fail("pin-images", err)
		}
		contents[f] = string(data)
		for _, line := range strings.Split(contents[f], "\n") {
			m := imageRefLine.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			ref := digestSuffix.ReplaceAllString(m[2], "")
			if !strings.Contains(ref, ":") || strings.HasPrefix(ref, "kiban-") || strings.Contains(ref, "${") {
				continue
			}
			refs[ref] = true
		}
	}
	sorted := make([]string, 0, len(refs))
	for r := range refs {
		sorted = append(sorted, r)
	}
	sort.Strings(sorted)
	for _, ref := range sorted {
		out, err := output("", "docker", "buildx", "imagetools", "inspect", ref, "--format", "{{.Manifest.Digest}}")
		if err != nil {
			return fail("pin-images", err)
		}
		digest := strings.TrimSpace(string(out))
		if !sha256Digest.MatchString(digest) {
			return fail("pin-images", fmt.Errorf("no digest for %s: %s", ref, digest))
		}
		for _, f := range pinnedFiles {
			if _, ok := contents[f]; !ok {
				continue
			}
			lines := strings.Split(contents[f], "\n")
			for i, line := range lines {
				if !imageRefLine.MatchString(line) {
					continue
				}
				if idx := strings.Index(line, ref); idx >= 0 {
					rest := digestSuffixAny.ReplaceAllString(line[idx+len(ref):], "")
					lines[i] = line[:idx] + ref + "@" + digest + rest
				}
			}
			contents[f] = strings.Join(lines, "\n")
		}
		fmt.Printf("pin-images: %s@%s\n", ref, digest)
	}
	for _, f := range pinnedFiles {
		if _, ok := contents[f]; !ok {
			continue
		}
		if err := os.WriteFile(f, []byte(contents[f]), 0o644); err != nil {
			return fail("pin-images", err)
		}
	}
	return 0
}

// digestSuffixAny strips a digest that directly follows the matched ref (anywhere in the rest
// of the line), the counterpart of the shell version's `sub(/^@sha256:[0-9a-f]*/, "", rest)`.
var digestSuffixAny = regexp.MustCompile(`^@sha256:[0-9a-f]*`)
