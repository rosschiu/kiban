// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// runK8sCheck is `make k8s-check`: renders the Kustomize tree without a cluster, on a scratch
// copy so the real overlays' gitignored secret files are never touched.
//
//  1. the base alone renders and contains NO Secret, so it is usable as a remote base;
//  2. each shipped overlay, with a generated secret, renders exactly one `kiban-secrets`, and
//     every namespaced resource lands in `kiban`: the base's `namespace:` covers only the
//     base's own resources, so an overlay Secret without one lands in the kubeconfig's
//     current namespace and every pod waits on it (the 0.1.1 regression);
//  3. the 0.1.0 upgrade path: a Secret left in base/ is moved by gen-secrets.sh, not regenerated;
//  4. an overlay in the shipped shape but outside the tree (one kept in another repository)
//     renders against the base with its own Secret, in the namespace.
func runK8sCheck(args []string) int {
	if len(args) > 0 {
		fmt.Fprintln(os.Stderr, "usage: dev k8s-check")
		return 2
	}
	if _, err := output("", "kubectl", "version", "--client"); err != nil {
		return fail("k8s-check", errors.New("kubectl not on PATH"))
	}
	work, err := os.MkdirTemp("", "kiban-k8s-check-")
	if err != nil {
		return fail("k8s-check", err)
	}
	defer os.RemoveAll(work)
	k8s := filepath.Join(work, "k8s")
	if err := copyTree("deploy/k8s", k8s); err != nil {
		return fail("k8s-check", err)
	}
	_ = os.Remove(filepath.Join(k8s, "base", "secret.yaml"))
	for _, ov := range []string{"kind", "production"} {
		_ = os.Remove(filepath.Join(k8s, "overlays", ov, "secret.yaml"))
	}

	render := func(dir string) ([]map[string]any, error) {
		out, err := output("", "kubectl", "kustomize", dir)
		if err != nil {
			return nil, err
		}
		var docs []map[string]any
		dec := yaml.NewDecoder(bytes.NewReader(out))
		for {
			var d map[string]any
			if err := dec.Decode(&d); err != nil {
				if errors.Is(err, io.EOF) {
					break
				}
				return nil, fmt.Errorf("parse kustomize output of %s: %w", dir, err)
			}
			if d != nil {
				docs = append(docs, d)
			}
		}
		return docs, nil
	}
	secrets := func(docs []map[string]any) int {
		n := 0
		for _, d := range docs {
			if d["kind"] == "Secret" && metaName(d) == "kiban-secrets" {
				n++
			}
		}
		return n
	}
	outsideNamespace := func(docs []map[string]any) []string {
		var bad []string
		for _, d := range docs {
			if d["kind"] == "Namespace" {
				continue
			}
			meta, _ := d["metadata"].(map[string]any)
			if meta["namespace"] != "kiban" {
				bad = append(bad, fmt.Sprintf("%v/%v", d["kind"], meta["name"]))
			}
		}
		return bad
	}
	genSecrets := func(overlay string) error {
		_, err := output("", filepath.Join(k8s, "gen-secrets.sh"), overlay)
		return err
	}

	// 1. base
	docs, err := render(filepath.Join(k8s, "base"))
	if err != nil {
		return fail("k8s-check", err)
	}
	if n := secrets(docs); n != 0 {
		return fail("k8s-check", fmt.Errorf("base renders %d kiban-secrets Secret(s); it must carry none", n))
	}
	// 2. shipped overlays
	for _, ov := range []string{"kind", "production"} {
		if err := genSecrets(ov); err != nil {
			return fail("k8s-check", fmt.Errorf("gen-secrets.sh %s: %w", ov, err))
		}
		if _, err := os.Stat(filepath.Join(k8s, "overlays", ov, "secret.yaml")); err != nil {
			return fail("k8s-check", fmt.Errorf("gen-secrets.sh %s wrote nothing", ov))
		}
		docs, err := render(filepath.Join(k8s, "overlays", ov))
		if err != nil {
			return fail("k8s-check", err)
		}
		if n := secrets(docs); n != 1 {
			return fail("k8s-check", fmt.Errorf("overlay %s renders %d kiban-secrets Secret(s), want 1", ov, n))
		}
		if bad := outsideNamespace(docs); len(bad) > 0 {
			return fail("k8s-check", fmt.Errorf("overlay %s renders resources outside the kiban namespace: %s", ov, strings.Join(bad, " ")))
		}
	}
	// 3. 0.1.0 upgrade path
	_ = os.Remove(filepath.Join(k8s, "overlays", "kind", "secret.yaml"))
	marker := "apiVersion: v1\nkind: Secret\nmetadata:\n  name: kiban-secrets\nstringData:\n  MARKER: \"from-0.1.0\"\n"
	if err := os.WriteFile(filepath.Join(k8s, "base", "secret.yaml"), []byte(marker), 0o600); err != nil {
		return fail("k8s-check", err)
	}
	if err := genSecrets("kind"); err != nil {
		return fail("k8s-check", fmt.Errorf("gen-secrets.sh kind (upgrade path): %w", err))
	}
	moved, _ := os.ReadFile(filepath.Join(k8s, "overlays", "kind", "secret.yaml"))
	if !bytes.Contains(moved, []byte("from-0.1.0")) {
		return fail("k8s-check", errors.New("gen-secrets.sh did not move the 0.1.0 base secret"))
	}
	if _, err := os.Stat(filepath.Join(k8s, "base", "secret.yaml")); err == nil {
		return fail("k8s-check", errors.New("the 0.1.0 base secret was copied, not moved"))
	}
	// 4. remote-shaped overlay
	remote := filepath.Join(work, "remote")
	if err := os.MkdirAll(remote, 0o755); err != nil {
		return fail("k8s-check", err)
	}
	kust := "apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\nresources:\n  - ../k8s/base\n  - secret.yaml\n"
	if err := os.WriteFile(filepath.Join(remote, "kustomization.yaml"), []byte(kust), 0o644); err != nil {
		return fail("k8s-check", err)
	}
	example, err := os.ReadFile(filepath.Join(k8s, "base", "secret.example.yaml"))
	if err != nil {
		return fail("k8s-check", err)
	}
	if err := os.WriteFile(filepath.Join(remote, "secret.yaml"), example, 0o600); err != nil {
		return fail("k8s-check", err)
	}
	docs, err = render(remote)
	if err != nil {
		return fail("k8s-check", err)
	}
	if n := secrets(docs); n != 1 {
		return fail("k8s-check", fmt.Errorf("remote-shaped overlay renders %d kiban-secrets Secret(s), want 1", n))
	}
	if bad := outsideNamespace(docs); len(bad) > 0 {
		return fail("k8s-check", fmt.Errorf("remote-shaped overlay renders resources outside the kiban namespace: %s", strings.Join(bad, " ")))
	}
	fmt.Println("k8s-check: PASS: base has no Secret; kind, production and a remote-shaped overlay each render one, every resource in the kiban namespace")
	return 0
}

func metaName(d map[string]any) string {
	meta, _ := d["metadata"].(map[string]any)
	n, _ := meta["name"].(string)
	return n
}

// copyTree copies a directory recursively, preserving file modes (gen-secrets.sh stays executable).
func copyTree(src, dst string) error {
	return filepath.Walk(src, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, info.Mode().Perm())
	})
}
