// SPDX-License-Identifier: Apache-2.0

// Package version carries the platform's own build identity — Version (the VERSION file's
// contents, e.g. "0.1.0") and Commit (the short git SHA the running binary was built
// from) — both injected at `go build` time via -ldflags (infra/Dockerfile.service's builder
// stage: "-X kiban/internal/version.Version=$(cat VERSION) -X kiban/internal/version.Commit=
// ${KIBAN_COMMIT}"). A `go run`/`go test`/local `go build` invocation without those ldflags
// keeps the defaults below ("dev"/"unknown"). Every cmd/*/main.go and modules/*/service/cmd/
// main.go feeds these straight to internal/obs/metrics.New for the
// kiban_build_info{service,version,commit} gauge — nothing else in this codebase reads them, so
// there is no separate "version API" to keep in sync.
//
// Why ldflags over a runtime env-var/file read: the compiled binary is
// the only artifact infra/Dockerfile.service's runtime-base images ship (COPY --from=builder
// /out/<bin>, never the source tree or the VERSION file itself) — a runtime os.ReadFile of
// VERSION would work under `go run` but silently fail ("file not found") in every container.
// ldflags bake the value in at compile time instead, so the running binary always knows its own
// version regardless of what's mounted/copied at runtime. Commit defaults to "unknown" when a
// build (e.g. `make dev`, `docker compose build`) does not pass the KIBAN_COMMIT build ARG;
// kiban_build_info{commit="unknown"} is then the honest value, not a bug.
package version

var (
	// Version is the platform release version (the VERSION file).
	Version = "dev"
	// Commit is the short git SHA the running binary was built from, or "unknown" when not
	// supplied at build time.
	Commit = "unknown"
)
