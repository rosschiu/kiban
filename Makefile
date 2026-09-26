# Neutral entry points — every contributor and CI uses these, never tool-specific commands.
# Wire each target to real commands as the stack solidifies. A target that isn't
# wired yet must fail loudly, not pass silently.

.PHONY: vulncheck setup dev dev-down dev-clean public-up images-preflight images images-quickstart images-devcert images-all pin-images test-stack-up test-stack-down test check fmt migrate-registry migrate-identity migrate-org migrate-authz migrate-notification migrate-timesheet migrate-docs migrate-helpdesk bench-authz test-harness web-check coverage-gate coverage-report validate-modules validate-migrations ratchet-guard license-check license-scan secret-scan docs-api docs-sdk docs docs-freshness-check docs-site quickstart-compose

# VERSION defaults from the VERSION file (`v` + its contents, e.g. "v0.1.0") so `make images`
# needs no argument on a normal release cut; `make images VERSION=v0.1.0-rc2` overrides it for an
# ad hoc build. KIBAN_IMAGE_TAG is the SEPARATE knob `make dev`/`make public-up` read to select
# pre-built images instead of building from source — see infra/compose.yaml's per-service
# `image:` keys.
VERSION ?= v$(shell cat VERSION)

setup: ## verify/report the host toolchain (docker+compose required; go/node/npm reported), scaffold .env (write-once) + infra/secrets-in/
	@./infra/setup.sh

dev: ## bring up the full stack (postgres + keycloak + migrate + bootstrap + the gateway edge + registry/identity/org/authz); set KIBAN_IMAGE_TAG=vX.Y.Z to run FROM images `make images` already built, instead of building from source
	@# Dev mode is never public mode — drop the marker `make public-up` writes so
	@# live-tagged test helpers and infra/e2e-*.sh / modules/*/curl-proof.sh stop refusing to run.
	@rm -f infra/.public-mode
	@# The one-time superadmin's initial password (secrets never live in env-visible places,
	@# so it's a 0600 FILE bootstrap's compose service bind-mounts — never .env).
	@# Generated once, idempotently (never overwrites an existing file), so this
	@# stays a single command with no manual step.
	@mkdir -p infra/secrets-in
	@[ -f infra/secrets-in/superadmin-password ] || { umask 077 && openssl rand -base64 24 > infra/secrets-in/superadmin-password; }
	@chmod 600 infra/secrets-in/superadmin-password
	$(if $(KIBAN_IMAGE_TAG),$(MAKE) images-preflight,)
	docker compose --env-file .env --project-directory infra up -d $(if $(KIBAN_IMAGE_TAG),--no-build,--build) --wait
	docker compose --env-file .env --project-directory infra ps

dev-down: ## stop the deployment skeleton, preserving volumes
	docker compose --env-file .env --project-directory infra down

dev-clean: ## stop the deployment skeleton and remove volumes
	@# See `dev`'s own comment — a clean dev stack is never public mode either.
	@rm -f infra/.public-mode
	docker compose --env-file .env --project-directory infra down -v

public-up: ## bring the stack up behind the HOST's shared Traefik edge at https://$$KIBAN_PUBLIC_HOST (required; KIBAN_PUBLIC_NETWORK selects the edge network); set KIBAN_IMAGE_TAG=vX.Y.Z to deploy FROM images `make images` already built, instead of building from source
	@# See infra/compose.public.yaml's own header comment: overrides the gateway to the
	@# dev-HTTP listener the shared Traefik forwards
	@# to, and points bootstrap at the public origin so the realm client's redirect URIs/web
	@# origins include it.
	@mkdir -p infra/secrets-in
	@[ -f infra/secrets-in/superadmin-password ] || { umask 077 && openssl rand -base64 24 > infra/secrets-in/superadmin-password; }
	@chmod 600 infra/secrets-in/superadmin-password
	$(if $(KIBAN_IMAGE_TAG),$(MAKE) images-preflight,)
	docker compose --env-file .env -f infra/compose.yaml -f infra/compose.public.yaml --project-directory infra up -d $(if $(KIBAN_IMAGE_TAG),--no-build,--build) --wait
	docker compose --env-file .env -f infra/compose.yaml -f infra/compose.public.yaml --project-directory infra run --rm bootstrap
	docker compose --env-file .env -f infra/compose.yaml -f infra/compose.public.yaml --project-directory infra ps
	@# Mark public mode so live-tagged test helpers and infra/e2e-*.sh /
	@# modules/*/curl-proof.sh refuse to run against this deployment (`make dev`/`make dev-clean`
	@# remove this marker; see their own comments).
	@touch infra/.public-mode

# The nine first-party app-service images `make images` builds and `KIBAN_IMAGE_TAG` deploys from.
# Image builds need no secrets: pass the environment file only when it exists (a release
# runner has none).
ENV_FILE_IF_PRESENT := $(if $(wildcard .env),--env-file .env,)
APP_SERVICES := registry identity org authz gateway notification timesheet docs helpdesk

# images-preflight: when deploying FROM tagged images (KIBAN_IMAGE_TAG set), every image must
# already exist locally — otherwise Compose would silently BUILD a missing one from whatever source
# is checked out (services carry both `build:` and `image:`), defeating "deploy a specific version".
# Fail closed, name the missing image.
#
# Also checks migrate/bootstrap/keycloak (QUICKSTART_SERVICES) and gateway-devcert
# (DEVCERT_SERVICE), which infra/compose.yaml tags too, so a `KIBAN_IMAGE_TAG=vX make dev`/`make
# public-up` needs `make images-all VERSION=vX` (all 13) run first.
images-preflight:
	@test -n "$(KIBAN_IMAGE_TAG)" || { echo "images-preflight: KIBAN_IMAGE_TAG is not set" >&2; exit 1; }
	@missing=""; for s in $(APP_SERVICES) $(QUICKSTART_SERVICES) $(DEVCERT_SERVICE); do \
	  docker image inspect "kiban-$$s:$(KIBAN_IMAGE_TAG)" >/dev/null 2>&1 || missing="$$missing kiban-$$s:$(KIBAN_IMAGE_TAG)"; \
	done; \
	if [ -n "$$missing" ]; then echo "images-preflight: missing local image(s):$$missing — run \`make images-all VERSION=$(KIBAN_IMAGE_TAG)\` first (or check the tag)" >&2; exit 1; fi; \
	echo "images-preflight: all $(words $(APP_SERVICES) $(QUICKSTART_SERVICES) $(DEVCERT_SERVICE)) images present for $(KIBAN_IMAGE_TAG)"

images: ## build+tag every app-service image kiban-<service>:$(VERSION) (default: v<VERSION file>), stamping the short git SHA into kiban_build_info{commit}
	@echo "images: building kiban-{registry,identity,org,authz,gateway,notification,timesheet,docs,helpdesk}:$(VERSION) at commit $(shell git rev-parse --short HEAD)"
	KIBAN_IMAGE_TAG=$(VERSION) KIBAN_COMMIT=$(shell git rev-parse --short HEAD) \
	  docker compose $(ENV_FILE_IF_PRESENT) --project-directory infra -f infra/compose.yaml build \
	    $(APP_SERVICES)
	@echo "images: done — deploy them with e.g. \`KIBAN_IMAGE_TAG=$(VERSION) make public-up\` (no rebuild)"

# The one-shot jobs the zero-clone quickstart needs as published images too (deploy/
# quickstart/docker-compose.yml has no `build:` blocks at all — a zero-clone user cannot build
# them). Kept as a SEPARATE target from `images` (not folded into APP_SERVICES) so `images`/
# `images-preflight`'s existing 9-service contract for `KIBAN_IMAGE_TAG` deploys is untouched —
# this target is additive, called by `images-all` and by release.yml directly.
# `gateway-devcert` is not part of it: the quickstart runs the gateway in insecure-HTTP mode (no
# TLS cert needed at all — see deploy/quickstart/README.md). It is its own target below so a
# `KIBAN_IMAGE_TAG` deploy of the TLS `make dev` shape never builds it from the checkout either.
QUICKSTART_SERVICES := migrate bootstrap keycloak
DEVCERT_SERVICE := gateway-devcert

images-quickstart: ## build+tag kiban-{migrate,bootstrap,keycloak}:$(VERSION) — the one-shot jobs deploy/quickstart's zero-clone compose file needs as GHCR images
	@echo "images-quickstart: building kiban-{migrate,bootstrap,keycloak}:$(VERSION) at commit $(shell git rev-parse --short HEAD)"
	KIBAN_IMAGE_TAG=$(VERSION) KIBAN_COMMIT=$(shell git rev-parse --short HEAD) \
	  docker compose $(ENV_FILE_IF_PRESENT) --project-directory infra -f infra/compose.yaml build \
	    $(QUICKSTART_SERVICES)
	@echo "images-quickstart: done"

images-devcert: ## build+tag kiban-gateway-devcert:$(VERSION) — the self-signed dev-cert one-shot `make dev` (TLS shape) needs; not used by the quickstart or k8s
	KIBAN_IMAGE_TAG=$(VERSION) docker compose $(ENV_FILE_IF_PRESENT) --project-directory infra -f infra/compose.yaml build $(DEVCERT_SERVICE)

images-all: images images-quickstart images-devcert ## the full 13-image set release.yml pushes to GHCR (9 app services + migrate/bootstrap/keycloak + gateway-devcert)

pin-images: ## refresh the @sha256 digest pin on every third-party base image (Dockerfiles, compose, k8s postgres) to the tag's current index digest — scripts/pin-images.sh; run `make quickstart-compose` after
	./scripts/pin-images.sh

docs-site: ## build the public documentation site (MkDocs Material, pinned in docs/requirements.txt) into the gitignored docs-site-build/ — the generated docs/api + docs/sdk trees are served as static reference pages; the root CHANGELOG.md is copied in as the changelog page
	@python3 -m venv .venv-docs >/dev/null
	@.venv-docs/bin/pip install -q -r docs/requirements.txt
	@sed -E 's#\]\(([A-Z][A-Z0-9_.-]*(\.md)?)\)#](https://github.com/rosschiu/kiban/blob/main/\1)#g' CHANGELOG.md > docs/changelog.md
	.venv-docs/bin/mkdocs build --strict -f mkdocs.yml -d docs-site-build

test-stack-up: ## bring up an ISOLATED test stack (project `kiban-test`, separate volumes + host ports) — never the `kiban` project `make dev`/`make public-up` manage
	@test -f .env || { echo ".env not found — copy .env.example and fill it in first" >&2; exit 1; }
	@# .env.test is .env with the four host-published ports remapped to values that
	@# don't collide with the `kiban` project (127.0.0.1:5434/8081/8443/8090) or other commonly
	@# published local ports. Every
	@# other value (DB/Keycloak passwords, realm name, ...) is reused as-is — this is a throwaway
	@# test database/realm, not a secrecy boundary from the dev stack's own secrets.
	@awk 'BEGIN{FS=OFS="="} /^POSTGRES_HOST_PORT=/{print "POSTGRES_HOST_PORT","15434";next} /^KEYCLOAK_HOST_PORT=/{print "KEYCLOAK_HOST_PORT","18081";next} {print}' .env > .env.test
	@# 18443/18080/18091/18085/18444 are already reserved by cmd/gateway/main_test.go's own
	@# host-run-gateway test convention (a DIFFERENT kind of test — a bare `go run`, not this
	@# compose container) — 18543 avoids that whole range.
	@grep -q '^KIBAN_GATEWAY_TLS_HOST_PORT=' .env.test || echo 'KIBAN_GATEWAY_TLS_HOST_PORT=18543' >> .env.test
	@grep -q '^KIBAN_GATEWAY_HTTP_HOST_PORT=' .env.test || echo 'KIBAN_GATEWAY_HTTP_HOST_PORT=18100' >> .env.test
	@# The test stack always runs the four sample modules: their live tests, curl proofs and
	@# the shell e2e suites are the module contract's proof.
	@sed -i '/^COMPOSE_PROFILES=/d; /^KIBAN_INSTALLED_MODULES=/d' .env.test
	@printf 'COMPOSE_PROFILES=samples\nKIBAN_INSTALLED_MODULES=notification,timesheet,docs,helpdesk\n' >> .env.test
	@# The bootstrap service always requires the one-time superadmin password FILE at
	@# infra/secrets-in/superadmin-password; on a fresh checkout (no prior `make dev`) bootstrap
	@# would otherwise fail with "SuperadminUsername/SuperadminPassword required".
	@# Same idempotent, write-once generation as `dev`'s own.
	@mkdir -p infra/secrets-in
	@[ -f infra/secrets-in/superadmin-password ] || { umask 077 && openssl rand -base64 24 > infra/secrets-in/superadmin-password; }
	@chmod 600 infra/secrets-in/superadmin-password
	docker compose -p kiban-test --env-file .env.test -f infra/compose.yaml -f infra/compose.test.yaml --project-directory infra up -d --build --wait
	docker compose -p kiban-test --env-file .env.test -f infra/compose.yaml -f infra/compose.test.yaml --project-directory infra ps

test-stack-down: ## tear down the isolated test stack AND its volumes (throwaway by design)
	docker compose -p kiban-test --env-file .env.test -f infra/compose.yaml -f infra/compose.test.yaml --project-directory infra down -v

test: ## full test suite (incl. the authz differential harness) — targets the isolated test stack (`make test-stack-up` first)
	@test -f .env.test || { echo ".env.test not found — run \`make test-stack-up\` first" >&2; exit 1; }
	set -a; . ./.env.test; set +a; go test -race -p 1 ./...
	$(MAKE) test-harness

GOVULNCHECK_VERSION := v1.8.0
vulncheck: ## fail on any reachable known vulnerability in the toolchain or dependencies
	go run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) ./...

check: ## fast gate: lint + typecheck/vet + unit tests (CI runs this) — targets the isolated test stack (`make test-stack-up` first)
	test -z "$$(gofmt -l .)"
	go vet ./...
	$(MAKE) vulncheck
	@test -f .env.test || { echo ".env.test not found — run \`make test-stack-up\` first" >&2; exit 1; }
	set -a; . ./.env.test; set +a; go test -p 1 ./...
	$(MAKE) web-check
	$(MAKE) validate-modules
	$(MAKE) validate-migrations
	$(MAKE) ratchet-guard
	$(MAKE) coverage-gate
	$(MAKE) license-check
	$(MAKE) license-scan
	$(MAKE) docs-freshness-check
	$(MAKE) secret-scan

secret-scan: ## gitleaks full-history + uncommitted-working-tree secret scan (.gitleaks.toml). gitleaks is a go.mod `tool` dependency (like tern/sqlc above) — `go tool gitleaks` builds/caches it locally on first use, no sudo/system install
	@if ! go tool gitleaks version >/dev/null 2>&1; then \
		echo "secret-scan: gitleaks unavailable via \`go tool gitleaks\` — it is declared in go.mod's tool block (added via \`go get -tool github.com/zricethezav/gitleaks/v8@v8.21.2\`), so this should only fail with no network access to the Go module proxy; see go.mod/go.sum. Never install with sudo." >&2; \
		exit 1; \
	fi
	@echo "secret-scan: full git history..." >&2
	go tool gitleaks git --config .gitleaks.toml
	@echo "secret-scan: uncommitted working-tree changes (git diff)..." >&2
	go tool gitleaks git --config .gitleaks.toml --pre-commit
	@echo "secret-scan: PASS — no leaks in history or the uncommitted working tree" >&2

license-check: ## SPDX header sweep (Go/TS/TSX/SQL/shell first-party files) per LICENSING.md's zone map; `-fix` inserts missing headers (see tools/licensecheck)
	go run ./tools/licensecheck/cmd

license-scan: ## third-party dependency license scan (Go via go-licenses, npm via license-checker) — fails on GPL/AGPL/SSPL in any distributed component
	./scripts/license-scan.sh

ratchet-guard: ## coverage/ratchet.json may only ever increase a scope's min, never decrease (or remove a scope) relative to HEAD — mechanical, not review-only
	go run ./tools/ratchetguard/cmd

validate-modules: ## module artifact validator (static, no live stack needed) over every modules/*/ directory
	go run ./cmd/modvalidate modules/*/

validate-migrations: ## foundation migration trees (migrations/*/): filename/order rules + checksums.json ledger completeness and immutability (static; `go run ./cmd/modvalidate -write-checksums migrations/<tree>` records a new file)
	go run ./cmd/modvalidate migrations/*/

web-check: ## web/sdk + web/shell gate — npm ci + typecheck + unit tests + build (no live stack needed)
	cd web && npm ci && npm run -w sdk typecheck && npm run -w sdk test && npm run -w sdk build
	cd web && npm run -w shell typecheck && npm run -w shell test && npm run -w shell build

docs-api: ## bundle every modules/*/openapi.yaml + internal/gateway/platform-openapi.yaml into standalone, offline-viewable HTML under docs/api/ (Redocly build-docs + local redoc.standalone.js inlining, see scripts/build-api-docs.mjs)
	cd web && npm ci
	node scripts/build-api-docs.mjs --out docs/api

docs-sdk: ## typedoc over web/sdk/src into docs/sdk/ (fails on any undocumented exported symbol — web/sdk/typedoc.json's requiredToBeDocumented gate), plus the SDK recipe catalog
	cd web && npm ci && npm run -w sdk docs
	cp web/sdk/RECIPES.md docs/sdk/recipes.md

docs: docs-api docs-sdk ## regenerate the full generated docs tree (API reference + SDK reference)

docs-freshness-check: ## regenerate docs/api, docs/sdk and the quickstart compose into a temp dir and diff against the committed files — fails if any has drifted from its source
	@rm -rf /tmp/kiban-docs-freshness
	@mkdir -p /tmp/kiban-docs-freshness/api /tmp/kiban-docs-freshness/sdk
	node scripts/build-api-docs.mjs --out /tmp/kiban-docs-freshness/api
	cd web/sdk && npx typedoc --out /tmp/kiban-docs-freshness/sdk
	cp web/sdk/RECIPES.md /tmp/kiban-docs-freshness/sdk/recipes.md
	./scripts/gen-quickstart-compose.sh > /tmp/kiban-docs-freshness/docker-compose.yml
	diff -rq docs/api /tmp/kiban-docs-freshness/api
	diff -rq docs/sdk /tmp/kiban-docs-freshness/sdk
	diff -u deploy/quickstart/docker-compose.yml /tmp/kiban-docs-freshness/docker-compose.yml
	@rm -rf /tmp/kiban-docs-freshness
	@echo "docs-freshness-check: docs/api, docs/sdk and deploy/quickstart/docker-compose.yml match their sources"

quickstart-compose: ## regenerate deploy/quickstart/docker-compose.yml from infra/compose.yaml (scripts/gen-quickstart-compose.sh; docs-freshness-check diffs it)
	./scripts/gen-quickstart-compose.sh > deploy/quickstart/docker-compose.yml

coverage-gate: ## coverage ratchet — fails if any scope drops below coverage/ratchet.json's min (needs the isolated test stack, `make test-stack-up`, not `make dev`)
	@test -f .env.test || { echo ".env.test not found — run \`make test-stack-up\` first" >&2; exit 1; }
	set -a; . ./.env.test; set +a; ./scripts/coverage-gate.sh gate

coverage-report: ## same scope table as coverage-gate, plus gap-to-floor, never fails
	@test -f .env.test || { echo ".env.test not found — run \`make test-stack-up\` first" >&2; exit 1; }
	set -a; . ./.env.test; set +a; ./scripts/coverage-gate.sh report

fmt: ## auto-format (gofmt over every tracked .go file; web/ has no formatter script or prettier dependency, so TS is not formatted here)
	gofmt -l -w $$(git ls-files '*.go')

# migrate-* targets run against the HOST-published Postgres port (127.0.0.1:$POSTGRES_HOST_PORT
# — KIBAN_DB_HOST/KIBAN_DB_PORT). `make dev`'s own `migrate` compose service applies
# the identical migrations against the compose-internal postgres:5432 instead — see
# infra/compose.yaml and infra/migrate-entrypoint.sh.
#
# Per-target table: migrations dir (tern.conf lives inside it) and the role-password step that
# runs after tern. registry sets the four foundation roles (migrations/registry/0001_roles.sql
# creates them; bootstrap execs the same wrapper); each module target sets its own role, which
# migrations/registry/00NN_<module>_role.sql created — so `make migrate-registry` runs first.
# identity/org/authz have no step: migrate-registry already set their passwords. Order: registry,
# authz, identity, org (authz before identity — see infra/migrate-entrypoint.sh).
MIGRATE_TARGETS := migrate-registry migrate-authz migrate-identity migrate-org migrate-notification migrate-timesheet migrate-docs migrate-helpdesk
MIGRATE_DIR_registry     := migrations/registry
MIGRATE_DIR_identity     := migrations/identity
MIGRATE_DIR_org          := migrations/org
MIGRATE_DIR_authz        := migrations/authz
MIGRATE_DIR_notification := modules/notification/migrations
MIGRATE_DIR_timesheet    := modules/timesheet/migrations
MIGRATE_DIR_docs         := modules/docs/migrations
MIGRATE_DIR_helpdesk     := modules/helpdesk/migrations
MIGRATE_PW_registry      := ./migrations/registry/set-role-passwords.sh
MIGRATE_PW_notification  := ./scripts/set-role-password.sh kiban_notification KIBAN_NOTIFICATION_DB_PASSWORD
MIGRATE_PW_timesheet     := ./scripts/set-role-password.sh kiban_timesheet KIBAN_TIMESHEET_DB_PASSWORD
MIGRATE_PW_docs          := ./scripts/set-role-password.sh kiban_docs KIBAN_DOCS_DB_PASSWORD
MIGRATE_PW_helpdesk      := ./scripts/set-role-password.sh kiban_helpdesk KIBAN_HELPDESK_DB_PASSWORD

# A literal newline (make folds backslash-newline inside a $(if ...) into one shell line; this
# keeps the password step on its own continuation line like the tern step).
define MIGRATE_NL


endef

$(MIGRATE_TARGETS): migrate-%: ## migrate-{registry,identity,org,authz,notification,timesheet,docs,helpdesk}: apply that service's/module's migrations (tern) + set its DB role password(s) where the table above says so
	set -a; . ./.env; set +a; \
	KIBAN_DB_HOST=127.0.0.1 KIBAN_DB_PORT=$$POSTGRES_HOST_PORT go tool tern migrate -m $(MIGRATE_DIR_$*) -c $(MIGRATE_DIR_$*)/tern.conf$(if $(MIGRATE_PW_$*),; \$(MIGRATE_NL)KIBAN_DB_HOST=127.0.0.1 KIBAN_DB_PORT=$$POSTGRES_HOST_PORT $(MIGRATE_PW_$*))

bench-authz: ## authz benchmark: 1M-tuple dataset, concurrent batchCan gate — targets the isolated test stack
	@test -f .env.test || { echo ".env.test not found — run \`make test-stack-up\` first" >&2; exit 1; }
	set -a; . ./.env.test; set +a; go test -tags bench ./internal/authz/bench/ -run TestBench -v -timeout 20m

test-harness: ## authz differential harness vs a real OpenFGA container (skips loudly if Docker is absent) — targets the isolated test stack
	@test -f .env.test || { echo ".env.test not found — run \`make test-stack-up\` first" >&2; exit 1; }
	set -a; . ./.env.test; set +a; go test -tags harness ./internal/authz/harness/ -v -timeout 15m
