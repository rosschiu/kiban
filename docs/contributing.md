# Contributing

This page describes how changes are made and checked in the
[repository](https://github.com/rosschiu/kiban). It reflects how the project works, not an
aspiration. `CONTRIBUTING.md` in the repository is the short form of the same rules.

## Set up

You need Linux on x86_64, Docker Engine with the Compose plugin, `make`, Go and Node for the
tools that run outside containers, and Python 3 for the documentation site.

```
make setup           # checks docker, writes .env with generated secrets (once), creates infra/secrets-in/
make dev             # builds and starts the full stack, waits until every container is healthy
make test-stack-up   # once: an isolated Compose project (kiban-test) with its own ports and volumes
make check           # the gate CI runs on every push and pull request
```

`make dev` gives you a running deployment at `https://127.0.0.1:8443` to try things against;
`make test-stack-up` gives the tests their own stack, so a test run never touches your
development data. `make help` lists every target.

## Before you write code

1. Read [Concepts](concepts.md), [Building on Kiban](building.md) and
   [Known limitations](limitations.md).
2. Open an issue first for anything beyond a small fix. A pull request that adds a substantial
   feature with no prior discussion will be redirected to an issue. A typo, a broken test or a
   documentation correction needs no issue.
3. Check open issues and pull requests so you are not duplicating work in flight.

## Branches and pull requests

Work on a branch and open a pull request against `main`. Keep each pull request one reviewable
unit with no unrelated edits; several small pull requests are easier to review than one large
one. Commits use `type(scope): summary` in the imperative mood (`fix(gateway): …`,
`docs(sdk): …`). Documentation changes are commits too.

The pull request template's checklist is the last step before review: gates green, tests
behavioural, no coverage minimum lowered, generated files regenerated, licence headers present,
no secrets, documentation updated where the change affects users, operators or module
developers. `CODEOWNERS` routes the review to the maintainer.

## The gates

```
make check   # format, vet, vulnerability check, unit and integration tests, web checks,
             # module and migration validation, coverage ratchet, licence and secret scans,
             # docs freshness
make test    # the fuller suite, including the OpenFGA differential authorization harness
```

CI runs exactly these targets. `make check` must pass on every pull request; `make test` is
required whenever behaviour changed. Both need the isolated test stack.

Coverage minimums are tiered by risk: 95% for security-critical packages (the authorization
engine and decision layers, the gateway's token, guard and proxy paths, identity, audit, the
bootstrap realm and seed code, the SDK's session code) and 80% elsewhere. The minimums in
`coverage/ratchet.json` may rise, never fall, and CI checks this mechanically. Coverage must come
from tests that assert real behaviour; assertion-free padding is rejected in review.

## Conventions that matter

- **Small, complete changes.** The repository stays runnable and the gates stay green after
  every commit.
- **Tests with the code.** Every behaviour change needs a test. Every service boundary (an HTTP
  endpoint, a database constraint, a cross-service call, an auth flow) needs at least one
  integration test against the real stack, not a mock.
- **Licence headers.** Every first-party Go, TypeScript, SQL and shell file starts with an
  `SPDX-License-Identifier` line matching its directory's licence; `make license-check` sweeps
  for missing or wrong headers and `go run ./tools/licensecheck/cmd -fix` inserts them.
- **Migrations are ledgered.** A migration touches only its own schema and is listed with its
  checksum in its tree's ledger (`go run ./cmd/modvalidate -write-checksums modules/<key>/` for
  a module); `make validate-migrations` parses every statement and refuses the dangerous shapes
  (see [Building on Kiban](building.md)).
- **The module contract is the interface.** A module ships a manifest, an authorization
  fragment, an OpenAPI file, checksummed migrations and optional UI routes, and passes
  `make validate-modules`. It never reaches into another module's schema or redefines the base
  authorization model.
- **Generated files are not hand-edited.** sqlc output, `docs/api/`, `docs/sdk/` and the
  quickstart compose file regenerate from `make docs`; `make check` fails if they drift.
- **Authentication, authorization and audit are never weakened.** If you believe a change there
  is right, explain it in the issue first.
- **Vocabulary.** Use the terms in the [glossary](glossary.md) in code, comments and API fields.

## Reporting security issues

Security vulnerabilities never go through public issues. Use GitHub's private vulnerability
reporting on the repository, as described in
[`SECURITY.md`](https://github.com/rosschiu/kiban/blob/main/SECURITY.md) and on the
[Security](security.md) page.

## Licensing of contributions

Every first-party file in the repository is Apache-2.0, and so is a contribution; see
[`LICENSING.md`](https://github.com/rosschiu/kiban/blob/main/LICENSING.md). A new module
declares its licence class in its manifest, and `make license-check` verifies that the module's
`LICENSE` file matches.

Whether outside contributions need a Developer Certificate of Origin sign-off or a contributor
licence agreement is not settled yet. Until it is, ask in your issue before submitting a large
change from outside the core team.
