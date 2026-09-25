# Contributing to Kiban

Thanks for your interest. This page describes how changes are made and checked in this
repository. It reflects how the project actually works, not an aspiration. The fuller version,
with setup steps and the conventions that matter, is the documentation's
[Contributing](https://rosschiu.github.io/kiban/contributing/) page.

## Before you write code

1. Read the [documentation](https://rosschiu.github.io/kiban/), in particular *Concepts*,
   *Building on Kiban*, and *Known limitations*.
2. Open an issue first for anything beyond a small fix. A pull request that adds a substantial
   feature with no prior discussion will be redirected to an issue, not merged as-is. Small,
   clearly-scoped fixes (a typo, a broken test, a doc correction) need no issue.
3. Check open issues and pull requests so you are not duplicating work in flight.

## Making the change

- Keep changes small and complete. The repository stays runnable and the gates stay green after
  every commit.
- Write tests with the code, not after. Every behaviour change needs a test; every service
  boundary (an HTTP endpoint, a database constraint, a cross-service call, an auth flow) needs at
  least one integration test against the real stack, not a mock.
- Never hand-edit generated files: sqlc output, `docs/api/`, `docs/sdk/`. They regenerate from
  `make docs`, and `make check` fails if they drift.
- Never weaken authentication, authorization, or audit behaviour. If you believe a change there
  is right, explain it in the issue first.
- Use the vocabulary in the documentation's *Glossary* in code, comments, and API fields.

## Gates

```
make test-stack-up   # once: an isolated Compose project (kiban-test) with its own ports and volumes
make check           # format, vet, unit and integration tests, web checks, module validation, coverage ratchet, licence and secret scans
make test            # the fuller suite, including the OpenFGA differential authorization harness
```

`make check` is what CI runs on every push and pull request, by calling exactly these targets.
`make test` is required whenever behaviour changed. `make help` lists every target.

### Coverage ratchet

Coverage minimums are tiered by risk: 95% for security-critical packages (the authorization
engine and decision layers, the gateway's token, guard and proxy paths, identity, audit,
bootstrap's realm and seed code, the SDK's session code) and 80% elsewhere. Minimums in
`coverage/ratchet.json` may rise, never fall; CI checks this mechanically. Coverage must come
from tests that assert real behaviour. Assertion-free padding is rejected in review.

## Commits and pull requests

Commits use `type(scope): summary` in the imperative mood (`fix(gateway): …`,
`docs(sdk): …`). Keep each commit a reviewable unit with no unrelated edits. Documentation
changes are commits too.

Use the pull request template's checklist: gates green, tests behavioural, generated docs
regenerated, licence headers present.

## Licensing of contributions

Every first-party file in this repository is Apache-2.0, and so is your contribution; see
`LICENSING.md`. A new module declares its licence class in its manifest, and `make license-check`
verifies that the module's `LICENSE` file matches.

Whether outside contributions need a Developer Certificate of Origin sign-off or a contributor
licence agreement is not settled yet. Until it is, ask in your issue before submitting a large
change from outside the core team.

## Bugs, features, vulnerabilities

Use the issue templates for bugs and feature requests. Security vulnerabilities never go
through public issues; see `SECURITY.md`.
