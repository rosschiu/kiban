<!--
Thanks for the pull request. CONTRIBUTING.md describes the process; this checklist is the last
step before review.
-->

## What and why

<!-- What does this change, and why does it matter? Link the issue it addresses. -->

## Checklist

- [ ] `make check` passes locally (format, vet, unit and integration tests, web checks, module
      validation, coverage ratchet, licence checks, docs freshness, secret scan). CI runs the
      same targets.
- [ ] `make test` passes if this change affects behaviour (the fuller suite, including the
      authorization differential harness).
- [ ] Tests assert real outcomes, not just execute lines.
- [ ] No coverage minimum in `coverage/ratchet.json` was lowered.
- [ ] The documentation site source is updated where the change affects users, operators, or
      module developers.
- [ ] No licence-header violations (`make license-check`) and no new dependency with an
      incompatible licence (`make license-scan`). See `LICENSING.md` if unsure which licence
      applies.
- [ ] No secrets committed.
- [ ] Generated files (`docs/api/`, `docs/sdk/`, sqlc output) were regenerated, not hand-edited.
