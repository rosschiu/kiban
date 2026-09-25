# DocShare module

Module key: `docs`.

DocShare shows fine-grained, per-file sharing. A file is a title plus a markdown body. Its creator
owns it and can share it with individual company members as `viewer` or `editor`. Every read and
write goes through the authorization engine's object-mode check on `docs_document:<id>`. The local
`docs.share` table is only a read-side index and never decides access (see the header comment in
`service/store.go`). There is deliberately **no** relation bridge from a file's viewer/editor tier
to `company_module#admin`, so a file nobody shared with you stays unreadable, even to the platform
superadmin (see the `_comment` in `authz.fragment.json`).

## Layout

- `module.manifest.json`, `authz.fragment.json`, `openapi.yaml`, `migrations/`: the module's
  contract artifacts.
- `service/`: the Go HTTP service (`cmd/` entrypoint, `http.go` routing and handlers, `store.go`
  data access, and `authzclient.go`/`orgclient.go`/`notificationclient.go`, thin wrappers over `modulekit`'s clients for the
  platform's service-to-service APIs).
- `frontend/frontend.manifest.json`: the routes/nav contract artifact. The React source lives
  under `web/shell/src/modules/docs/`, because the shell has no remote module loading yet (the
  notification and timesheet modules work the same way).

## Authorization model

The fragment declares one object type, `docs_document`, with `owner`/`editor`/`viewer` relations
(an owner is also an editor, and an editor is also a viewer) and a `company_module` tupleset
pointer. `docs.manage` (module-level: audit trail, orphan cleanup) and `docs.create`
(membership-gated) never grant read access to file content; `authz.fragment.json`'s `_comment`
explains why.

## Running it

Run `make migrate-docs` after `make migrate-registry` (which creates the `kiban_docs` role in
`migrations/registry/0010_docs_role.sql` and `0011_docs_audit_usage.sql`). Then `make dev` or
`make test-stack-up` starts the `docs` compose service with the rest of the stack.

## Testing

- `go test ./modules/docs/...`: Go tests, against a migrated stack (see
  `service/dbtest_env_test.go`).
- `npm run -w shell test`: frontend unit tests in `web/shell/test/modules/docs/`.
- `npm run -w shell e2e`: the full two-user Playwright journey in `web/shell/e2e/docs.spec.ts`.
