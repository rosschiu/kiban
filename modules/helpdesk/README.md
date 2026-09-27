# helpdesk module

Module key: `helpdesk`.

The helpdesk module shows role tiers and assignment. Any active company member (the reporter)
can raise a ticket. An agent works it and an admin administers the module: three role tiers, one
workflow. It uses a different authz idiom from DocShare's per-file model. `helpdesk.tickets.work`
and `helpdesk.manage` are plain company_module tier checks (member/editor/admin), never per-ticket
tuples. Who can see a ticket, and who can change its status, is decided by service-logic
comparisons against the ticket's reporter and assignee (see the header comment in
`service/store.go`).

A ticket, or the company-wide agent tier, can be bound to one of three targets:

- a **member**: that person works the ticket or holds the tier;
- a **position**: whoever currently holds that position works the ticket or holds the tier.
  This is resolved at read time through authz's object-mode `can` for `position:<id>#holder`
  and is never snapshotted into a row;
- a **group**: every current member of the group works the ticket or holds the tier (many
  people, unlike a position's single holder). This is resolved through
  `AuthzClient.IsGroupMember` (`group:<id>#member`).

## Layout

- `module.manifest.json`, `authz.fragment.json`, `openapi.yaml`, `migrations/`: the module's
  contract artifacts.
- `service/`: the Go HTTP service (`cmd/` entrypoint, `http.go` routing and handlers, `store.go`
  data access, and `authzclient.go`/`orgclient.go`/`notificationclient.go`, thin wrappers over `modulekit`'s clients for the
  platform's service-to-service APIs).
- `frontend/frontend.manifest.json`: the routes/nav contract artifact. The React source lives
  under `web/shell/src/modules/helpdesk/`, because the shell has no remote module loading yet
  (the DocShare, notification and timesheet modules work the same way).

## Authorization model

Two authorization idioms:

1. **Tier checks** (`helpdesk.tickets.create`/`helpdesk.tickets.work`/`helpdesk.manage`):
   `company_module#member`/`#editor`/`#admin` on the caller, via `AuthzClient.Can`. The
   `#editor` (agent) tier can be held three ways. It can be held directly (`@ user:<kcSub>`, the
   member path). It can be held through a bound position's current holder
   (`@ position:<id>#holder`), so a successor inherits the position's access with zero permission
   edits on handover. Or it can be held through a bound group's current members
   (`@ group:<id>#member`): every current member holds the tier at the same time, with zero
   permission edits as membership changes.
2. **Per-ticket visibility and status transitions**: plain row comparisons in `store.go`/`http.go`
   (the caller's kcSub against the reporter/assignee), plus an object-mode check when the assignee
   isn't a plain member. `AuthzClient.IsPositionHolder` or `AuthzClient.IsGroupMember` answers
   "does the caller currently hold this ticket's assigned position, or belong to its assigned
   group?" The service never duplicates an org lookup and never decides from the read-side
   `helpdesk.agent` or ticket index alone; the authorization engine is the source of truth.

A ticket has at most one of `assignee_member_id`, `assignee_position_id` and `assignee_group_id`
(enforced by migrations 0005 and 0007). A position or group must already be bound as a helpdesk
agent (`POST /agents` with `{positionId}` or `{groupId}`) before a ticket can be assigned to it.
Otherwise the request fails with 422; assigning one ticket never binds the target as a side
effect.

`GET .../assignable-positions` and `GET .../assignable-groups` are both gated on
`helpdesk.manage`. They are the module's own reads of its agent-bound positions and groups that
don't require a superadmin (the group read returns a member count, not a single holder). The
assign sheet's Positions/Groups tabs and the Agents admin page's holder names use them.

Assigning a ticket to a group notifies every current member who has a linked user. The members
are looked up at send time through an org service-to-service read,
`GET /internal/org/groups/{id}/members`. This is the one real behavioral difference from a
position, where only the single holder is notified.

## Running it

Run `make migrate-helpdesk` after `make migrate-registry` (which creates the `kiban_helpdesk`
role). Then `make dev` or `make test-stack-up` starts the `helpdesk` compose service with the rest
of the stack.

## Testing

- `go test ./modules/helpdesk/...`: Go tests, against a migrated stack (see
  `service/dbtest_env_test.go`). `group_agent_test.go` and `group_ticket_assignment_test.go`
  cover group binding and group assignment.
- `npm run -w shell test`: frontend unit tests in `web/shell/test/modules/helpdesk/`.
- `npm run -w shell e2e`: the full journeys. `web/shell/e2e/helpdesk.spec.ts` runs the
  three-user workflow, and `web/shell/e2e/walkthrough.spec.ts` rehearses the demo script,
  including a position-assignment handover. Nothing exercises group assignment through the real
  UI yet.
