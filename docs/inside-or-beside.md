# Module inside or app beside

Teams arriving from an out-of-process authorizer read that Kiban writes a grant in the same
transaction as the audit row and conclude they can drop their own consistency layer. That is
true for one of the two shapes an integration can take, and not for the other. This page says
which, what each gives up, and the pattern for the common case.

## The two shapes

| | Module inside Kiban | App beside Kiban |
|---|---|---|
| Where it runs | Compiled into the platform, routed by the gateway, its schema in Kiban's Postgres | Its own process, its own database, any language |
| How it writes a grant | A SQL write in the same transaction as its own row and the audit event | `POST /api/auth/grants` over HTTP, after or before its own commit |
| Consistency with its own data | Atomic: the row and the tuple exist together or not at all | Two systems, two commits: a failure between them leaves one without the other |
| What it gives up | Any language but Go; a release cycle tied to Kiban's; `docs/building.md`'s contract | Atomicity between its rows and its tuples |
| Who should pick it | A contributor extending the platform, the four samples | Almost every application |

The four sample modules are the first shape. [Integrate your app](integrate.md) is the second,
and it is the one to choose unless you are extending Kiban itself.

## What "same transaction" covers, and what it does not

Inside Kiban, every mutation and its audit event commit together, and a module's grant is one
of those mutations. The guarantee is between Kiban's own tables.

An app beside Kiban still gets that guarantee for Kiban's side: a grant request either writes
every tuple it names and the ledger rows, or nothing. What Kiban cannot promise is anything
about your database. Your transaction and the grant request are two commits, and the process
can die between them.

## The pattern for an app beside Kiban

Two facts make this simple:

- A grant is idempotent. Granting a tuple that already exists writes nothing and answers `200`;
  the same for revoking one that is gone. Repeating a grant is always safe.
- A check denies while the tuple is missing. A row without its tuple is invisible to its
  intended readers, never visible to the wrong ones. So the safe order is to make the tuple
  exist before the row is reachable, and to clean the tuple up after the row is gone.

Creating an object:

1. Choose the object id yourself (a UUID), before anything is written.
2. Grant the anchor and the first relations in one call, with that id.
3. Commit your own row.

If step 3 fails, Kiban holds tuples for an object that does not exist. They grant access to
nothing, since there is no row to serve. Revoke the anchor when you notice, or leave them for
the sweep below; anchoring the same id again starts from nothing either way.

If the process dies between 2 and 3, the same applies. If it dies before 2 completes, nothing
exists on either side.

Deleting an object:

1. Delete your row, or mark it deleted.
2. Revoke the anchor. Every other tuple on the object goes with it in the same transaction.

If step 2 fails, the tuples outlive the row; they grant access to nothing. The sweep removes
them.

Granting and revoking a share on an existing object:

- Grant first, then record the share in your database if you keep a copy. A failure after the
  grant leaves access that your UI does not show; the sweep below reconciles it.
- For a revoke, record the removal first, then revoke. A failure after the record leaves access
  the UI no longer shows, until the sweep.

The reconciliation sweep:

A periodic job walks your rows and re-issues the grants they imply, and revokes the anchors of
ids your database no longer has. Because grants are idempotent, the job can run as often as you
like and needs no state of its own: for each row, `grant(anchor + relations)`; for each anchor
you know you created and whose row is gone, `revoke(anchor)`. Keep the set of ids you created
somewhere, a column or a log, so the job knows what to revoke. The sweep is the whole
consistency layer; it replaces nothing you would have needed for Kiban's own side.

If you keep no copy of shares in your database and treat Kiban as the only truth for who may
see what, the sweep reduces to the delete case: revoke anchors of ids that no longer exist.

## What to tell a reviewer

"Kiban is consistent with itself in one transaction. Our rows and Kiban's tuples are two
commits; we grant before the row exists and revoke after it is gone, so a crash in between
leaves tuples that grant nothing, and a sweep re-issues idempotent grants and revokes orphan
anchors." That is the honest sentence; it is shorter than the consistency layer it replaces.
