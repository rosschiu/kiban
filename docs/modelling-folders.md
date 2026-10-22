# Modelling folders: inherited, broken and limited access

A document system asks for three things: a file in a folder is readable by whoever can read
the folder; one folder can stop inheriting from its parent; one person can be given one file.
The first instinct is an exclusion rule ("viewer of the parent, except here"). The model subset
has no exclusion, no conditions and no wildcards, by design. The pattern below needs none of
them, and it is the one the engine evaluates best: every answer is a walk along explicit
tuples.

## The model

Two object types, each with an anchor, a `parent` relation and a `viewer` relation that is
either direct or inherited through the parent:

```json
"relations": {
  "folder": {
    "company_module": { "this": true },
    "parent": { "this": true },
    "viewer": { "union": [
      { "this": true },
      { "tupleToUserset": { "tupleset": "parent", "computedUserset": "viewer" } }
    ] }
  },
  "file": {
    "company_module": { "this": true },
    "parent": { "this": true },
    "viewer": { "union": [
      { "this": true },
      { "tupleToUserset": { "tupleset": "parent", "computedUserset": "viewer" } }
    ] }
  }
}
```

Read the `viewer` rule as: whoever holds `viewer` directly on this object, or holds `viewer`
on whatever this object's `parent` tuple points at. `editor` and `owner` follow the same shape;
they are left out here to keep the tuples short.

## Inheritance is a tuple

A tree is a set of `parent` tuples. Three objects, one grant:

```
folder:root   # viewer @ group:sales#member
folder:q3     # parent @ folder:root
file:plan     # parent @ folder:q3
```

Check "may Alice, a member of Sales, view file:plan": `file:plan#viewer` has no direct tuple
for her; the `parent` tuple leads to `folder:q3`, whose `viewer` has no direct tuple either; its
`parent` leads to `folder:root`, where `viewer @ group:sales#member` matches. Allowed. Every
check binds to the company through the anchors, as always.

## Breaking inheritance

To stop `folder:q3` inheriting from `root`, delete the edge and copy what should survive:

1. Revoke `folder:q3 # parent @ folder:root`.
2. Grant on `folder:q3` the direct viewers that should keep access, for example
   `folder:q3 # viewer @ group:sales#member` if Sales stays, or a narrower subject if not.

Nothing else changes. `file:plan` still points at `folder:q3`, so it inherits from `q3` and from
nothing above it. There is no "except" anywhere: a broken folder is simply a folder whose
`parent` tuple is gone. Your application copies the grants it wants to keep, which is also the
moment to show the user what they are keeping.

Re-attaching is the reverse: grant the `parent` tuple again and revoke the copies you no longer
want.

## Limited access

One person, one file, nothing above it:

```
file:plan # viewer @ user:<bob's subject>
```

Bob is not in Sales and cannot see `folder:q3` or `root`. The check on `file:plan` matches the
direct tuple before it ever walks a parent. Revoking that one tuple removes the access. The same
works for a position (`position:<id>#holder`) or a group.

## When the parent moves

Moving `file:plan` from `q3` to `q4` is two tuple writes in one grant call and one revoke:

1. Grant `file:plan # parent @ folder:q4`.
2. Revoke `file:plan # parent @ folder:q3`.

Nothing on the file's own `viewer` relation changes. Direct grants (Bob's) travel with the file;
inherited access follows the new parent from the next check onward. Do the grant before the
revoke so no check in between sees a file with no parent.

Moving a folder moves its whole subtree the same way, with one `parent` tuple, because every
descendant reaches it through its own `parent` chain.

## Depth and cycles

The engine follows `parent` chains up to 32 levels and refuses deeper trees with
`DEPTH_EXCEEDED`, which is a denial. A cycle (a folder whose chain reaches itself) contributes
nothing to its own answer and is not an error; your application should still refuse to create
one.

## What this gives up

A rule such as "everyone in Sales except Carol" cannot be written. Model the exception the
other way round: give the folder a group that excludes Carol, or grant the people who should
see it directly. Exclusion is a property of your groups and your grants, not of the model, and
that keeps every decision a walk along tuples your audit trail already records.
