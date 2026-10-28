# Modelling practices

One rule covers most questions teams bring: **structure in the model, policy in the data.**

The model is the vocabulary: which object types exist, which relations they have, how a
relation derives from another. An app sets it in its fragment at registration, and changes it
by registering again, which is superadmin work, like changing a schema. Policy is who holds
what, and every piece of it is a tuple your app grants and revokes at runtime through the
grants route, with no administrator involved. When a question sounds like "can the model
change at runtime", the answer is almost always "that is not a model change".

## A role matrix is tuples

A Director edits "which deal role may do what" on a page, live. That is not a model change.

Model, fixed at registration:

```json
"deal": {
  "company_module": { "this": true },
  "role": { "this": true },
  "viewer":   { "union": [ { "this": true }, { "tupleToUserset": { "tupleset": "role", "computedUserset": "member" } } ] },
  "editor":   { "union": [ { "this": true }, { "tupleToUserset": { "tupleset": "role", "computedUserset": "member" } } ] },
  "approver": { "union": [ { "this": true }, { "tupleToUserset": { "tupleset": "role", "computedUserset": "member" } } ] }
},
"deal_role": {
  "company_module": { "this": true },
  "member": { "this": true }
}
```

Each row of the matrix is one tuple. "Delivery Lead may approve deal D":

```
deal:D # approver @ deal_role:delivery-lead-D#member
```

A tick on the page grants it, an untick revokes it, and every Delivery Lead gains or loses
`approver` on their next check. Membership is the same shape:

```
deal_role:delivery-lead-D # member @ user:<bob's subject>
```

One role object per deal keeps the rows company-bound through the anchors. For a matrix that
applies to every deal of a kind, put the rows on one object the deals inherit from through a
`parent` tuple, as in [folders](modelling-folders.md).

The only thing the Director cannot do on that page is invent a new verb, say "export". That is
a new relation, so it is a re-registration, and that is right: a new verb has to be enforced in
your code before it means anything.

## "And" is an intersection

"Delivery sees a line only if the line is on the delivery side and they are on the deal" is two
facts joined by "and", and the model says it directly:

```json
"line": {
  "company_module": { "this": true },
  "deal": { "this": true },
  "delivery_side": { "this": true },
  "on_deal": { "tupleToUserset": { "tupleset": "deal", "computedUserset": "member" } },
  "viewer": { "intersection": [ { "computedUserset": "delivery_side" }, { "computedUserset": "on_deal" } ] }
}
```

A check holds only when every child holds. Before 0.2.0 the model had no intersection, and the
pattern below still works on any version: your app knows both facts, so it writes one tuple
that already means both:

```
deal:D # delivery_viewer @ user:<alice>        when Alice joins deal D on the delivery side
line:L # deal @ deal:D                          on a delivery-side line
line:L # sales_deal @ deal:D                    on a sales-side line
```

with `line.viewer` deriving through `deal → delivery_viewer` and `sales_deal → sales_viewer`.
Every check is one walk. The cost is yours: revoke the derived tuple when either fact stops,
and let the reconciliation sweep from [Module inside or app beside](inside-or-beside.md)
catch what a crash missed.

## Inheritance, breaking it, limited access

Inheritance is a `parent` tuple, breaking it deletes that tuple and copies the grants to keep,
limited access is a direct grant on the object. No exclusion is needed and none exists.
[Modelling folders](modelling-folders.md) works it through with tuples and checks.

## What is a grant, what is a re-registration

| Change | What it is |
|---|---|
| Give someone, a position or a group access to an object | A grant |
| Take it away | A revoke |
| A role may now do one more thing on an object | A grant of the relation to the role's `member` |
| A new object joins a folder, a deal, a project | A grant of its `parent` or `deal` tuple |
| An object moves | Grant the new parent tuple, then revoke the old |
| A new kind of thing to protect (a new object type) | A re-registration |
| A new verb (a new relation), or a new way a relation derives | A re-registration |
| A relation should also be implied by another | A re-registration |

A re-registration replaces the fragment in place and leaves every tuple as it is. Removing a
relation that tuples still name makes those tuples inert, not invalid; revoke them first if the
ledger should say so.
