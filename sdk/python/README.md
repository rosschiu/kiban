# kiban-sdk (Python)

The Python client for an application that runs beside Kiban. The app's backend authenticates
as its registered service client, verifies the user tokens Kiban's login issued, asks for access
decisions, writes and removes relation tuples on its own object types, and looks members up,
all through the gateway's public API.

```python
from kiban import KibanClient

kiban = KibanClient(gateway_url="https://kiban.example", client_id="tokidesk-backend", client_secret=SECRET)

user = kiban.verify_user_token(bearer)                      # the user behind a request
decision = kiban.can(bearer, "tokidesk.ticket.view", module_key="tokidesk", company_id=company_id)
kiban.grant(company_id, [kiban.anchor_tuple("tokidesk", "ticket", ticket_id, company_id),
                         {"objectType": "ticket", "objectId": ticket_id, "relation": "viewer",
                          "subjectType": "user", "subjectId": user.subject}])
```

Install: `pip install kiban-sdk` (from this directory: `pip install .`). Depends on PyJWT with
its cryptography extra. Licence: Apache-2.0.
