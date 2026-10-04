# SPDX-License-Identifier: Apache-2.0
"""The SDK against a fake gateway: JWKS and token endpoint under /realms/kiban plus the four
public routes, each recording the bearer it saw."""

import json
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

from kiban import KibanApiError, KibanClient

KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
JWK = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(KEY.public_key()))
JWK.update({"kid": "k1", "alg": "RS256", "use": "sig"})


def sign(issuer: str, sub: str, aud: str = "kiban-api", azp: str = None, exp_in: int = 300) -> str:
    claims = {"iss": issuer, "aud": aud, "sub": sub, "iat": int(time.time()), "exp": int(time.time()) + exp_in}
    if azp:
        claims["azp"] = azp
    return jwt.encode(claims, KEY, algorithm="RS256", headers={"kid": "k1"})


class State:
    token_calls = 0
    grants = []
    bearers = []
    paths = []
    batch = {}
    issuer = ""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):  # quiet
        pass

    def _json(self, status, body):
        raw = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(n) if n else b""

    def do_GET(self):
        if self.path == "/realms/kiban/protocol/openid-connect/certs":
            return self._json(200, {"keys": [JWK]})
        if "/members/by-subject/" in self.path:
            State.bearers.append(self.headers.get("Authorization"))
            return self._json(200, {"data": {"isMember": True, "isActive": True, "memberId": "m-1"}})
        if self.path == "/api/org/me/companies":
            State.bearers.append(self.headers.get("Authorization"))
            return self._json(200, {"data": [{"id": "co-1", "code": "ACME", "name": "Acme", "isActive": True}]})
        if self.path.startswith("/api/org/companies/co-1/members?"):
            State.bearers.append(self.headers.get("Authorization"))
            State.paths.append(self.path)
            return self._json(200, {"data": {"items": [{"id": "m-1", "displayName": "Alice", "email": "", "hasLinkedUser": True, "kind": "service"}], "total": 1, "page": 1, "pageSize": 25, "totalPages": 1}})
        if "/positions/p-1/holder?date=" in self.path:
            State.paths.append(self.path)
            return self._json(200, {"data": {"id": "a-1", "positionId": "p-1", "memberId": "m-1", "validFrom": "2026-01-01", "validTo": None}})
        if self.path.endswith("/groups/g-1/members"):
            return self._json(200, {"data": [{"groupId": "g-1", "memberId": "m-1", "memberDisplayName": "Alice"}]})
        if self.path.endswith("/groups/empty/members"):
            return self._json(200, {"data": []})
        self._json(404, {"error": {"code": "NOT_FOUND", "message": "nope"}})

    def do_POST(self):
        body = self._body()
        if self.path == "/realms/kiban/protocol/openid-connect/token":
            State.token_calls += 1
            form = parse_qs(body.decode())
            if form.get("client_id") != ["app-backend"] or form.get("client_secret") != ["s3cret"]:
                return self._json(401, {"error": "unauthorized_client"})
            return self._json(200, {"access_token": sign(State.issuer, "service-account-app-backend", azp="app-backend"), "expires_in": 300})
        State.bearers.append(self.headers.get("Authorization"))
        data = json.loads(body) if body else {}
        if self.path == "/api/auth/effective-access/can":
            allowed = data.get("featureKey") == "app.ticket.view"
            return self._json(200, {"data": {"allowed": allowed, "reason": "ALLOWED" if allowed else "ENGINE_DENIED"}})
        if self.path == "/api/auth/effective-access/batch-can":
            State.batch = data
            return self._json(200, {"data": [
                {"object": it["object"], "relation": it["relation"], "decision": {"allowed": it["object"]["id"] == "t-1", "reason": "ALLOWED" if it["object"]["id"] == "t-1" else "ENGINE_DENIED"}}
                for it in data.get("items", [])
            ]})
        if self.path == "/api/auth/grants":
            State.grants.append(data)
            if data.get("companyId") == "other":
                return self._json(403, {"error": {"code": "AUTHORIZATION_DENIED", "message": "not yours"}})
            return self._json(200, {"data": {"status": "ok"}})
        if self.path == "/api/platform/admin/apps":
            return self._json(200, {"data": {"module": data.get("key"), "installed": True}})
        self._json(404, {"error": {"code": "NOT_FOUND", "message": "nope"}})


class ClientTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = HTTPServer(("127.0.0.1", 0), Handler)
        cls.url = f"http://127.0.0.1:{cls.server.server_port}"
        State.issuer = f"{cls.url}/realms/kiban"
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def test_client(self):
        with self.assertRaises(ValueError):
            KibanClient(gateway_url=self.url, client_id="", client_secret="")
        c = KibanClient(gateway_url=self.url + "/", client_id="app-backend", client_secret="s3cret")

        user = sign(State.issuer, "alice", azp="kiban-frontend")
        v = c.verify_user_token(user)
        self.assertEqual((v.subject, v.client_id), ("alice", "kiban-frontend"))
        with self.assertRaises(jwt.InvalidTokenError):
            c.verify_user_token(sign(State.issuer, "alice", aud="other"))
        with self.assertRaises(jwt.InvalidTokenError):
            c.verify_user_token(sign(State.issuer, "alice", exp_in=-120))

        d = c.can(user, "app.ticket.view", module_key="app", company_id="co-1")
        self.assertTrue(d.allowed)
        self.assertEqual(State.bearers[0], f"Bearer {user}")

        c.grant("co-1", [c.anchor_tuple("app", "ticket", "t-1", "co-1"),
                         {"objectType": "ticket", "objectId": "t-1", "relation": "viewer", "subjectType": "user", "subjectId": "alice"}])
        c.revoke("co-1", [{"objectType": "ticket", "objectId": "t-1", "relation": "viewer", "subjectType": "user", "subjectId": "alice"}])
        self.assertEqual([g["op"] for g in State.grants], ["grant", "revoke"])
        self.assertEqual(State.grants[0]["tuples"][0]["subjectId"], "co-1/app")
        self.assertEqual(State.token_calls, 1, "the service token is cached")
        svc = c.verify_user_token(State.bearers[1].removeprefix("Bearer "))
        self.assertEqual(svc.subject, "service-account-app-backend")

        with self.assertRaises(KibanApiError) as ctx:
            c.grant("other", [])
        self.assertEqual((ctx.exception.status, ctx.exception.code), (403, "AUTHORIZATION_DENIED"))

        # The batch check: triples in, one decision per item out, the user's bearer.
        results = c.batch_can(user, "app.ticket.view", [("ticket", "t-1", "viewer"), ("ticket", "t-2", "viewer")], module_key="app", company_id="co-1")
        self.assertEqual([(r.object_id, r.decision.allowed) for r in results], [("t-1", True), ("t-2", False)])
        self.assertEqual(State.batch["items"][0], {"object": {"type": "ticket", "id": "t-1"}, "relation": "viewer"})
        self.assertEqual(State.bearers[-1], f"Bearer {user}")
        self.assertEqual(len(c.batch_can_service("app.ticket.view", [("ticket", "t-1", "viewer")], company_id="co-1")), 1)

        # The org reads: companies with the user's bearer, the rest with the service token.
        self.assertEqual([co["code"] for co in c.me_companies(user)], ["ACME"])
        self.assertEqual(State.bearers[-1], f"Bearer {user}")
        page = c.member_directory("co-1", q="ali", page=1, page_size=25)
        self.assertEqual(page["items"][0]["kind"], "service")
        self.assertIn("q=ali", State.paths[-1])
        self.assertTrue(State.bearers[-1].startswith("Bearer ey"))
        holder = c.position_holder("co-1", "p-1", "2026-09-28")
        self.assertEqual(holder["memberId"], "m-1")
        self.assertTrue(State.paths[-1].endswith("/holder?date=2026-09-28"))
        self.assertEqual(c.group_members("co-1", "g-1")[0]["memberDisplayName"], "Alice")
        self.assertEqual(c.group_members("co-1", "empty"), [])

        fact = c.member_by_subject("co-1", "alice")
        self.assertEqual((fact.is_member, fact.member_id), (True, "m-1"))

        cap = c.register_app("admin-token", {"key": "app", "displayName": "App", "version": "1", "serviceClientId": "app-backend", "authzFragment": {}})
        self.assertEqual(cap["module"], "app")
        self.assertEqual(State.bearers[-1], "Bearer admin-token")

        self.assertFalse(c.can_service("app.nope").allowed)


if __name__ == "__main__":
    unittest.main()
