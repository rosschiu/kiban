# SPDX-License-Identifier: Apache-2.0
"""The app's backend view of Kiban: service token, user token verification, decisions,
tuples, members, registration. Standard library HTTP plus PyJWT for token verification."""

from __future__ import annotations

import json
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Optional

import jwt


@dataclass
class VerifiedToken:
    """The verified identity a Kiban token carries. Identity only, never authority."""

    subject: str
    client_id: Optional[str]
    claims: dict[str, Any] = field(default_factory=dict)


@dataclass
class Decision:
    """Kiban's answer: allowed, or denied with one of the frozen reason codes."""

    allowed: bool
    reason: str


@dataclass
class MemberFact:
    """Whether a subject is an active member of a company, and which member."""

    is_member: bool
    is_active: bool
    member_id: Optional[str]


class KibanApiError(Exception):
    """Kiban's error envelope: HTTP status, code, message, details."""

    def __init__(self, status: int, code: str, message: str, details: Any = None):
        super().__init__(f"kiban: HTTP {status} {code}: {message}")
        self.status = status
        self.code = code
        self.message = message
        self.details = details


class KibanClient:
    """A client for the app's service client. Safe for use from several threads."""

    def __init__(
        self,
        gateway_url: str,
        client_id: str,
        client_secret: str,
        realm: str = "kiban",
        audience: str = "kiban-api",
        timeout: float = 15.0,
        opener: Optional[urllib.request.OpenerDirector] = None,
    ):
        if not gateway_url or not client_id or not client_secret:
            raise ValueError("gateway_url, client_id and client_secret are required")
        self.gateway_url = gateway_url.rstrip("/")
        self.realm = realm
        self.client_id = client_id
        self.client_secret = client_secret
        self.audience = audience
        self.timeout = timeout
        self._opener = opener or urllib.request.build_opener()
        self.issuer = f"{self.gateway_url}/realms/{realm}"
        self._jwks = jwt.PyJWKClient(f"{self.issuer}/protocol/openid-connect/certs", cache_keys=True)
        self._lock = threading.Lock()
        self._token: Optional[str] = None
        self._expires_at = 0.0

    # --- tokens -------------------------------------------------------------------------

    def service_token(self) -> str:
        """The app's own access token (client credentials), refreshed before it expires."""
        with self._lock:
            if self._token and self._expires_at - time.time() > 30:
                return self._token
            form = urllib.parse.urlencode(
                {"grant_type": "client_credentials", "client_id": self.client_id, "client_secret": self.client_secret}
            ).encode()
            req = urllib.request.Request(
                f"{self.issuer}/protocol/openid-connect/token",
                data=form,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                method="POST",
            )
            status, body = self._send(req)
            if status != 200:
                raise KibanApiError(status, "TOKEN_REQUEST_FAILED", body.decode(errors="replace"))
            data = json.loads(body)
            self._token = data["access_token"]
            self._expires_at = time.time() + float(data.get("expires_in", 300))
            return self._token

    def verify_user_token(self, bearer: str) -> VerifiedToken:
        """Verifies a bearer a user presented to the app: signature against the realm's keys,
        issuer, audience and time claims. Raises ``jwt.InvalidTokenError`` otherwise."""
        key = self._jwks.get_signing_key_from_jwt(bearer)
        claims = jwt.decode(bearer, key.key, algorithms=["RS256"], audience=self.audience, issuer=self.issuer, leeway=30)
        return VerifiedToken(subject=claims["sub"], client_id=claims.get("azp"), claims=claims)

    # --- decisions ----------------------------------------------------------------------

    def can(
        self,
        user_bearer: str,
        feature_key: str,
        module_key: Optional[str] = None,
        company_id: Optional[str] = None,
        scope: str = "company",
        object: Optional[dict[str, str]] = None,
        relation: Optional[str] = None,
    ) -> Decision:
        """Asks whether the user behind ``user_bearer`` may use ``feature_key`` here. Kiban
        answers for that bearer only; pass the bearer the user presented, unchanged."""
        body: dict[str, Any] = {"featureKey": feature_key, "scope": scope}
        if module_key:
            body["moduleKey"] = module_key
        if company_id:
            body["companyId"] = company_id
        if object:
            body["object"] = object
        if relation:
            body["relation"] = relation
        data = self._api("POST", "/api/auth/effective-access/can", user_bearer, body)
        return Decision(allowed=bool(data.get("allowed")), reason=str(data.get("reason", "")))

    def can_service(self, feature_key: str, **kwargs: Any) -> Decision:
        """``can`` for the app's own service account (a background job)."""
        return self.can(self.service_token(), feature_key, **kwargs)

    # --- tuples -------------------------------------------------------------------------

    @staticmethod
    def anchor_tuple(app_key: str, object_type: str, object_id: str, company_id: str) -> dict[str, str]:
        """The ``company_module`` anchor tuple binding an object of the app to a company; write
        it in the same ``grant`` call as the object's first tuple."""
        return {
            "objectType": object_type,
            "objectId": object_id,
            "relation": "company_module",
            "subjectType": "company_module",
            "subjectId": f"{company_id}/{app_key}",
        }

    def grant(self, company_id: str, tuples: list[dict[str, str]]) -> None:
        """Writes tuples on the app's own object types in ``company_id``."""
        self._grants("grant", company_id, tuples)

    def revoke(self, company_id: str, tuples: list[dict[str, str]]) -> None:
        """Removes tuples the app wrote."""
        self._grants("revoke", company_id, tuples)

    def _grants(self, op: str, company_id: str, tuples: list[dict[str, str]]) -> None:
        self._api("POST", "/api/auth/grants", self.service_token(), {"op": op, "companyId": company_id, "tuples": tuples})

    # --- org ----------------------------------------------------------------------------

    def member_by_subject(self, company_id: str, subject: str) -> MemberFact:
        """Asks org whether ``subject`` is an active member of ``company_id``."""
        path = f"/api/org/companies/{urllib.parse.quote(company_id, safe='')}/members/by-subject/{urllib.parse.quote(subject, safe='')}"
        data = self._api("GET", path, self.service_token())
        return MemberFact(is_member=bool(data.get("isMember")), is_active=bool(data.get("isActive")), member_id=data.get("memberId"))

    # --- registration -------------------------------------------------------------------

    def register_app(self, superadmin_bearer: str, manifest: dict[str, Any]) -> dict[str, Any]:
        """Registers (or re-registers) the app with a superadmin's bearer; returns its capability."""
        return self._api("POST", "/api/platform/admin/apps", superadmin_bearer, manifest)

    # --- plumbing -----------------------------------------------------------------------

    def _api(self, method: str, path: str, bearer: str, body: Any = None) -> dict[str, Any]:
        data = json.dumps(body).encode() if body is not None else None
        headers = {"Authorization": f"Bearer {bearer}"}
        if data is not None:
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(self.gateway_url + path, data=data, headers=headers, method=method)
        status, raw = self._send(req)
        try:
            envelope = json.loads(raw) if raw else {}
        except ValueError:
            envelope = {}
        if status >= 400:
            err = envelope.get("error") or {}
            raise KibanApiError(status, err.get("code", f"HTTP_{status}"), err.get("message", raw.decode(errors="replace")), err.get("details"))
        return envelope.get("data") or {}

    def _send(self, req: urllib.request.Request) -> tuple[int, bytes]:
        try:
            with self._opener.open(req, timeout=self.timeout) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read()
