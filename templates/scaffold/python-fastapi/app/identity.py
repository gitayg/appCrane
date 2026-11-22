"""Verified AppCrane identity.

AppCrane's proxy checks every visitor and forwards who they are as
X-AppCrane-* request headers. Those headers are only trustworthy when their
signature checks out: a request that reaches this container any other way (a
published TCP port, another container on the same host) can carry any headers
it likes. So nothing here reads an identity header until the v2 signature over
all of them matches, using the per-app, per-environment secret AppCrane
injects as APPCRANE_IDENTITY_SECRET.

The signed text is, joined with "\\n":
    appcrane-identity-v2
    <X-AppCrane-Identity-Ts>
    one "name:value" line per header in SIGNED_HEADERS_V2 (absent = empty)
HMAC-SHA256 with the secret, base64url without padding, sent as
X-AppCrane-Identity-Sig-V2.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re
import time
from dataclasses import dataclass, field
from typing import Mapping
from urllib.parse import unquote

SIGNED_HEADERS_V2 = (
    "x-appcrane-user",
    "x-appcrane-user-id",
    "x-appcrane-user-email",
    "x-appcrane-user-name",
    "x-appcrane-user-role",
    "x-appcrane-app-role",
    "x-appcrane-is-admin",
    "x-appcrane-app-roles",
    "x-appcrane-auth-via",
)
MAX_AGE_SEC = 300
MAX_CLOCK_SKEW_SEC = 60

# Per-app role ladder. Compare with at_least(), never with ==: an owner must
# pass an "admin" check.
ROLE_RANK = {"none": 0, "viewer": 1, "user": 2, "admin": 3, "owner": 4}


def at_least(app_role: str, minimum: str) -> bool:
    return ROLE_RANK.get(app_role, 0) >= ROLE_RANK[minimum]


@dataclass(frozen=True)
class Identity:
    user_id: str
    email: str
    name: str
    platform_role: str
    app_role: str
    is_app_admin: bool
    app_roles: list[str] = field(default_factory=list)
    auth_via: str = "session"


class IdentityError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def _get(headers: Mapping[str, str], name: str) -> str:
    value = headers.get(name)
    return "" if value is None else str(value)


def sign_identity_v2(secret: str, ts: str | int, headers: Mapping[str, str]) -> str:
    lines = ["appcrane-identity-v2", str(ts)] + [f"{h}:{_get(headers, h)}" for h in SIGNED_HEADERS_V2]
    mac = hmac.new(secret.encode("utf-8"), "\n".join(lines).encode("utf-8"), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(mac).rstrip(b"=").decode("ascii")


def verify_headers(headers: Mapping[str, str], secret: str | None = None, now: float | None = None) -> Identity:
    """Return the verified Identity, or raise IdentityError. `headers` must be
    case-insensitive or lowercase-keyed (Starlette's request.headers is)."""
    secret = os.environ.get("APPCRANE_IDENTITY_SECRET", "") if secret is None else secret
    if not secret:
        raise IdentityError("IDENTITY_NOT_CONFIGURED", "APPCRANE_IDENTITY_SECRET is not set, so no identity can be verified")
    sig = _get(headers, "x-appcrane-identity-sig-v2")
    ts = _get(headers, "x-appcrane-identity-ts")
    if not sig or not re.fullmatch(r"\d{1,12}", ts):
        raise IdentityError("IDENTITY_UNSIGNED", "the request carries no signed AppCrane identity")
    if not hmac.compare_digest(sign_identity_v2(secret, ts, headers).encode(), sig.encode()):
        raise IdentityError("IDENTITY_FORGED", "the identity signature does not match")
    age = int(time.time() if now is None else now) - int(ts)
    if age > MAX_AGE_SEC or age < -MAX_CLOCK_SKEW_SEC:
        raise IdentityError("IDENTITY_EXPIRED", "the identity signature is too old")
    user_id = _get(headers, "x-appcrane-user-id")
    if not re.fullmatch(r"\d+", user_id):
        raise IdentityError("IDENTITY_UNSIGNED", "the signed identity names no user")
    app_role = _get(headers, "x-appcrane-app-role")
    if app_role not in ROLE_RANK:
        app_role = "none"
    return Identity(
        user_id=user_id,
        email=_get(headers, "x-appcrane-user-email") or _get(headers, "x-appcrane-user"),
        name=unquote(_get(headers, "x-appcrane-user-name")),
        platform_role=_get(headers, "x-appcrane-user-role"),
        app_role=app_role,
        is_app_admin=at_least(app_role, "admin"),
        app_roles=[r.strip() for r in _get(headers, "x-appcrane-app-roles").split(",") if r.strip()],
        auth_via=_get(headers, "x-appcrane-auth-via") or "session",
    )
