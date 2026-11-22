import os
import secrets
import time
from urllib.parse import quote

import pytest

from app.identity import sign_identity_v2

# A fresh secret per test run: nothing secret-shaped is committed, and headers
# signed in one run cannot pass in another.
TEST_SECRET = secrets.token_urlsafe(32)
os.environ["APPCRANE_IDENTITY_SECRET"] = TEST_SECRET


def signed_headers(app_role="user", user_id="42", app_roles=None, secret=None, ts=None, extra=None):
    """Headers exactly as AppCrane's proxy issues them, signed with `secret`."""
    h = {
        "x-appcrane-auth-mode": "authenticated",
        "x-appcrane-user": "person@example.test",
        "x-appcrane-user-id": user_id,
        "x-appcrane-user-email": "person@example.test",
        "x-appcrane-user-name": quote("Test Person"),
        "x-appcrane-user-role": "user",
        "x-appcrane-app-role": app_role,
        "x-appcrane-is-admin": "1" if app_role in ("admin", "owner") else "0",
    }
    if app_roles:
        h["x-appcrane-app-roles"] = app_roles
    h.update(extra or {})
    ts = int(time.time()) if ts is None else ts
    h["x-appcrane-identity-ts"] = str(ts)
    h["x-appcrane-identity-sig-v2"] = sign_identity_v2(secret or TEST_SECRET, ts, h)
    return h


@pytest.fixture
def sign():
    return signed_headers
