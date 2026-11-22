import secrets
import time

import pytest

from app.identity import IdentityError, at_least, authenticated_within, sign_identity_v2, sign_identity_v3, verify_headers


def code_of(headers, **kw):
    with pytest.raises(IdentityError) as e:
        verify_headers(headers, **kw)
    return e.value.code


def test_matches_appcrane_signer_byte_for_byte():
    # Known answers computed by AppCrane's own signer (appcrane-tenant
    # signIdentityV2). If this fails, this copy signs different bytes than the
    # platform and no real request would verify.
    headers = {
        "x-appcrane-user": "kat@example.test",
        "x-appcrane-user-id": "7",
        "x-appcrane-user-email": "kat@example.test",
        "x-appcrane-user-name": "K%C3%A4t%20Tester",
        "x-appcrane-user-role": "user",
        "x-appcrane-app-role": "admin",
        "x-appcrane-is-admin": "1",
        "x-appcrane-app-roles": "approver,auditor",
        "x-appcrane-auth-via": "app-key",
    }
    assert sign_identity_v2("known-answer-only", 1700000000, headers) == "Bm6H2230lr8CqUJ9vcOPtxZj9z3umJzlGjTjY2FRZ-o"
    del headers["x-appcrane-app-roles"], headers["x-appcrane-auth-via"]
    assert sign_identity_v2("known-answer-only", 1700000000, headers) == "OyZ3qwyGsbpbIPfWQw-8s4LA3dxePNBv7t7v6hd29Mo"
    headers.update({"x-appcrane-identity-ts": "1700000000", "x-appcrane-identity-sig-v2": "OyZ3qwyGsbpbIPfWQw-8s4LA3dxePNBv7t7v6hd29Mo"})
    who = verify_headers(headers, secret="known-answer-only", now=1700000010)
    assert who.name == "Kät Tester"
    assert who.app_role == "admin"


def test_signed_identity_verifies(sign):
    who = verify_headers(sign(app_role="admin", app_roles="approver,auditor"))
    assert who.user_id == "42"
    assert who.email == "person@example.test"
    assert who.name == "Test Person"
    assert who.is_app_admin is True
    assert who.app_roles == ["approver", "auditor"]
    assert who.auth_via == "session"


def test_unsigned_is_refused(sign):
    h = sign(app_role="owner")
    del h["x-appcrane-identity-sig-v2"]
    assert code_of(h) == "IDENTITY_UNSIGNED"
    assert code_of({}) == "IDENTITY_UNSIGNED"


def test_other_secret_is_refused(sign):
    assert code_of(sign(app_role="owner", secret=secrets.token_urlsafe(32))) == "IDENTITY_FORGED"


@pytest.mark.parametrize("name,value", [
    ("x-appcrane-app-role", "owner"),
    ("x-appcrane-user-id", "1"),
    ("x-appcrane-is-admin", "1"),
    ("x-appcrane-app-roles", "approver"),
    ("x-appcrane-auth-via", "session"),
])
def test_altering_a_signed_header_is_refused(sign, name, value):
    h = sign(app_role="viewer")
    h[name] = value
    assert code_of(h) == "IDENTITY_FORGED"


def test_removing_auth_via_is_refused(sign):
    h = sign(extra={"x-appcrane-auth-via": "app-key"})
    assert verify_headers(h).auth_via == "app-key"
    del h["x-appcrane-auth-via"]
    assert code_of(h) == "IDENTITY_FORGED"


def test_old_signature_is_refused(sign):
    assert code_of(sign(ts=int(time.time()) - 301)) == "IDENTITY_EXPIRED"


def test_no_secret_configured(sign):
    assert code_of(sign(), secret="") == "IDENTITY_NOT_CONFIGURED"


def test_role_ladder():
    assert at_least("owner", "admin")
    assert at_least("admin", "admin")
    assert not at_least("viewer", "user")
    assert not at_least("bogus", "viewer")


def test_v3_matches_appcrane_signer_and_carries_auth_time():
    # Known answer from appcrane-tenant signIdentityV3.
    headers = {
        "x-appcrane-user": "kat@example.test",
        "x-appcrane-user-id": "7",
        "x-appcrane-user-email": "kat@example.test",
        "x-appcrane-user-name": "K%C3%A4t%20Tester",
        "x-appcrane-user-role": "user",
        "x-appcrane-app-role": "admin",
        "x-appcrane-is-admin": "1",
        "x-appcrane-app-roles": "approver,auditor",
        "x-appcrane-auth-via": "app-key",
        "x-appcrane-auth-time": "1699999000",
        "x-appcrane-auth-mfa": "totp",
    }
    assert sign_identity_v3("known-answer-only", 1700000000, headers) == "hRvPjJVpUFxZGYGrcXcV0uQWKXSHGBfklZsx_Bm6i1E"
    headers.update({"x-appcrane-identity-ts": "1700000000", "x-appcrane-identity-sig-v3": "hRvPjJVpUFxZGYGrcXcV0uQWKXSHGBfklZsx_Bm6i1E"})
    who = verify_headers(headers, secret="known-answer-only", now=1700000010)
    assert who.auth_time == 1699999000
    assert who.mfa == "totp"
    assert authenticated_within(who, 600, now=1700000010) is False
    assert authenticated_within(who, 1200, now=1700000010) is True
    headers["x-appcrane-auth-time"] = "1700000005"
    assert code_of(headers, secret="known-answer-only", now=1700000010) == "IDENTITY_FORGED"
