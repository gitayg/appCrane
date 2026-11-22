import secrets

import pytest
from fastapi.testclient import TestClient

from app.main import create_app, read_version


class FakeStore:
    """In-memory stand-in for NotesStore, so these run with no Postgres.
    tests/test_db.py runs the same routes against a real one."""

    def __init__(self, broken=False):
        self.notes = []
        self.broken = broken

    def ping(self):
        if self.broken:
            raise RuntimeError("down")

    def list(self):
        return list(reversed(self.notes))

    def add(self, body, author_id):
        row = {"id": len(self.notes) + 1, "body": body, "author_id": author_id, "created_at": None}
        self.notes.append(row)
        return row

    def delete(self, note_id):
        return 1


@pytest.fixture
def client():
    return TestClient(create_app(FakeStore(), read_version()))


def test_health_needs_no_identity(client):
    r = client.get("/api/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert body["version"] == read_version() == "0.1.0"
    assert body["database"] == "ok"


def test_health_is_503_when_database_unreachable():
    r = TestClient(create_app(FakeStore(broken=True), "0.1.0")).get("/api/health")
    assert r.status_code == 503
    assert r.json()["status"] == "error"


def test_unsigned_request_is_refused(client):
    r = client.get("/api/me", headers={"x-appcrane-user-id": "1", "x-appcrane-app-role": "owner", "x-appcrane-is-admin": "1"})
    assert r.status_code == 401
    assert r.json()["error"]["code"] == "IDENTITY_UNSIGNED"


def test_forged_request_is_refused(client, sign):
    r = client.get("/api/me", headers=sign(app_role="owner", secret=secrets.token_urlsafe(32)))
    assert r.status_code == 401
    assert r.json()["error"]["code"] == "IDENTITY_FORGED"


def test_signed_request_sees_identity(client, sign):
    r = client.get("/api/me", headers=sign(app_role="viewer"))
    assert r.status_code == 200
    assert r.json()["user"]["user_id"] == "42"
    assert r.json()["user"]["app_role"] == "viewer"


def test_viewer_reads_but_cannot_write(client, sign):
    assert client.get("/api/notes", headers=sign(app_role="viewer")).status_code == 200
    assert client.post("/api/notes", headers=sign(app_role="viewer"), json={"body": "hi"}).status_code == 403
    r = client.post("/api/notes", headers=sign(app_role="user"), json={"body": "hi"})
    assert r.status_code == 201
    assert r.json()["note"]["author_id"] == "42"


def test_admin_route(client, sign):
    assert client.delete("/api/admin/notes/1", headers=sign(app_role="user")).status_code == 403
    assert client.delete("/api/admin/notes/1", headers=sign(app_role="owner")).status_code == 200
