import os

import pytest

from app.migrate import MIGRATIONS_DIR, migrate, migration_files


class RecordingConn:
    """Records what migrate() sends, so the bookkeeping is tested with no database."""

    def __init__(self, already=()):
        self.log = []
        self.already = list(already)

    def execute(self, sql, params=None):
        self.log.append(sql)
        rows = [(n,) for n in self.already] if sql == "SELECT name FROM schema_migrations" else []
        return type("Cur", (), {"fetchall": lambda _self: rows})()

    def transaction(self):
        conn = self

        class Tx:
            def __enter__(self):
                conn.log.append("BEGIN")

            def __exit__(self, exc_type, *_):
                conn.log.append("ROLLBACK" if exc_type else "COMMIT")
                return False

        return Tx()


def test_migrations_apply_in_order_under_the_lock():
    conn = RecordingConn()
    applied = migrate(conn)
    assert applied == migration_files() and len(applied) >= 1
    assert "pg_advisory_lock" in conn.log[0]
    begin = conn.log.index("BEGIN")
    assert "CREATE TABLE notes" in conn.log[begin + 1]
    assert conn.log[begin + 3] == "COMMIT"
    assert "pg_advisory_unlock" in conn.log[-1]


def test_recorded_migration_is_not_reapplied():
    conn = RecordingConn(already=migration_files())
    assert migrate(conn) == []
    assert "BEGIN" not in conn.log


# Against a real Postgres. Point TEST_DATABASE_URL at a throwaway database,
# for example: docker run --rm -e POSTGRES_PASSWORD=pw -p 5433:5432 postgres:16-alpine
# and TEST_DATABASE_URL=postgres://postgres:pw@127.0.0.1:5433/postgres
URL = os.environ.get("TEST_DATABASE_URL")


@pytest.mark.skipif(not URL, reason="TEST_DATABASE_URL is not set")
def test_real_postgres_migrate_then_write_and_read(sign):
    import psycopg
    from fastapi.testclient import TestClient

    from app.db import create_pool
    from app.main import create_app
    from app.store import NotesStore

    with psycopg.connect(URL, autocommit=True) as conn:
        conn.execute("DROP TABLE IF EXISTS notes, schema_migrations")
        assert migrate(conn) == migration_files(MIGRATIONS_DIR)
        assert migrate(conn) == []

    pool = create_pool(URL)
    try:
        client = TestClient(create_app(NotesStore(pool), "0.1.0"))
        assert client.get("/api/health").json()["database"] == "ok"
        r = client.post("/api/notes", headers=sign(app_role="user"), json={"body": "stored in postgres"})
        assert r.status_code == 201
        notes = client.get("/api/notes", headers=sign(app_role="viewer")).json()["notes"]
        assert notes[0]["body"] == "stored in postgres"
        assert notes[0]["author_id"] == "42"
    finally:
        pool.close()
