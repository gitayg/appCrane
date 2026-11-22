"""Forward-only SQL migrations.

app/migrations/NNN_name.sql, applied in name order, each in its own
transaction, recorded in schema_migrations. Add a new file for every change;
never edit or delete one that has been deployed. A session advisory lock makes
two containers starting at once apply each file exactly once.
"""

from __future__ import annotations

import re
from pathlib import Path

LOCK_KEY = 7240311
MIGRATIONS_DIR = Path(__file__).parent / "migrations"
_NAME = re.compile(r"^\d+_[a-z0-9_]+\.sql$")


def migration_files(directory: Path = MIGRATIONS_DIR) -> list[str]:
    return sorted(p.name for p in directory.iterdir() if _NAME.match(p.name))


def migrate(conn, directory: Path = MIGRATIONS_DIR) -> list[str]:
    """Apply pending migrations on `conn` (a psycopg connection in autocommit mode)."""
    applied: list[str] = []
    conn.execute("SELECT pg_advisory_lock(%s)", (LOCK_KEY,))
    try:
        conn.execute(
            "CREATE TABLE IF NOT EXISTS schema_migrations (name text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())"
        )
        done = {row[0] for row in conn.execute("SELECT name FROM schema_migrations").fetchall()}
        for name in migration_files(directory):
            if name in done:
                continue
            with conn.transaction():
                conn.execute((directory / name).read_text(encoding="utf-8"))
                conn.execute("INSERT INTO schema_migrations (name) VALUES (%s)", (name,))
            applied.append(name)
    finally:
        conn.execute("SELECT pg_advisory_unlock(%s)", (LOCK_KEY,))
    return applied
