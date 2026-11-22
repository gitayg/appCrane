"""The notes example's data access. Replace with your own tables."""

from __future__ import annotations

from psycopg.rows import dict_row


class NotesStore:
    def __init__(self, pool):
        self.pool = pool

    def ping(self) -> None:
        with self.pool.connection() as conn:
            conn.execute("SELECT 1")

    def list(self) -> list[dict]:
        with self.pool.connection() as conn, conn.cursor(row_factory=dict_row) as cur:
            cur.execute("SELECT id, body, author_id, created_at FROM notes ORDER BY id DESC LIMIT 100")
            return cur.fetchall()

    def add(self, body: str, author_id: str) -> dict:
        with self.pool.connection() as conn, conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                "INSERT INTO notes (body, author_id) VALUES (%s, %s) RETURNING id, body, author_id, created_at",
                (body, author_id),
            )
            return cur.fetchone()

    def delete(self, note_id: int) -> int:
        with self.pool.connection() as conn:
            return conn.execute("DELETE FROM notes WHERE id = %s", (note_id,)).rowcount
