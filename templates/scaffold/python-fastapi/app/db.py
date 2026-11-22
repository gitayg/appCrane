"""Managed Postgres.

AppCrane injects DATABASE_URL when deployhub.json declares
"database": {"engine": "postgres"}. The URL already carries the TLS
parameters (sslmode, sslrootcert, sslcert, sslkey) and libpq (psycopg) reads
them from it, so nothing else is needed. Sandbox and production each get their
own database under the same variable name.

AppCrane caps each database login at 25 connections; keep the pool well below.
"""

from __future__ import annotations

import os

from psycopg_pool import ConnectionPool


def create_pool(url: str | None = None) -> ConnectionPool | None:
    url = os.environ.get("DATABASE_URL", "") if url is None else url
    if not url:
        return None
    pool = ConnectionPool(url, min_size=1, max_size=5, open=False)
    pool.open(wait=True, timeout=30)
    return pool
