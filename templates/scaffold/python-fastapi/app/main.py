from __future__ import annotations

import json
import logging
from pathlib import Path

from fastapi import Depends, FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from .identity import Identity, IdentityError, at_least, verify_headers

log = logging.getLogger("__APP_SLUG__")

# Paths served without a verified identity. AppCrane's health probe calls the
# container directly, with no identity headers, so /api/health must be here.
# Add to this set only for routes that are genuinely public.
PUBLIC_PATHS = {"/api/health"}


def read_version() -> str:
    manifest = Path(__file__).resolve().parent.parent / "deployhub.json"
    return str(json.loads(manifest.read_text(encoding="utf-8")).get("version", "0.0.0"))


def _error(status: int, code: str, message: str) -> JSONResponse:
    return JSONResponse({"error": {"code": code, "message": message}}, status_code=status)


class AppError(Exception):
    def __init__(self, status: int, code: str, message: str):
        self.status, self.code, self.message = status, code, message


def current_identity(request: Request) -> Identity:
    return request.state.identity


def require_app_role(minimum: str):
    """Require at least `minimum` on the per-app ladder: viewer < user < admin < owner."""

    def check(identity: Identity = Depends(current_identity)) -> Identity:
        if not at_least(identity.app_role, minimum):
            raise AppError(403, "ROLE_REQUIRED", f"this needs the {minimum} role or higher")
        return identity

    return check


def require_app_defined_role(key: str):
    """Require one of the roles this app defines for itself (X-AppCrane-App-Roles)."""

    def check(identity: Identity = Depends(current_identity)) -> Identity:
        if key not in identity.app_roles:
            raise AppError(403, "APP_ROLE_REQUIRED", f"this needs the {key} role")
        return identity

    return check


class NoteIn(BaseModel):
    body: str = Field(min_length=1, max_length=2000)


def create_app(store, version: str) -> FastAPI:
    """`store` is a NotesStore, or None when no database is configured."""
    app = FastAPI(title="__APP_SLUG__", version=version, docs_url=None, redoc_url=None, openapi_url=None)

    @app.middleware("http")
    async def require_identity(request: Request, call_next):
        if request.url.path in PUBLIC_PATHS:
            return await call_next(request)
        try:
            request.state.identity = verify_headers(request.headers)
        except IdentityError as e:
            return _error(503 if e.code == "IDENTITY_NOT_CONFIGURED" else 401, e.code, e.message)
        return await call_next(request)

    @app.exception_handler(AppError)
    async def app_error(_request: Request, e: AppError):
        return _error(e.status, e.code, e.message)

    def need_store():
        if store is None:
            raise AppError(503, "NO_DATABASE", "DATABASE_URL is not set")
        return store

    @app.get("/api/health")
    def health():
        if store is None:
            return {"status": "ok", "version": version, "database": "not_configured"}
        try:
            store.ping()
        except Exception:
            log.exception("health: database unreachable")
            return JSONResponse({"status": "error", "version": version, "database": "unreachable"}, status_code=503)
        return {"status": "ok", "version": version, "database": "ok"}

    @app.get("/api/me")
    def me(identity: Identity = Depends(current_identity)):
        return {"user": identity.__dict__}

    @app.get("/api/notes")
    def list_notes(_: Identity = Depends(require_app_role("viewer")), s=Depends(need_store)):
        return {"notes": s.list()}

    @app.post("/api/notes", status_code=201)
    def add_note(note: NoteIn, identity: Identity = Depends(require_app_role("user")), s=Depends(need_store)):
        return {"note": s.add(note.body.strip(), identity.user_id)}

    # Gated twice on purpose: here, and by the "access" rule in deployhub.json
    # that makes AppCrane's proxy refuse /api/admin/* below admin.
    @app.delete("/api/admin/notes/{note_id}")
    def delete_note(note_id: int, _: Identity = Depends(require_app_role("admin")), s=Depends(need_store)):
        return {"deleted": s.delete(note_id)}

    return app


def build() -> FastAPI:
    """Entry point for uvicorn --factory: connect, migrate, serve."""
    import os

    import psycopg

    from .db import create_pool
    from .migrate import migrate
    from .store import NotesStore

    logging.basicConfig(level=logging.INFO)
    store = None
    url = os.environ.get("DATABASE_URL", "")
    if url:
        with psycopg.connect(url, autocommit=True) as conn:
            applied = migrate(conn)
        log.info("migrations applied: %s", ", ".join(applied) if applied else "none (up to date)")
        store = NotesStore(create_pool(url))
    else:
        log.info("DATABASE_URL is not set: running without a database")
    return create_app(store, read_version())
