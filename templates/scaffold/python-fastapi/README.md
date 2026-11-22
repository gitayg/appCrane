# __APP_NAME__

A FastAPI service on AppCrane with sign-in, roles, a managed Postgres database
and a health check already wired.

## What is already done for you

| Concern | Where | What it does |
|---|---|---|
| Sign-in | `app/identity.py`, `app/main.py` | Every request except `/api/health` must carry AppCrane's signed identity; unsigned or forged requests get 401. |
| Roles | `require_app_role()`, `require_app_defined_role()` | `viewer < user < admin < owner`, plus roles your app defines. |
| Database | `app/db.py`, `app/migrate.py`, `app/migrations/` | Postgres via `DATABASE_URL`; SQL migrations run at startup. |
| Health | `GET /api/health` | `{ "status": "ok", "version": "<deployhub.json version>" }` for AppCrane's deploy check. |
| Path rules | `deployhub.json` `access` | AppCrane's proxy refuses `/api/admin/*` below admin. |
| MCP tools | `deployhub.json` `mcp` | `list_notes` and `add_note` are callable by AI agents through AppCrane. |
| Container | `Dockerfile` | Python 3.12, non-root user, port 3000. |
| Tests | `tests/` | Identity (signed, unsigned, forged, altered, expired), roles, health, migrations. |

## Run the tests

```sh
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt
pytest
```

The real-database test runs when `TEST_DATABASE_URL` points at a throwaway
Postgres (see `tests/test_db.py`); otherwise it is skipped and says so.

## Run it locally

```sh
export APPCRANE_IDENTITY_SECRET="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
export DATABASE_URL=postgres://...   # optional, a local Postgres
uvicorn app.main:build --factory --port 3000
```

## Change it

Replace the notes example with your own routes in `app/main.py`, a store in
`app/store.py` and a new migration in `app/migrations/`. Keep the identity
middleware, the health route and the tests. `CLAUDE.md` lists the rules a
coding agent must follow.

## Ship it

Push with `appcrane_push_to_managed_app` and deploy to sandbox with
`appcrane_deploy(slug="__APP_SLUG__", stage="sandbox")`.
