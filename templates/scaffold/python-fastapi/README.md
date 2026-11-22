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

## AppCrane widgets

When AppCrane serves this app on its own host, it also serves drop-in widgets
for sign-in and access at `/__appcrane/widgets.js` on that host. Add the script
once and place any of the elements in your pages:

```html
<script src="/__appcrane/widgets.js" defer></script>

<appcrane-user-menu sessions-href="/account"></appcrane-user-menu>
<appcrane-sessions></appcrane-sessions>             <!-- list and revoke your sessions on this app -->
<appcrane-app-members></appcrane-app-members>       <!-- owners: members, roles, add by email (turn on first) -->
<appcrane-request-access></appcrane-request-access> <!-- ask the owners for access; put it on a public page -->
<appcrane-app-keys></appcrane-app-keys>             <!-- your sign-in keys for this app (turn on first) -->
```

- The script is plain JavaScript with no dependencies. Each element renders in
  its own shadow root and is styled with constructable stylesheets, so a strict
  CSP (`script-src 'self'`, no inline styles) needs no change.
- To pin the exact bytes with Subresource Integrity, read
  `/__appcrane/widgets/manifest.json` and use its `src` and `integrity`. That
  URL changes when AppCrane updates the widgets.
- The widgets call `/__appcrane/widgets/api/*` on this host with a widget
  token that is good for one hour, for this app and environment only. They never
  see your AppCrane session or an API key. Roles and owner rules are AppCrane's,
  the same as in the dashboard.
- `<appcrane-app-members>` and `<appcrane-app-keys>` are off until an owner
  turns each on (app page, Widgets card, or
  `PUT /api/apps/<slug>/widget-scopes`), because they act with the signed-in
  person's power from the app's own JavaScript.
- Someone with no role on a private app cannot sign in on its host, so on a
  public (bypass) page `<appcrane-request-access>` links them to AppCrane's own
  access-request page for this app instead.
- Elements fire `appcrane-change`, `appcrane-signed-out` and `appcrane-error`
  events (they bubble). Call `AppCraneWidgets.refresh()` to reload them.
- Not available when the app is served under a path on the AppCrane host
  instead of its own host.
