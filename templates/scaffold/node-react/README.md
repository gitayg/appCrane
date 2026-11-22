# __APP_NAME__

An Express API and a React (Vite) frontend, served as one Node process on
AppCrane, with sign-in, roles, a managed Postgres database and a health check
already wired.

## What is already done for you

| Concern | Where | What it does |
|---|---|---|
| Sign-in | `server/identity.js`, `server/app.js` | Every request except `/api/health` must carry AppCrane's signed identity; unsigned or forged requests get 401. |
| Roles | `requireAppRole()`, `requireAppDefinedRole()` | `viewer < user < admin < owner`, plus roles your app defines. |
| Database | `server/db.js`, `server/migrate.js`, `server/migrations/` | Postgres via `DATABASE_URL`; SQL migrations run at startup. |
| Health | `GET /api/health` | `{ "status": "ok", "version": "<package.json version>" }` for AppCrane's deploy check. |
| Path rules | `deployhub.json` `access` | AppCrane's proxy refuses `/api/admin/*` below admin. |
| MCP tools | `deployhub.json` `mcp` | `list_notes` and `add_note` are callable by AI agents through AppCrane. |
| Tests | `test/` | Identity (signed, unsigned, forged, altered, expired), roles, health, migrations. |

## Run the tests

```sh
npm install
npm test
```

The real-database test runs when `TEST_DATABASE_URL` points at a throwaway
Postgres (see `test/db.test.js`); otherwise it is skipped and says so.

## Run it locally

```sh
npm install
export APPCRANE_IDENTITY_SECRET="$(node -e "console.log(require('crypto').randomBytes(32).toString('base64url'))")"
npm start                                  # API on :3000
(cd client && npm install && npm run dev)  # UI with a signed test identity
curl $(npm run -s dev:headers) http://localhost:3000/api/me
```

Set `DATABASE_URL` to a local Postgres to use the notes routes.

## Change it

Replace the notes example with your own routes in `server/app.js`, a new
migration in `server/migrations/`, and your UI in `client/src/`. Keep the
identity middleware, the health route and the tests. `CLAUDE.md` lists the
rules a coding agent must follow.

## Ship it

Push the code with `appcrane_push_to_managed_app` and deploy to sandbox with
`appcrane_deploy(slug="__APP_SLUG__", stage="sandbox")`. Environment variable
names the app reads are listed in `env.example`; set their values with
`appcrane_set_secret`, never in a file.

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
