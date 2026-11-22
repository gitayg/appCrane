# __APP_NAME__

A static site (HTML, CSS, JavaScript in `public/`) on AppCrane, served by a
small Node server with no dependencies.

## What is already done for you

| Concern | Where | What it does |
|---|---|---|
| Sign-in | `server/identity.js`, `server/app.js` | Every file is served only with AppCrane's signed identity; unsigned or forged requests get 401. |
| Who is visiting | `GET api/me` | The signed-in person and their role, for the page to show. |
| Admin pages | `public/admin/`, `deployhub.json` `access` | Refused below the admin role, by the server and by AppCrane's proxy. |
| Health | `GET /api/health` | `{ "status": "ok", "version": "<package.json version>" }` for AppCrane's deploy check. |
| Safe paths | `resolveInside()` | Requests cannot read files outside `public/`. |
| Tests | `test/` | Identity (signed, unsigned, forged, altered, expired), admin pages, health, path traversal. |

## Run the tests

```sh
npm test
```

## Run it locally

```sh
export APPCRANE_IDENTITY_SECRET="$(node -e "console.log(require('crypto').randomBytes(32).toString('base64url'))")"
npm start
curl $(npm run -s dev:headers) http://localhost:3000/
```

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
