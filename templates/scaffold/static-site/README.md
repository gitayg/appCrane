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
