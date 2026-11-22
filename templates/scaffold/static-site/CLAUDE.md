# __APP_NAME__ — contract for coding agents

A static site on AppCrane. The content lives in `public/`; `server/` is a small
dependency-free Node server that serves it. Keep every rule below.

## Identity: verify, never just read
- `server/app.js` serves nothing but `/api/health` until `verifyRequest()` in
  `server/identity.js` accepts the request. Keep that order.
- `X-AppCrane-*` headers are trusted ONLY after the `X-AppCrane-Identity-Sig-V2`
  HMAC verifies with `APPCRANE_IDENTITY_SECRET` and is under 300 s old.
- Do not add a login page, passwords or tokens: AppCrane signs people in.
- `GET api/me` returns the visitor (`userId`, `email`, `name`, `appRole`,
  `appRoles`). Per-app roles rank `viewer < user < admin < owner`; compare with
  `atLeast()` from `server/identity.js`, never `=== 'admin'`.
- Hiding something in the page's JavaScript is not access control. Pages only
  admins and owners may see go under `public/admin/`: the server refuses them
  below admin, and so does AppCrane's proxy (the `access` rule in
  `deployhub.json`). Keep both.

## Files
- Put site files in `public/` only; `resolveInside()` refuses paths that leave it.
- Use relative links (`./styles.css`, `api/me`), never a leading `/`: AppCrane
  serves the site under a sub-path.

## Database
- This template has none. If the site needs data, add
  `"database": { "engine": "postgres" }` to `deployhub.json` (AppCrane injects
  `DATABASE_URL`), or start from the `node-react` template instead.

## Health
- `GET /api/health` stays public and returns 200 with `status` and `version`
  (from `package.json`). AppCrane rolls back a deploy that does not.

## Secrets and config
- No secrets in the repository, and no `.env` files (AppCrane refuses a push
  with one). Variable names are listed in `env.example`.

## Shipping
- Run `npm test`; it must pass. Push with `appcrane_push_to_managed_app`, then
  `appcrane_deploy(slug="__APP_SLUG__", stage="sandbox")`. Production only
  when a person asks.

## AppCrane widgets
- For a user menu, sign-out, session list, member management, access requests
  or app sign-in keys, use AppCrane's widgets instead of building them:
  `<script src="/__appcrane/widgets.js" defer>` and the `<appcrane-*>` elements
  listed in README.md. Do not proxy, wrap or re-implement `/__appcrane/*`, and
  never route it to the app: AppCrane answers those paths on the app's host.
