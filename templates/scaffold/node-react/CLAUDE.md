# __APP_NAME__ — contract for coding agents

This app runs on AppCrane. These rules are what keep it safe; keep every one
of them when you change the code.

## Identity: verify, never just read
- Every request except `/api/health` goes through `requireIdentity()` in
  `server/app.js`, which calls `verifyRequest()` in `server/identity.js`.
- `X-AppCrane-*` headers are trusted ONLY after the `X-AppCrane-Identity-Sig-V2`
  HMAC verifies with `APPCRANE_IDENTITY_SECRET` and the timestamp is under 300 s
  old. Never read an identity header anywhere else, never from a cookie, a query
  string or the request body.
- Do not add a login page, password storage, JWTs or a session system. AppCrane
  signs people in; the app receives who they are.
- Do not add paths to `PUBLIC_PATHS` unless the route is meant for anonymous
  callers. Do not catch and ignore a failed verification.
- Use `req.identity` in routes: `userId`, `email`, `name`, `appRole`,
  `isAppAdmin`, `appRoles` (the app's own roles), `authVia` (`app-key` for a
  script using an app sign-in key, else `session`).

## Roles
- Per-app ladder: `viewer < user < admin < owner`. Gate with
  `requireAppRole('admin')` (or `atLeast()`); never compare `appRole === 'admin'`,
  which locks owners out.
- App-defined roles (`approver`, `auditor`, ...) are a separate set: gate with
  `requireAppDefinedRole('approver')`. Define and grant them with the
  `appcrane_create_app_role` / `appcrane_set_user_app_roles` MCP tools.
- `/api/admin/*` is also refused below admin at AppCrane's proxy by the
  `access` rule in `deployhub.json`. Keep server-side checks anyway.

## Database
- Postgres is declared in `deployhub.json` (`"database": { "engine": "postgres" }`).
  AppCrane provisions it and injects `DATABASE_URL` with TLS parameters already
  in it; sandbox and production get separate databases.
- Never hardcode a connection string, host or password. Never ask for one.
- Schema changes are new files in `server/migrations/` (`002_<name>.sql`, ...),
  applied at startup. Never edit or delete a migration that has been deployed.
- Always use parameterised queries (`$1`, `$2`), never string concatenation.

## Health
- `GET /api/health` must stay public and return 200 with JSON containing
  `status` and `version` (`version` comes from `package.json`). AppCrane rolls a
  deploy back when it does not.

## Secrets and config
- No secrets in the repository. Set values with `appcrane_set_secret` /
  `appcrane_set_env`; read them from `process.env`.
- Do not commit `.env` files: AppCrane refuses a push containing one. The list
  of variable names lives in `env.example` (names only, no values).
- AppCrane injects `PORT`, `DATA_DIR` (persistent `/data`),
  `APPCRANE_IDENTITY_SECRET`, `APPCRANE_SERVICE_TOKEN` + `CRANE_INTERNAL_URL`
  (email service), and, when the app's LLM gateway is enabled,
  `ANTHROPIC_BASE_URL`/`ANTHROPIC_API_KEY` and/or `OPENAI_BASE_URL`/`OPENAI_API_KEY`
  pointing at AppCrane's gateway. Use the official SDKs with those variables;
  never put a provider key in the app.
- Audit events: `server/audit.js` `auditEvent(action, { req, targets, metadata })`
  writes to AppCrane's audit store with the service token. Register the action
  on the app first; pass `req` so the signed-in user is the actor.

## Frontend
- Vite `base` stays `process.env.APP_BASE_PATH || './'`. Never `'/'`.
- API calls use relative paths (`api/notes`, no leading slash) so they work
  under the app's sub-path.

## MCP tools
- `deployhub.json` `mcp.tools` exposes routes as MCP tools. Calls arrive with
  the caller's signed identity, so the same verification and role checks apply.

## Shipping
- Run `npm test` before every push; it must pass.
- Push with `appcrane_push_to_managed_app`, then
  `appcrane_deploy(slug="__APP_SLUG__", stage="sandbox")`. Deploy to production
  only when a person asks.

## AppCrane widgets
- For a user menu, sign-out, session list, member management, access requests
  or app sign-in keys, use AppCrane's widgets instead of building them:
  `<script src="/__appcrane/widgets.js" defer>` and the `<appcrane-*>` elements
  listed in README.md. Do not proxy, wrap or re-implement `/__appcrane/*`, and
  never route it to the app: AppCrane answers those paths on the app's host.
