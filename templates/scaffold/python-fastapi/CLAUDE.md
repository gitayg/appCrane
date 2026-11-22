# __APP_NAME__ — contract for coding agents

A FastAPI service on AppCrane. These rules are what keep it safe; keep every
one of them when you change the code.

## Identity: verify, never just read
- Every request except `/api/health` goes through the `require_identity`
  middleware in `app/main.py`, which calls `verify_headers()` in
  `app/identity.py`.
- `X-AppCrane-*` headers are trusted ONLY after the `X-AppCrane-Identity-Sig-V2`
  HMAC verifies with `APPCRANE_IDENTITY_SECRET` and is under 300 s old. Never
  read an identity header anywhere else, never from a cookie, a query string or
  the body.
- Do not add a login page, password storage, JWTs or sessions. AppCrane signs
  people in; the app receives who they are.
- Do not add to `PUBLIC_PATHS` unless the route is meant for anonymous callers.
- In routes, take `identity: Identity = Depends(current_identity)` or a role
  dependency below. Fields: `user_id`, `email`, `name`, `app_role`,
  `is_app_admin`, `app_roles`, `auth_via` (`app-key` for a script, else `session`).

## Roles
- Per-app ladder `viewer < user < admin < owner`: gate with
  `Depends(require_app_role("admin"))` or `at_least()`; never
  `app_role == "admin"`, which locks owners out.
- App-defined roles (`approver`, ...) are a separate set:
  `Depends(require_app_defined_role("approver"))`.
- `/api/admin/*` is also refused below admin at AppCrane's proxy by the
  `access` rule in `deployhub.json`. Keep the in-app checks anyway.

## Database
- Postgres is declared in `deployhub.json`; AppCrane injects `DATABASE_URL`
  with TLS parameters in it. Sandbox and production get separate databases.
- Never hardcode a connection string or password.
- Schema changes are new files in `app/migrations/` (`002_<name>.sql`, ...),
  applied at startup. Never edit or delete one that has been deployed.
- Always pass values as query parameters (`%s`), never by string formatting.

## Health and version
- `GET /api/health` stays public and returns 200 with `status` and `version`.
  `version` is read from `deployhub.json`: bump it there for every release.

## Container
- The `Dockerfile` must keep `EXPOSE 3000`, a non-root `USER`, and no secrets in
  `ENV`. AppCrane injects `PORT`; uvicorn listens on it.
- Pin every dependency in `requirements.txt` with `==`.

## Secrets and config
- No secrets in the repository and no `.env` files (AppCrane refuses a push with
  one). Variable names are listed in `env.example`. Set values with
  `appcrane_set_secret`.
- When the app's LLM gateway is enabled AppCrane injects `ANTHROPIC_BASE_URL` /
  `ANTHROPIC_API_KEY` (and/or the `OPENAI_*` pair) pointing at its gateway. The
  official SDKs read them; never put a provider key in the app.

## MCP tools
- `deployhub.json` `mcp.tools` exposes routes as MCP tools. Calls arrive with
  the caller's signed identity, so the same checks apply.

## Shipping
- Run `pytest` before every push; it must pass.
- Push with `appcrane_push_to_managed_app`, then
  `appcrane_deploy(slug="__APP_SLUG__", stage="sandbox")`. Production only when
  a person asks.
