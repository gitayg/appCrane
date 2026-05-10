# AppCrane operations playbook (MCP-only)

You are an agent operating an AppCrane install through MCP. Every action you
take in this guide is an `appcrane_*` tool call. There is no `curl`, no `gh`,
no shell — if a tool doesn't exist for a thing, the thing isn't an
agent-runnable thing on this platform.

If you're onboarding a brand-new app, call
`appcrane_get_guide(topic="onboarding")` instead — that playbook covers paths
(a)/(b)/(c)/(d). This guide is for everything that comes after.

## How AppCrane is organized

- **Apps** are containerized workloads behind one of two URLs:
  `{{HOST}}/<slug>` (production) and `{{HOST}}/<slug>-sandbox`.
- Each app has a **GitHub source of truth** — either a user repo
  (`source_type='github'`) or an AppCrane-managed repo on a service account
  (`source_type='managed'`). Upload-based apps existed pre-v2.3.1; if you
  encounter one, treat it as needing migration before further work.
- **Deploys** are git-clone → build container → swap. They run sandbox-only
  by default; promotion to production is a separate step.
- **Identity** has two tiers globally (`platform_admin`, `admin`, `user`) and
  three per-app (`owner`, `admin`, `user`). Platform admins are implicit
  owners of every app.

## The deployment lifecycle

Every `appcrane_deploy` returns a `deployment_id`. The deployment moves
through these statuses:

```
pending → building → deploying → live
                                 ↘ failed
                                 ↘ rolled_back
```

- **pending** — queued; container hasn't started building.
- **building** — `docker build` is running. May take 1-10 minutes.
- **deploying** — image is built; AppCrane is swapping containers and
  running the health probe.
- **live** — health check passed; new container is serving traffic.
- **failed** — anything pre-build (clone failed, npm install died, supply-chain
  SHA mismatch, manifest invalid) OR health probe never returned 200.
- **rolled_back** — deploy completed but a later operation reverted it.

After triggering, **don't poll `appcrane_get_logs`** in a loop. Use
`appcrane_wait_deploy(deployment_id, timeout_sec=180)` — it blocks server-side
until the deployment hits a terminal status (max 600s), then returns.

## Diagnosing failures — pick the right tool

The biggest agent mistake is reading runtime container logs when the
container never started. Two log surfaces, two tools:

| Symptom | Use | Why |
|---|---|---|
| Deploy failed in 1-2 seconds | `appcrane_get_deploy_log(deployment_id)` | Pre-build error — clone, npm install, docker build, health-validate. Runtime logs don't exist. |
| Deploy went live but app behaves wrong | `appcrane_get_logs(slug, env, lines, search)` | Runtime stdout/stderr from the running container. |
| Health endpoint returns 5xx | `appcrane_get_health(slug, env)` | Server-side fetch of the app's `/api/health` from the internal port — bypasses Caddy auth, gives you the real status code + body. |
| Need to inspect a file inside the running container | `appcrane_ls(slug, env, path)` + `appcrane_cat(slug, env, path)` | Validates what actually shipped (e.g. `/app/dist/assets/`). Paths must start with `/app` or `/data`. |
| Need to push a file >256KB into a container | `appcrane_push_staged_file(slug, env, token, dest)` after uploading via `POST /api/files/staged` | Large files can't go through JSON-RPC tool args. |

Fast deploy failure (<5s) almost always means the build never started.
**Always start with `appcrane_get_deploy_log` for fast failures**, not
`appcrane_get_logs`.

## App config — read, update, never re-create

If you need to change a field on an existing app (github_url, branch, token,
visibility, resource limits, etc.) DO NOT delete and re-create the app. Use:

- `appcrane_get_app(slug)` — returns the full record including a `config`
  block with every mutable field (token shown as a boolean `token_set`,
  never plaintext).
- `appcrane_update_app(slug, ...)` — patch any subset of name / description
  / category / domain / source_type / github_url / branch / github_token /
  visibility / public_access / image_retention / frame_ancestors /
  max_ram_mb / max_cpu_percent. Empty string clears a string field;
  omitted fields are left alone; `github_token` semantics: omit = keep,
  `""` = clear, value = rotate (encrypted at rest).

## App health endpoint contract — required, server-enforced

Every deployable app MUST expose an HTTP endpoint that returns JSON with
both `status` and `version` fields. The deploy validator rejects apps
whose health endpoint doesn't return both. Default path is `/api/health`;
override via `deployhub.json:be.health`.

Minimum acceptable response:

```json
{ "status": "ok", "version": "1.2.3" }
```

If you see "Health endpoint not responding" or "version field missing" in
a deploy log, the fix is on the app's code side — add or fix the route,
push, redeploy.

## Environment variables

```
appcrane_get_env(slug, env, reveal?)   — list, optionally with values
appcrane_set_env(slug, env, key, value) — upsert a single key
```

Values are encrypted at rest (AES-256-GCM). `reveal=true` is admin-gated.
Setting an env var does not redeploy automatically — call `appcrane_deploy`
after changes to make them take effect.

## Per-app access management

The five tools that replace the old `/users` dashboard for an agent doing
access work:

| Tool | Purpose |
|---|---|
| `appcrane_list_app_members(slug)` | Who has access to this app + their role (owner/admin/user/viewer/none) |
| `appcrane_grant_app_access(slug, user, role)` | Add or upgrade. `user` accepts id, email, or username |
| `appcrane_revoke_app_access(slug, user)` | Remove entirely. Refuses to remove the last owner |
| `appcrane_list_access_requests(slug?)` | Pending end-user "Request access" submissions |
| `appcrane_approve_access_request(request_id, role)` | Grant + close the request |
| `appcrane_deny_access_request(request_id, reason)` | Close with audit-trail reason |

All require platform_admin OR admin/owner of the target app.

## Tile icons

`public/icon.png` in the repo gets auto-picked up on every deploy and shown
on every surface (Dashboard tile, Launcher cards, Manage table, frame
topbar, legacy /portal). PNG/SVG/WEBP/JPG/GIF accepted, 500KB cap.

For mid-flight changes without a redeploy: `appcrane_set_app_icon(slug,
format, base64)`. Accepts data-URL prefix or bare base64.

## Enhancement-request lifecycle

End users file "Request enhancement" submissions through the in-app
request modal. Agents work them via:

- `appcrane_list_requests(slug, bucket?)` — bucket is `new` / `selected` /
  `planning` / `in_progress` / `done`
- `appcrane_set_request_status(id, bucket)` — move through the funnel

The bigger plan-then-build flow happens elsewhere; this just exposes the
queue so an agent can triage.

## Deploys: production vs sandbox

- `appcrane_deploy(slug, env="sandbox")` — default. Always start here.
- `appcrane_deploy(slug, env="production")` — only after explicit user
  approval. Production deploys are user-visible immediately.

## Constraints worth remembering

- **Vite apps:** `base: process.env.APP_BASE_PATH || './'`. Never `'/'`.
  AppCrane does NOT inject `APP_BASE_PATH` at build time.
- **Custom Dockerfile:** `EXPOSE` must match `deployhub.json` port (default 3000).
  No `VOLUME /data` (AppCrane mounts it). No `ENV DATA_DIR` (AppCrane injects).
  Must end with `USER <non-root>`.
- **Port:** the app must `process.env.PORT || 3000`.
- **Supply-chain verify:** after clone, AppCrane cross-checks the local HEAD
  SHA against GitHub's claim for the deploying branch. Mismatch = refused
  deploy. Toggleable via `supply_chain_verify_enabled` setting.
- **Self-update:** v2.5.9+, only `platform_admin` can pull AppCrane updates.

## Working principles

1. **One MCP tool call per intent.** Don't shell out, don't try to compose
   the platform yourself.
2. **Surface failures, don't loop on them.** When a tool errors, show the
   user the error and ask before retrying. No silent recovery.
3. **Sandbox first.** Promote to production only after the user says so.
4. **Cite the tool that grounds your action.** Telling the user "I'm calling
   `appcrane_deploy slug=portal env=sandbox` because you asked me to ship
   the changes" is honest and reviewable.
5. **End every workflow with the URL + one-line summary.** "Live at
   {{HOST}}/myapp-sandbox; v0.1.2; commit `abc1234`; health green."

## When in doubt

`appcrane_list_apps` to see what you have. `appcrane_get_app(slug)` for any
single app's full state. `appcrane_get_guide(topic="onboarding")` if you're
about to onboard a new one.
