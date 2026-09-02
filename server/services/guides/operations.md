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
- Most apps have a **GitHub source of truth** — either a user repo
  (`source_type='github'`) or an AppCrane-managed repo on a service account
  (`source_type='managed'`). An app can also be **upload-only**
  (`source_type='upload'`, v2.53.0): no repo, releases arrive as bundles. That
  is a deliberate mode, not a broken one — do not "fix" it by attaching a repo.
- `source_type='managed_legacy'` is different and DOES need migration: it marks
  pre-v2.3.1 upload apps, which redeploy an old release directory and cannot
  accept new bundles.
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
| Need to deploy but the repo path is unavailable | `appcrane_deploy_artifact(slug, env, token)` after uploading the bundle via `POST /api/files/staged` | Deploys from bytes, touching GitHub not at all. This is the fallback when the service-account PAT returns 401 and every managed-repo write fails — and the only deploy path a `dhk_mcp_*` key can take, since dhk_app_* keys were removed in v2.2.12. |

### Renaming an app

`appcrane_rename_app(slug, new_slug, redirect?)` (platform admin), or
`POST /api/apps/<slug>/rename` for the same thing over REST. Both run the same
code. `appcrane_update_app` cannot do it — that tool changes name, domain and
source, never the slug.

The rename is **not destructive**. Deploy history, env vars, ports, per-app
roles and grants all key off `apps.id`, not the slug, so they survive untouched.
The old slug is recorded in `slug_aliases` and keeps redirecting, the data
directory is moved, Caddy is reloaded, and every live environment is redeployed.

Two things it does **not** do: a managed app's `AMC_<slug>` GitHub repo keeps
its original name (the stored `github_url` keeps clones working, but the names
diverge permanently), and any external DNS pointing at the old URL is yours to
re-point. It does not touch `domain` either — a custom domain already on the app
carries over untouched.

**Need a slug another app is holding?** Do not delete that app — rename it out
of the way with `redirect: false`, then take the slug:

```
appcrane_rename_app slug="wanted"  new_slug="wanted-retired" redirect=false
appcrane_rename_app slug="realapp" new_slug="wanted"
```

`redirect: false` matters: without it the retired app keeps an alias claiming
the slug you are freeing. This frees the data directory too, which deleting does
not — `DELETE /api/apps/<slug>` clears the rows and stops the containers but
leaves `data/apps/<slug>` on disk, and a rename onto a slug whose directory
still exists is refused (a directory rename only succeeds onto an empty target).
Renaming the squatter is non-destructive and reversible; deleting is neither.

### Deploying without a repo, entirely over MCP

For an app with no GitHub repo — or when the repo path is broken — bytes reach
AppCrane over MCP with no curl:

**Pick by where the bytes are, not by habit.** All three end in a staged token
for `appcrane_deploy_artifact`; they differ enormously in cost.

1. **The file is reachable at a URL** (release asset, S3/R2 presigned link) —
   `appcrane_stage_from_url { url, sha256 }`. AppCrane downloads it. Costs the
   same few dozen tokens whatever the size. Prefer this.
2. **You have a shell** —
   `curl -F file=@dist.zip -H "X-API-Key: <your dhk_mcp_ key>" https://<host>/api/files/staged`.
   That endpoint accepts MCP keys, so this is not a workaround around key scope;
   it is the supported upload channel, and the bytes never enter the agent's
   context.
3. **Neither, and the file is small** — `appcrane_stage_chunk` +
   `appcrane_stage_assemble`. Capped at 8 parts on purpose: every byte here is
   emitted by the model, one base64 character at a time, so a large file costs
   output tokens per character and fails the digest on a single typo.

```
appcrane_stage_from_url  url="https://.../dist.zip" sha256=<digest>
appcrane_deploy_artifact slug="myapp" env="production" token=<from staging>
```

Pass the whole-file `sha256` wherever you stage — it is what ties the deployed
artifact to the one you built, and it becomes the release identity
(`commit_hash = sha256:<digest>`). An upload app can also be redeployed from the
release it is already running, with no new bundle, via `appcrane_deploy`.

`stage_from_url` is https-only, does not follow redirects, and refuses hosts
that resolve to private or link-local addresses — a server that fetches URLs on
request is one prompt away from being a proxy into its own network.

### A self-update that fails on EBADENGINE

```
npm error code EBADENGINE
npm error notsup Required: {"node":">=22"}  Actual: {"node":"v20.20.2"}
```

Seen on AppCrane **older than v2.57.0**, where `.npmrc` set `engine-strict=true`
and npm refused to install Node-22 dependencies onto Node 20.

It happens on hosts provisioned below the current floor, because the updater
that runs is always the version being upgraded **from** — a box on a release
older than v2.51.0 has an updater with no Node step. Its `git reset --hard`
succeeds and the `npm install` after it does not, so the tree ends up ahead of
`node_modules` and the update stops.

From v2.55.2 the updater reconciles the runtime *before* it moves the tree, and
reads the floor from the release it is about to install rather than the one it
is replacing — so a refusal on a newer updater is a clean no-op.

From v2.57.0 the stall does not happen at all. `engine-strict` is gone, so the
install completes on the old runtime and the old updater reaches its own
`process.exit(0)`; systemd re-execs, and `scripts/safe-boot.sh` raises Node to
the floor before the app starts. Nothing to do by hand. If the runtime cannot be
raised and the new release genuinely cannot run, the boot crashes and the
sentinel rolls back to the previous SHA.

**The fix is a restart, not a repair.** systemd's `ExecStart` is
`scripts/safe-boot.sh`, a file inside that tree — so the reset that failed to
finish still delivered a new boot wrapper. On the next start it raises Node to
the floor and runs the install the update could not.

From v2.56.0 a platform admin can trigger that without ssh:

```
POST /api/self-update/restart?confirm=1
```

It writes nothing and fetches nothing — it exits so the supervisor re-execs on
the code already on disk. Older hosts need the shell:

```bash
sudo systemctl restart appcrane
```

`Restart=always` means a reboot or a crash does the same thing unattended. If
the host does not permit an automatic upgrade (no apt, or no root and no
passwordless sudo) the wrapper still boots and logs the two commands to run —
check `journalctl -u appcrane | grep safe-boot`.

### A crash loop after a Node upgrade

```
The module '.../better_sqlite3.node' was compiled against a different
Node.js version using NODE_MODULE_VERSION 115. This version requires 127.
```

better-sqlite3 is a V8-ABI addon, not N-API, so **any** Node major change breaks
it — including one `unattended-upgrades` applies with no AppCrane update at all.
The process then dies on every boot.

`scripts/safe-boot.sh` repairs this on the way up (v2.58.0): it probes the addon
before starting the app and runs `npm rebuild better-sqlite3` when it fails. A
restart is enough. Two things worth knowing if you are diagnosing it by hand:

- **`require("better-sqlite3")` succeeds on a mismatched ABI.** The addon loads
  lazily, on the first `new Database()`. Any health check that only requires the
  module will report a host healthy seconds before it crash-loops.
- **`npm install` does not fix it.** npm treats node_modules as satisfied and
  skips the addon. Only `npm rebuild` recompiles against the new ABI.

Pinning Node in apt (`/etc/apt/preferences.d/`) stops unattended-upgrades moving
the major version, at the cost of also holding back Node security updates. It is
a reasonable belt-and-braces measure; the rebuild is the one that reaches hosts
you have not pinned yet.

### Vulnerability scanning

Every deploy scans the release's dependency manifests against OSV, and a daily
pass rescans the fleet — advisories get published after a deploy, so scanning
only at deploy time goes stale on its own. `package-lock.json`, `go.sum`,
`Cargo.lock`, `Gemfile.lock`, `poetry.lock` and `Pipfile.lock` are read, with
the ecosystem tracked per package (OSV's answer depends on it).

Findings are **reported, never blocking**. A scan that fails a deploy turns a
security signal into an outage, and the first time it does someone switches it
off. A manifest that cannot be *parsed*, however, fails the whole scan rather
than contributing nothing to one that then reports `ok` — a scan that looked at
nothing must not look like a clean scan.

Owners get a daily digest for their own apps; platform admins get the fleet.
`appcrane_scan_report` answers the same question on demand and is scoped to what
the caller can see.

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
appcrane_get_secret(slug, env)          — list keys with MASKED values (safe for chat)
appcrane_reveal_secret(slug, env, key)  — plaintext of ONE key (lands in transcript; audited)
appcrane_set_env(slug, env, key, value) — upsert a single key
```

Values are encrypted at rest (AES-256-GCM). `appcrane_get_secret` never returns
plaintext — you get is_set / length / a last-3-char preview / a sha256 fingerprint,
which is what you need to check "is X set?" or "did it change?". Only
`appcrane_reveal_secret` returns a real value, one key at a time, and that value
appears in the conversation — reveal only when the user explicitly needs it, not
to inspect config. Setting an env var does not redeploy automatically — call
`appcrane_deploy` after changes to make them take effect.

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

The three below are a **different system**: the roles an app defines for itself
(`approver`, `auditor`…). They confer nothing on AppCrane — no deploy, no env, no
delete — and are only handed to the app to enforce. Reach for
`appcrane_grant_app_access` above when you mean platform power, and for these
when you mean an app's own label. See the onboarding guide for the wire contract.

| Tool | Purpose |
|---|---|
| `appcrane_list_app_roles(slug)` | The roles this app defines + which members hold each |
| `appcrane_create_app_role(slug, key, label, description?)` | Define a role. Grants it to nobody. Owner/admin of the app |
| `appcrane_set_user_app_roles(slug, user, keys)` | Replace that user's whole set. `keys: []` clears it |

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

## Complete MCP tool reference

Every `appcrane_*` tool, grouped by purpose. The authoritative input schema for each is on the tool itself (your MCP client shows it) — this is the at-a-glance index.

### Discovery & info

| Tool | What it does |
|---|---|
| `appcrane_list_apps` | List all AppCrane apps the current user has access to |
| `appcrane_get_app` | Get detailed info for a single app: URLs, current versions per environment, recent deployments, and health state |
| `appcrane_get_health` | Fetch the deployed app's health endpoint server-side, bypassing AppCrane's auth proxy |
| `appcrane_get_logs` | Get recent runtime logs from a running app container (docker logs) |
| `appcrane_get_deploy_log` | Read the deploy/build log for a specific deployment — the output that came out of clone / npm install / docker build / health-validate, BEFORE the ... |
| `appcrane_list_releases` | List the deploy/release history for an app + env, newest first — each release is id, version, commit, status (live / rolled_back / failed / pending... |
| `appcrane_top_apps` | Top apps by distinct active users in a lookback window |
| `appcrane_top_users` | Top users by distinct apps opened in a lookback window |

### Deploy lifecycle

| Tool | What it does |
|---|---|
| `appcrane_deploy` | Trigger a deployment — this IS how you "update an env to the latest" |
| `appcrane_wait_deploy` | Block until a deployment reaches a terminal state (live / failed / rolled_back), then return its final status |
| `appcrane_rollback` | Roll an env back to a prior release |
| `appcrane_promote` | Promote the current live SANDBOX release to production — the gated sandbox→prod path |
| `appcrane_list_cron` | List the scheduled jobs declared in an app's deployhub.json `cron` array (after the most recent deploy) |
| `appcrane_run_cron_now` | Trigger a scheduled cron job RIGHT NOW, regardless of its schedule |
| `appcrane_check_resource_limits` | Which containers are NOT running with their configured CPU/RAM? Admin only |

### Platform operations (platform admin)

`--memory`, `--cpus` and a port publish are all `docker run` flags: changing one
rewrites the database row and nothing else until the container is **recreated**.
A container created before the change keeps running without it, and every other
surface reports the *configured* value. `appcrane_check_resource_limits` is what
tells the two apart — `state: not_applied` on memory means no limit at all, so
that container can take the whole host.

Off-site backup has existed since v2.21.9 and is a no-op until a bucket and
credentials are entered, which made it easy to believe there was no backup
feature at all. These make the state answerable without opening Settings:

| Tool | What it does |
|---|---|
| `appcrane_get_backup_status` | Is off-site backup configured, enabled, and when did it last actually run? Never returns the secret |
| `appcrane_set_backup_config` | Set bucket / region / prefix / endpoint / key / schedule. Refuses to enable an incomplete config |
| `appcrane_run_backup_now` | Run it immediately to prove the credentials work, rather than finding out at 03:00 |

The backup covers `deployhub.db`, `.env`, icons and appdata — a copy of every
secret AppCrane holds. Treat the destination bucket accordingly; that is why all
three are platform-admin only, and why the secret access key is write-only and
better entered in Settings → Backup than passed through an agent.

### App management

| Tool | What it does |
|---|---|
| `appcrane_create_app` | Register a new app in AppCrane from a GitHub repository |
| `appcrane_create_managed_app` | Create a new app using AppCrane's GitHub service-account — the platform creates a repo on the configured org/user, owns it, and the agent works aga... |
| `appcrane_update_app` | Patch fields on an existing app |
| `appcrane_set_app_meta` | Set an app's category, visibility, auth_mode, and/or auth_bypass_paths — the owner self-service fields (same controls the dashboard Launcher expose... |
| `appcrane_set_app_icon` | Set the tile icon for an app (shown on the Dashboard, the Launcher cards, the Manage table, and the frame topbar) |

### Env & files & data

| Tool | What it does |
|---|---|
| `appcrane_get_secret` | List env vars with MASKED values (preview + fingerprint) — safe for chat |
| `appcrane_reveal_secret` | Reveal ONE env var's plaintext by key (lands in transcript; audited) |
| `appcrane_set_env` | Set or update an environment variable on an app |
| `appcrane_set_data_blob` | Write a blob directly to the app's persistent /data volume on the host — single hop, no container round-trip, no GitHub round-trip, no inline size ... |
| `appcrane_ls` | List files inside a running app container at a specific path |
| `appcrane_cat` | Print the contents of a file inside a running app container |
| `appcrane_push_staged_file` | Move a previously-staged file (uploaded via POST /api/files/staged) into a running container at a path under /app or /data |
| `appcrane_deploy_artifact` | Deploy a release from a staged bundle (.zip/.tar.gz/.tgz) instead of from git. Identified by a SHA-256 AppCrane computes over the bytes, recorded as `commit_hash = sha256:<digest>` |
| `appcrane_stage_from_url` | Have AppCrane download a file and stage it. The cheap path for artifacts — bytes never enter the agent's context |
| `appcrane_stage_chunk` | Upload one part of a SMALL file over MCP. Max 8 parts; the model emits every byte |
| `appcrane_stage_assemble` | Join the parts into a staged file and return its token, verifying the whole-file SHA-256 |
| `appcrane_rename_app` | Rename an app's slug. Not destructive — history, env vars, ports and grants key off the app id |
| `appcrane_scan_report` | CVE findings for an app, or across the fleet (scoped to apps you can see) |
| `appcrane_scan_app` | Scan one app's dependency manifests against OSV now, instead of waiting for the daily pass |
| `appcrane_platform_policy` | Read or set the platform levers: ban public apps, require security scans (platform admin) |
| `appcrane_push_to_managed_app` | Push a batch of files to a managed app's AMC_<slug> repo, authenticated server-side via AppCrane's service-account credential |

### Access control

| Tool | What it does |
|---|---|
| `appcrane_list_app_members` | List every user who has access to an app, with their per-app role (owner / admin / user / viewer / none) |
| `appcrane_grant_app_access` | Grant a user access to an app at a specific per-app role |
| `appcrane_revoke_app_access` | Remove a user's access from an app entirely |
| `appcrane_list_access_requests` | List pending access requests — enhancement_requests rows whose message starts with "Access request for app …" (the portal's Request-access button p... |
| `appcrane_approve_access_request` | Approve a pending access request: grants the requester access to the app at `role` (default "user") and marks the enhancement_request as done |
| `appcrane_deny_access_request` | Deny a pending access request: marks the enhancement_request as done WITHOUT granting access |
| `appcrane_list_app_roles` | List the roles an app defines FOR ITSELF (approver, auditor…) and which members hold each. Not AppCrane permissions — the app enforces them |
| `appcrane_create_app_role` | Define a new app-defined role. Grants it to nobody; confers nothing on the platform. Owner/admin of the app |
| `appcrane_set_user_app_roles` | Replace the whole set of app-defined roles a user holds on one app. Does not touch their AppCrane per-app tier |

### Requests & guides

| Tool | What it does |
|---|---|
| `appcrane_list_requests` | List enhancement requests filed against an app via the AppCrane intake form |
| `appcrane_set_request_status` | Move a request through the lifecycle: triage → in_progress → shipped → validated |
| `appcrane_get_guide` | Fetch the latest AppCrane playbook on a given topic |
