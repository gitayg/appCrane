# AppCrane

**The self-hosted home for the apps your AI builds and your AI deploys.**

[![GitHub stars](https://img.shields.io/github/stars/gitayg/appCrane?style=flat)](https://github.com/gitayg/appCrane/stargazers)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](LICENSE)
![Platform: Ubuntu 22.04+](https://img.shields.io/badge/platform-Ubuntu%2022.04%2B-e95420)

Vibe-code an app with Claude Code or Cursor, then have your AI agent deploy it — over MCP — to a server **you** own. Docker isolation per app, SAML/OIDC SSO, per-user audit that distinguishes agents from humans, per-tenant data isolation, and a middleware hard-wall so the platform operator can't read your app secrets.

**MCP-first.** AI agents connect once via `claude mcp add ... /api/mcp` and operate the platform through 39 `appcrane_*` tools — create, deploy, read logs, set env, **roll back**. No curl, no separate scripts. `appcrane_get_guide(topic="onboarding"|"operations")` returns the current playbook on demand.

## Why AppCrane

Tools for AI-built internal apps split cleanly along two axes, and one corner is empty:

|  | **Ungoverned** | **Governed** |
|---|---|---|
| **Vendor-hosted** | v0, Bolt.new | Lovable, Replit, Retool, Superblocks — SSO and audit, but your app data, DB connections and API keys live on *their* multi-tenant cloud |
| **Self-hosted** | Coolify, Dokku, CapRover, Dokploy — your infra, but no SSO, no RBAC, no per-user audit, no tenancy model | **AppCrane** |

You can have governance, or you can have your own infrastructure. Every other option makes you pick. That gap is the entire reason this exists — it was built for a company that needed both and found nothing that did both.

**Why it matters now.** Three things changed in 2026:

- **The bottleneck moved from writing software to operating it.** In Anthropic's [Claude Code study](https://www.anthropic.com/research/claude-code-expertise) (~400k sessions), "operating software" — deploying, configuring, running pipelines — grew from 14% to 21% of sessions while fixing broken code fell from 33% to 19%. Non-engineers now ship deployable code within 7 points of professional engineers. The scarce thing isn't the app any more; it's somewhere safe to run it.
- **Shadow AI became measurable.** The [2026 Verizon DBIR](https://www.verizon.com/business/resources/reports/dbir/) reports shadow-AI detections up 4×, AI use on corporate devices rising 15% → 45% in a year with 67% through non-corporate accounts — and source code as the most commonly submitted data type. Bans make it worse; a sanctioned platform is the answer that works.
- **Governance-by-console is the failure mode.** Platforms that gate every app behind a human clicking through an approval UI stall once there are hundreds of apps. AppCrane's answer is different in kind: the **agent** drives the governed lifecycle over MCP, and the platform records and constrains it — rather than a person mediating each step.

### Against self-hosted PaaS

| Feature | AppCrane | Coolify | Dokploy |
|---|---|---|---|
| Agent-first / MCP-native | ✅ | ~ thin | ~ 508 flat tools |
| MCP rollback (undo, not just redeploy) | ✅ | ❌ | ✅ |
| Enterprise SSO (SAML/OIDC/SCIM) | ✅ | ~ | ❌ paid tier |
| Per-user audit, agent vs human attributed | ✅ | ~ | ❌ |
| Per-tenant DB + storage isolation | ✅ | ❌ | ❌ |
| Secret hard-wall (operator can't read) | ✅ | ❌ | ❌ |
| Managed repo (no GitHub account needed) | ✅ | ❌ | ❌ |
| Self-hosted, your infra | ✅ | ✅ | ✅ |
| Open source | ✅ AGPL-3.0 | ✅ Apache-2.0 | ✅ Apache-2.0 |

**Honest scope:** Coolify has a far larger template marketplace, a bigger community, and multi-server orchestration. If you want one-click Postgres and 280 app templates, use Coolify. Choose AppCrane when the apps are AI-built, the agent should do the deploying, and you need to prove afterwards who did what.

**Full matrix** vs AWS Copilot / App Runner / Lightsail / CodeDeploy / Vercel → **[glick.run/comparison.html](https://glick.run/comparison.html)**

## Features

- **Docker container isolation** — every app runs in its own container; no shared dependencies, no runaway processes
- **Enterprise SSO** — SAML 2.0, OIDC, and SCIM provisioning; connect to Okta, Azure AD, Google Workspace
- **Identity forwarded to apps as headers** — `X-AppCrane-User-Role`, `X-AppCrane-App-Role`, etc. are injected by the proxy after `forward_auth` verifies the user; deployed apps read identity directly off the request without a callback (oauth2-proxy / IAP pattern)
- **`/api/me` endpoint** — canonical "who is the caller" for proxied apps; accepts the `cc_token` cookie, Bearer, or `X-API-Key`; returns global role + per-app role (`?app=<slug>` or `Referer`-inferred)
- **Headless app type** — set `auth_mode: 'headless'` to bypass `forward_auth` entirely on an app; right tool for telemetry ingest, public webhooks, status pages, and single-purpose unauthenticated services
- **AppStudio AI pipeline** — AI proposes code improvements on a schedule; you review and approve before anything ships
- **Real-time presence** — see who's active on each app, which environment, and when they last deployed
- **Dual environments** per app: production + sandbox, always-on, separate ports
- **Auto-HTTPS** via Caddy reverse proxy with Let's Encrypt
- **GitHub webhook auto-deploy** on push (HMAC-verified)
- **Zero-downtime deploys** (start new, health check, swap, drain old)
- **Rollback in seconds** (symlink-based, keeps last 5 releases)
- **Encrypted env vars** (AES-256-GCM) — admin cannot read them by design
- **Health checks** with auto-restart and email notifications
- **Audit log** for every action
- **MCP server** at `/api/mcp` exposing 39 `appcrane_*` tools — agents operate the platform without ever touching curl, gh, or shell

## Quick Start

**One command** on a fresh Ubuntu server installs and wires up *everything* — Node,
Caddy (with automatic HTTPS), Docker, the systemd service, an encrypted-secrets key,
and your admin user:

```bash
curl -fsSL https://raw.githubusercontent.com/gitayg/appCrane/main/install.sh | sudo bash
```

It prompts for just two things — your **domain** and **admin email** — and is safe to
re-run. When it finishes, point your domain's DNS at the server and you're live.

**Prerequisites:** a fresh Ubuntu server (root / sudo) and a domain whose DNS `A`
record points at it — Caddy provisions TLS automatically on first request.

**Non-interactive** (CI / automation) — no prompts:

```bash
sudo CRANE_DOMAIN=crane.example.com ADMIN_EMAIL=admin@example.com bash install.sh
# flags also work: --domain / --admin-email / --admin-name / --tls-cert / --tls-key
```

<details>
<summary><b>What the installer sets up — and why installing by hand isn't recommended</b></summary>

Everything below is done for you, idempotently, by the one command above:

- **Node.js 20** + AppCrane, with the `crane` CLI linked globally
- **Caddy** — the reverse proxy that routes `<domain>/<slug>` to each app, runs the
  SSO auth, injects the `X-AppCrane-*` identity headers, and auto-provisions TLS —
  **plus** the group, file permissions, and a `sudoers` rule so AppCrane can reload
  Caddy on every deploy
- **Docker** + a **systemd** `appcrane` service (`Restart=always` — survives crashes
  and reboots, and powers one-click self-update)
- A `.env` with a freshly generated `ENCRYPTION_KEY` — **back this up; losing it makes
  every stored secret unrecoverable** — and your admin user (`crane init`)

Installing by hand means reproducing all of that — **especially the Caddy install +
permissions + sudoers**, which is the most-missed step and later surfaces as
permission errors or apps that never receive their identity headers. If you must,
treat [`install.sh`](install.sh) as the source of truth rather than a shortened list.

> **AppStudio (optional):** to enable AI app-building, set an Anthropic API key —
> `systemctl edit appcrane --force`, add `Environment="ANTHROPIC_API_KEY=sk-ant-..."`
> under `[Service]`, then `systemctl daemon-reload && systemctl restart appcrane`.

</details>

### Deploy your first app

The installer already created your admin user, so once DNS points at the box:

```bash
# Reachable at https://<your-domain>/myapp
crane app create --name "MyApp" --slug myapp --repo https://github.com/yourorg/myapp
crane deploy myapp --env sandbox

# Give a teammate access (optional)
crane user create --name sarah --email sarah@example.com
crane app assign myapp --email sarah@example.com
```

## CLI Reference

### Server
```bash
crane status                              # Server health: CPU, RAM, disk, apps
crane config --show                       # Show CLI config
crane config --url http://localhost:5001  # Set API URL
crane config --key dhk_admin_xxx          # Set API key

# Recover a lost platform-owner API key (run on the box, direct DB).
# Defaults to the platform_admin; override to target a specific account:
crane regenerate-key                      # Regenerate the platform owner's key
crane regenerate-key --email you@ex.com   # ...for a specific user by email
crane regenerate-key --user-id 1          # ...or by user id
```

### Migrate config between instances
Move the platform `settings` (including encrypted secrets) to another AppCrane —
without sharing encryption keys. Export keeps secrets ciphertext; import
re-encrypts them with the target instance's own key.
```bash
# On the SOURCE instance:
crane config export --out config.json

# Copy config.json to the TARGET, then on the TARGET:
OLD_ENCRYPTION_KEY=<source ENCRYPTION_KEY> crane config import config.json
```
The source `ENCRYPTION_KEY` (from the source's `.env`) is needed only to decrypt
the secrets during import; it is used transiently, never stored. One-way values
(e.g. the SCIM token, stored as a hash) can't be migrated — the import lists them
to regenerate on the target. Delete `config.json` afterward.

### Apps (admin)
```bash
crane app list
crane app create --name X --slug x --domain x.example.com --repo https://github.com/...
crane app info myapp
crane app delete myapp --confirm
crane app assign myapp --email user@example.com
```

### Deploy (app user)
```bash
crane deploy myapp --env sandbox
crane deploy myapp --env production
crane deploy:history myapp --env prod
crane deploy:log myapp --id 5
crane rollback myapp --env production
crane promote myapp                       # sandbox → production, zero downtime
```

### Env Vars (app user — admin cannot access)
```bash
crane env set myapp --env sandbox DATABASE_URL=postgres://... API_KEY=sk-test
crane env list myapp --env production
crane env list myapp --env sandbox --reveal
crane env delete myapp API_KEY --env sandbox
```

### Health, Webhooks, Backups
```bash
crane health status myapp
crane health config myapp --env prod --endpoint /api/health --interval 30
crane webhook myapp --auto-sandbox on
crane backup create myapp --env prod
crane backup list myapp
crane logs myapp --env production
crane audit --app myapp
```

## MCP (for AI agents)

AppCrane is MCP-first. One `claude mcp add` and the agent gets 35
`appcrane_*` tools — list apps, deploy, set/get secrets, read logs,
manage access, rotate icons, the lot. Tool names are AWS-aligned
(`stage`, `set_secret`/`get_secret`, `cp`).

```bash
claude mcp add --transport http appcrane https://crane.example.com/api/mcp \
  --header "X-API-Key: dhk_admin_or_user_xxxxxxxxxxxxx" \
  --header "X-Github-Token: ghp_your_github_pat"
```

Then in any Claude Code session:

> Onboard a new app. Start by calling `appcrane_get_guide` with `topic="onboarding"` for the playbook.

The agent pulls the current guide from the server, so edits propagate
without a redeploy of your tooling. `topic="operations"` returns the
post-onboarding reference (deploy lifecycle, troubleshooting fast
failures, access management, etc.).

## Architecture

```
Ubuntu Server
├── Caddy (reverse proxy, auto-HTTPS)
│   ├── myapp.example.com          → production app
│   └── myapp-sandbox.example.com  → sandbox app
├── Docker (container isolation)
│   ├── myapp-production           ← isolated container per env
│   └── myapp-sandbox
├── AppCrane API (:5001)
│   ├── Express 5 + SQLite
│   ├── Health checker (cron)
│   ├── SSO (SAML / OIDC / SCIM)
│   ├── AppStudio AI pipeline
│   └── Presence (WebSocket)
└── /data/apps/myapp/
    ├── production/releases/       (symlink-based, last 5)
    └── sandbox/releases/
```

## Security

- **Init locked to localhost** — admin setup only from the server itself
- **API key auth** — all requests require `X-API-Key` header
- **Admin isolation** — admin cannot read env vars or `/data/`; enforced at middleware level
- **AES-256-GCM** encrypted env vars at rest
- **Webhook HMAC** verification for GitHub
- **SCIM deprovisioning** — removing a user from your IdP revokes AppCrane access automatically
- **All actions audited** — who did what, when

### Supply chain — SBOM + build provenance

A deployment self-updates straight from git (`/api/self-update` runs `git fetch`
+ `git reset --hard origin/main`), so the question a reviewer asks is "how do I
know the source I pulled is the source you published?" Every tagged release
answers it with four attached artifacts:

| Artifact | What it is |
|---|---|
| `appcrane-<tag>-source.tar.gz` | Reproducible `git archive` of the tagged tree (tracked files only) |
| `appcrane-sbom.cdx.json` | CycloneDX SBOM of the **production** dependency tree |
| `appcrane-sbom.spdx.json` | Same, SPDX format |
| `SHA256SUMS.txt` | Checksums for all of the above |

The source archive carries **build provenance and an SBOM attestation** signed
via sigstore keyless (GitHub artifact attestations) — no long-lived signing key
exists to be stolen. Verify a downloaded archive with:

```bash
gh attestation verify appcrane-<tag>-source.tar.gz --repo gitayg/appCrane
```

Dev dependencies are deliberately excluded from the SBOM — they aren't shipped
to a deployment, and including them would overstate the real attack surface.

## Identity contract for deployed apps

Apps deployed on AppCrane never need to implement their own auth. The Caddy proxy verifies every request against `/api/identity/verify` *before* forwarding it to the container, and the result is delivered to the app in three complementary ways. Apps should consume them in this **precedence order**:

### 1. Request headers (zero-fetch, recommended)

Caddy `copy_headers` the verified identity onto the upstream proxy request. The app reads them directly:

| Header | Value | Notes |
|---|---|---|
| `X-AppCrane-Auth-Mode` | `authenticated` \| `headless` \| `bypass` | Always present on every proxied request, including ones with no identity. Read it first. |
| `X-AppCrane-User` | email | Backward-compat single identifier. Set on `authenticated` requests. |
| `X-AppCrane-User-Id` | numeric id (string) | Set on `authenticated` requests. |
| `X-AppCrane-User-Email` | email | Granular. May be absent if the user has no email. |
| `X-AppCrane-User-Name` | display name, `encodeURIComponent`-d | `decodeURIComponent` on read. May be absent. |
| `X-AppCrane-User-Role` | `platform_admin` \| `admin` \| `user` | Platform-wide tier, raw token. **Not** a per-app permission. |
| `X-AppCrane-App-Role` | `owner` \| `admin` \| `user` \| `viewer` | Per-app role — the one to gate on. An explicit `app_user_roles` row wins over the global-admin fallback, so a platform admin who owns the app arrives as `owner`, not `admin`. |
| `X-AppCrane-Is-Admin` | `1` \| `0` | `1` when the per-app role is `admin` or `owner`. Use it instead of comparing role strings. |

**Trust model:** the Caddy generator wraps the `request_header -X-AppCrane-*` strips and the `forward_auth` block in a `route { … }` so they execute in written order — Caddy's own directive sort would otherwise run the strips *after* `forward_auth` and delete the identity it had just copied. Caddy zeroes out any client-set `X-AppCrane-*` headers first, then `copy_headers` re-injects only what `/verify` returned. The strips are emitted on **every** route that proxies an app, including headless apps and `auth_bypass_paths` prefixes where no `forward_auth` runs at all — a route that verifies nobody must not accept the caller's own `X-AppCrane-Is-Admin`. Header smuggling is impossible — what the app receives is guaranteed platform-issued. Caddy also strips the platform's `cc_token` session cookie out of `Cookie` before it reaches any container (v2.39.0), so an app can't read a visitor's platform session and act as them — **apps must take identity from these headers, never from a cookie**.

**Identity does not require SSO.** `/api/identity/verify` resolves a session from `X-API-Key` or from `Authorization: Bearer` / the `cc_token` cookie against `identity_sessions`. SSO is one way to create such a session; local password login and API keys are others. An instance with no IdP still injects the full header set for logged-in users.

**Absence semantics:** on an `authenticated` app an unverified visitor never reaches the container at all (Caddy fails closed at `forward_auth` and redirects to `/login`), so **presence = trusted**. Identity legitimately absent means `X-AppCrane-Auth-Mode` is `headless` (whole app opted out) or `bypass` (this path is in `auth_bypass_paths`, **or** the app is served on its own custom domain) — in every case the request is served with no verified identity and the app owns its own authn. No `X-AppCrane-Auth-Mode` at all means the request didn't come through AppCrane's proxy — i.e. direct-to-container. A custom-domain app *is* proxied and does get `X-AppCrane-Auth-Mode: bypass`.

**Role ordering:** `none` < `viewer` < `user` < `admin` < `owner`. `appRole === 'admin'` is a bug — it denies owners.

```js
// Express example
const RANK = { none: 0, viewer: 1, user: 2, admin: 3, owner: 4 }
const atLeast = (appRole, min) => (RANK[appRole] ?? 0) >= RANK[min]

app.use((req, res, next) => {
  const mode    = req.get('X-AppCrane-Auth-Mode')   // 'authenticated' | 'headless' | 'bypass'
  const role    = req.get('X-AppCrane-User-Role')   // platform tier
  const appRole = req.get('X-AppCrane-App-Role')    // 'owner' | 'admin' | 'user' | 'viewer'
  const email   = req.get('X-AppCrane-User-Email') || req.get('X-AppCrane-User')
  req.user = (mode === 'authenticated' && role)
    ? { id: req.get('X-AppCrane-User-Id'), email, role, appRole, isAppAdmin: atLeast(appRole, 'admin') }
    : null
  next()
})
```

### 2. `GET /api/me` (when you need more than the basics)

Returns the full user object — name, email, username, global role — plus the per-app role for whatever app the caller is asking about. Same origin as the app, so the browser auto-sends `cc_token`; no SDK or token plumbing required:

```js
const r = await fetch('/api/me')        // ?app=<slug> optional; Referer-inferred otherwise
if (r.status === 401) { location.href = '/login?redirect=' + encodeURIComponent(location.href); return }
const { user, app_role } = await r.json()
```

Auth precedence inside `/api/me`:
1. `cc_token` cookie (proxied apps' default — `httpOnly`, browser-managed).
2. `Authorization: Bearer <session>` (CLI / programmatic).
3. `X-API-Key: dhk_*` (admin / agent keys).

App slug resolution:
1. Explicit `?app=<slug>` query.
2. `Referer`-inferred (first path segment; sandbox-suffix retry).
3. Lean global-only payload if neither resolves.

### 3. Headless apps — opt out entirely

For services where the *whole app* is meant to be unauthenticated — telemetry ingest, public webhooks, status pages, the squash CLI's `ping`/`stats` — set the app's `auth_mode` to `headless` (owner-only toggle in the Launcher, or `appcrane_set_app_meta slug=<…> auth_mode=headless` via MCP). The Caddy block then skips `forward_auth` and `copy_headers`: no identity headers, no `/api/me`, no `cc_token` (that cookie is stripped for every app regardless). The incoming `X-AppCrane-*` strip is **not** skipped — a headless route verifies nobody, so it must not let a caller supply its own identity headers either. `X-AppCrane-Auth-Mode: headless` still arrives, so the app can distinguish "identity is off by design" from a misconfigured proxy. The app's own server takes responsibility for any payload-level authn it needs (HMAC, install-id, IP allowlist, etc.).

Pick by shape:
- **The whole app is unauth ingest** → headless app (clean separation, smaller blast radius).
- **Mostly-auth app with a couple of public endpoints** → keep `authenticated`, gate the public paths at the app's own router.

### 4. Per-tenant DB (multitenancy) — opt in

Opt in with `"multitenant": true` in `deployhub.json` and AppCrane gives each of
your app's users an isolated SQLite database on the persistent `/data` volume —
you don't build tenant isolation yourself. A tenant is **(org, user)**, where
`org` is the user's email domain. This is **fully opt-in**: apps that don't set
the flag are completely unaffected.

When enabled, AppCrane injects `APPCRANE_TENANT_ROOT=/data/tenants`. Use the
[`appcrane-tenant`](packages/tenant) helper to derive the tenant DB from the
identity headers above (section 1) — no path-building by hand:

```js
import { tenantDb } from 'appcrane-tenant'

app.get('/api/notes', (req, res) => {
  const db = tenantDb(req)   // opens /data/tenants/<org>/u<userId>/db.sqlite
  res.json({ notes: db.prepare('SELECT * FROM notes').all() })
})
```

`tenantDbPath(req)` returns just the path if you use a different SQLite driver.
Each tenant also gets a `storage/` dir (`tenantStorageDir(req)` / `tenantFile(req, name)`)
for files. Set `"tenant_quota_mb": <n>` in `deployhub.json` to cap per-tenant
usage — AppCrane injects it and `assertTenantQuota(req)` throws once a tenant is
full (the quota covers DB + storage).

Always build tenant paths via the helper (never from raw user input) — the
identity headers are platform-signed and the org slug is sanitised against
traversal. When a user's access is revoked, AppCrane purges that tenant's dir
automatically. Consumer domains (e.g. `gmail.com`) share an `org` label, but
isolation is per-user, so data never mixes. The helper isn't on npm yet — copy
[`packages/tenant/index.js`](packages/tenant/index.js) or depend on it by path;
see the [multitenant-notes example](examples/multitenant-notes).

## Permission Model

| Action | Admin | App User |
|--------|-------|----------|
| Create/delete apps | Yes | No |
| Assign users | Yes | No |
| Server health | Yes | No |
| Deploy / rollback / promote | **No** | Yes (own apps) |
| View/edit env vars | **No** | Yes (own apps) |
| Configure health/webhooks | **No** | Yes (own apps) |
| Backups | **No** | Yes (own apps) |

## Tech Stack

Node.js 20, Express 5, SQLite, Docker, Caddy 2, SAML/OIDC/SCIM, AES-256-GCM, Commander.js, Ubuntu 22.04+

## License

[GNU AGPL v3](LICENSE). Free and open source — use, modify, and self-host. If you run a modified version as a network service, you must make your source available under the same license. Need to run private modifications as a service, or embed AppCrane in a proprietary product? A [commercial license](COMMERCIAL-LICENSE.md) is available.

## Feedback & Contributions

Open an issue: https://github.com/gitayg/appCrane/issues

Pull requests welcome — please read [CONTRIBUTING.md](CONTRIBUTING.md) first. It includes the short CLA that keeps AppCrane's dual-licensing (AGPL + commercial) possible.
