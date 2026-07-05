# AppCrane

**The self-hosted home for the apps your AI builds and your AI deploys.**

[![GitHub stars](https://img.shields.io/github/stars/gitayg/appCrane?style=flat)](https://github.com/gitayg/appCrane/stargazers)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](LICENSE)
![Platform: Ubuntu 22.04+](https://img.shields.io/badge/platform-Ubuntu%2022.04%2B-e95420)

Vibe-code an app with Claude Code or Cursor, then have your AI agent deploy it — over MCP — to a server **you** own. AppCrane is a self-hosted, **agent-first** deployment platform with the enterprise guardrails the cloud PaaS crowd skips: Docker isolation per app, SAML/OIDC/SCIM SSO, per-user audit, and a middleware hard-wall so the platform operator can't read your app secrets (your model API keys stay yours). A self-hosted alternative to Heroku, Vercel, and hosted agent-deploy services like AppDeploy.

**MCP-first.** AI agents connect once via `claude mcp add ... /api/mcp` and operate the platform through 38 `appcrane_*` tools. No curl, no separate scripts — `appcrane_get_guide(topic="onboarding"|"operations")` returns the latest playbook on demand.

## Why AppCrane

| Feature | AppCrane | Coolify | Dokploy |
|---|---|---|---|
| Agent-first / MCP-native | ✅ | ❌ | ~ add-on |
| Self-hosted, your infra | ✅ | ✅ | ✅ |
| Enterprise SSO (SAML/OIDC/SCIM) | ✅ | ~ | ❌ |
| Secret hard-wall (operator can't read) | ✅ | ❌ | ❌ |
| Managed repo (no GitHub account) | ✅ | ❌ | ❌ |
| Docker isolation per app | ✅ | ✅ | ✅ |
| Dual sandbox/prod environments | ✅ | ~ | ✅ |
| Zero-downtime deploys | ✅ | ~ | ✅ |
| Open source | ✅ AGPL-3.0 | ✅ Apache-2.0 | ✅ Apache-2.0 |

**Full matrix** vs AWS Copilot / App Runner / Lightsail / CodeDeploy / Vercel / AppDeploy → **[glick.run/comparison.html](https://glick.run/comparison.html)**

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
- **MCP server** at `/api/mcp` exposing 38 `appcrane_*` tools — agents operate the platform without ever touching curl, gh, or shell

## Quick Start

```bash
curl -fsSL https://raw.githubusercontent.com/gitayg/appCrane/main/install.sh | sudo bash
```

Or manually:

```bash
# 1. Clone and install
git clone https://github.com/gitayg/appCrane.git
cd appCrane
npm install
npm link    # makes 'crane' command available globally

# 2. Install and start via systemd
cp scripts/appcrane.service /etc/systemd/system/appcrane.service
systemctl daemon-reload
systemctl enable --now appcrane

# 2.5. (Optional) Set Anthropic API key for AppStudio
# Add to the systemd unit so it survives restarts:
systemctl edit appcrane --force
# Add under [Service]: Environment="ANTHROPIC_API_KEY=sk-ant-..."
# Then: systemctl daemon-reload && systemctl restart appcrane

# 3. Initialize admin (must run on the server)
crane init --name admin --email admin@example.com

# 4. Create an app
crane app create \
  --name "MyApp" \
  --slug myapp \
  --domain myapp.example.com \
  --repo https://github.com/yourorg/myapp

# 5. Create a user and assign to the app
crane user create --name sarah --email sarah@example.com
crane app assign myapp --email sarah@example.com

# 6. Deploy
crane config --key dhk_user_the_key_from_step_5
crane deploy myapp --env sandbox
```

## CLI Reference

### Server
```bash
crane status                              # Server health: CPU, RAM, disk, apps
crane config --show                       # Show CLI config
crane config --url http://localhost:5001  # Set API URL
crane config --key dhk_admin_xxx          # Set API key
```

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

## Identity contract for deployed apps

Apps deployed on AppCrane never need to implement their own auth. The Caddy proxy verifies every request against `/api/identity/verify` *before* forwarding it to the container, and the result is delivered to the app in three complementary ways. Apps should consume them in this **precedence order**:

### 1. Request headers (zero-fetch, recommended)

Caddy `copy_headers` the verified identity onto the upstream proxy request. The app reads them directly:

| Header | Value | Notes |
|---|---|---|
| `X-AppCrane-User` | email | Backward-compat single identifier. Always set for authenticated requests. |
| `X-AppCrane-User-Id` | numeric id (string) | Always set. |
| `X-AppCrane-User-Email` | email | Granular. May be absent if the user has no email. |
| `X-AppCrane-User-Name` | display name, `encodeURIComponent`-d | `decodeURIComponent` on read. May be absent. |
| `X-AppCrane-User-Role` | `platform_admin` \| `admin` \| `user` | Raw token, underscore intact. Always set. |
| `X-AppCrane-App-Role` | `owner` \| `admin` \| `user` \| `viewer` | Per-app role. Platform admins collapse to `admin` on every app — branch on `X-AppCrane-User-Role` if you specifically need to target platform admins. |

**Trust model:** the Caddy generator emits `request_header -X-AppCrane-*` strip directives *before* the `forward_auth` block in each per-app handler. Caddy zeroes out any client-set `X-AppCrane-*` headers first, then `copy_headers` re-injects only what `/verify` returned. Header smuggling is impossible — what the app receives is guaranteed platform-issued.

**Absence semantics:** if `X-AppCrane-User-Role` isn't on the request, the request was *not* verified (Caddy failed closed at `forward_auth` and you wouldn't receive it). So **presence = trusted**.

```js
// Express example
app.use((req, res, next) => {
  const role    = req.get('X-AppCrane-User-Role')    // 'platform_admin' | 'admin' | 'user'
  const appRole = req.get('X-AppCrane-App-Role')     // 'owner' | 'admin' | 'user' | 'viewer'
  const email   = req.get('X-AppCrane-User-Email') || req.get('X-AppCrane-User')
  req.user = role ? { id: req.get('X-AppCrane-User-Id'), email, role, appRole } : null
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

For services where the *whole app* is meant to be unauthenticated — telemetry ingest, public webhooks, status pages, the squash CLI's `ping`/`stats` — set the app's `auth_mode` to `headless` (owner-only toggle in the Launcher, or `appcrane_set_app_meta slug=<…> auth_mode=headless` via MCP). The Caddy block then skips `forward_auth`, copy_headers, and the strips entirely. No `X-AppCrane-*` headers, no `/api/me`, no `cc_token`. The app's own server takes responsibility for any payload-level authn it needs (HMAC, install-id, IP allowlist, etc.).

Pick by shape:
- **The whole app is unauth ingest** → headless app (clean separation, smaller blast radius).
- **Mostly-auth app with a couple of public endpoints** → keep `authenticated`, gate the public paths at the app's own router.

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
