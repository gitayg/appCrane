# AppCrane

Self-hosted deployment manager for running multiple React apps on a single Ubuntu server.

**CLI + REST API + Dashboard.** Manage everything from the command line. AI agents can use the curl API via `/agent-guide`.

## What it does

- **Multi-app management** on one server with isolated processes (PM2 + cgroups)
- **Dual environments** per app: production + sandbox, always-on, separate ports
- **Auto-HTTPS** via Caddy reverse proxy with Let's Encrypt
- **GitHub integration** with webhook auto-deploy on push
- **Rollback** in seconds (symlink-based, keeps last 5 releases)
- **Zero-downtime deploys** (start new, health check, swap, drain old)
- **Encrypted env vars** (AES-256-GCM) with admin isolation (admin can't read them)
- **Health checks** with auto-restart and email notifications
- **Backup/restore** with prod-to-sandbox data copy
- **Audit log** for every action
- **AI-agent friendly** docs at `/agent-guide` (plain markdown, all curl commands)

## Quick Start

```bash
# 1. Clone and install
git clone https://github.com/gitayg/appCrane.git
cd appCrane
npm install
npm link    # makes 'crane' command available globally

# 2. Start the server (background, auto-restarts on crash)
npx pm2 start server/index.js --name appcrane

# 3. Initialize admin (must be run on the server, not remotely)
crane init --name admin --email admin@example.com
# Saves API key automatically to ~/.appcrane/config.json

# 4. Create an app
crane app create \
  --name "MyApp" \
  --slug myapp \
  --domain myapp.example.com \
  --repo https://github.com/yourorg/myapp

# 5. Create a user and assign to the app
crane user create --name sarah --email sarah@example.com
crane app assign myapp --email sarah@example.com

# 6. Deploy (as app user - configure CLI with user's key first)
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
crane app list                            # List all apps
crane app create --name X --slug x --domain x.example.com --repo https://github.com/...
crane app info myapp                   # App details, ports, health, deploys
crane app delete myapp --confirm       # Delete app
crane app assign myapp --email user@example.com
```

### Deploy (app user)
```bash
crane deploy myapp --env sandbox       # Deploy to sandbox
crane deploy myapp --env production    # Deploy to production
crane deploy:history myapp --env prod  # Deploy history
crane deploy:log myapp --id 5          # Build log
crane rollback myapp --env production  # Rollback to previous
crane promote myapp                    # Promote sandbox → production
```

### Env Vars (app user -- admin cannot access)
```bash
crane env set myapp --env sandbox DATABASE_URL=postgres://... API_KEY=sk-test
crane env list myapp --env production
crane env list myapp --env sandbox --reveal   # Show actual values
crane env delete myapp API_KEY --env sandbox
```

### Health (app user)
```bash
crane health status myapp              # Both envs
crane health test myapp --env prod     # Test endpoint now
crane health config myapp --env prod --endpoint /api/health --interval 30
```

### Webhooks, Backups, Logs, Users
```bash
crane webhook myapp                    # Show webhook URL
crane webhook myapp --auto-sandbox on  # Auto-deploy on push
crane backup create myapp --env prod   # Create backup
crane backup list myapp                # List backups
crane logs myapp --env production      # App logs
crane audit --app myapp                # Audit log
crane user list                           # List users (admin)
crane user create --name X --email X      # Create user (admin)
crane notify myapp --email X --on-deploy-fail --on-app-down
```

## curl API (for AI agents)

Every CLI command has a curl equivalent. Point your AI agent to:

```
curl https://crane.example.com/agent-guide
```

This returns a markdown document with every operation as a copy-paste curl command.

### Examples
```bash
export CC="https://crane.example.com"
export KEY="dhk_admin_your_key"

# List apps
curl -s -H "X-API-Key: $KEY" $CC/api/apps

# Create app
curl -s -X POST $CC/api/apps \
  -H "X-API-Key: $KEY" -H "Content-Type: application/json" \
  -d '{"name":"MyApp","slug":"myapp","domain":"myapp.example.com","source_type":"github","github_url":"https://github.com/yourorg/myapp"}'

# Deploy
curl -s -X POST $CC/api/apps/myapp/deploy/sandbox -H "X-API-Key: $KEY"

# Server health
curl -s -H "X-API-Key: $KEY" $CC/api/server/health
```

## Architecture

```
Ubuntu Server
├── Caddy (reverse proxy, auto-HTTPS)
│   ├── myapp.example.com          → production app
│   └── myapp-sandbox.example.com  → sandbox app
├── PM2 (process manager)
│   ├── appcrane              ← manages everything
│   ├── myapp-production
│   └── myapp-sandbox
├── AppCrane API (:5001)
│   ├── Express 5 + SQLite
│   ├── Health checker (cron)
│   └── Email notifications
└── /data/apps/myapp/
    ├── production/releases/   (symlink-based, last 5)
    └── sandbox/releases/
```

## Security

- **Init locked to localhost** -- admin setup can only be done on the server itself
- **API key auth** -- all requests require `X-API-Key` header
- **Admin cannot access env vars or /data/** -- enforced at middleware level
- **Env vars encrypted** at rest (AES-256-GCM)
- **Webhook HMAC** verification for GitHub
- **All actions audited** -- who did what, when

## Permission Model

| Action | Admin | App User |
|--------|-------|----------|
| Create/delete apps | Yes | No |
| Assign users | Yes | No |
| Server health | Yes | No |
| Deploy / rollback / promote | **No** | Yes (own apps) |
| View/edit .env | **No** | Yes (own apps) |
| View/edit /data/ | **No** | Yes (own apps) |
| Configure health/webhooks | **No** | Yes (own apps) |
| Backups | **No** | Yes (own apps) |

## Domain Routing

Each app gets two URLs automatically:
- `appname.example.com` → production
- `appname-sandbox.example.com` → sandbox

Caddy handles HTTPS and routing. Internal ports are managed by AppCrane automatically -- users never need to know or access them.

## PM2 Commands

```bash
npx pm2 list                     # See all processes (appcrane + apps)
npx pm2 logs appcrane          # AppCrane server logs
npx pm2 restart appcrane       # Restart after git pull
npx pm2 stop appcrane          # Stop server
```

## Tech Stack

Node.js, Express 5, SQLite, PM2, Caddy, AES-256-GCM, Commander.js, nodemailer

## Feedback & Contributions

Have ideas, feature requests, or found a bug? Open an issue on GitHub:

https://github.com/gitayg/appCrane/issues

Pull requests welcome. If you're using AppCrane, I'd love to hear about it -- drop a note in the issues or reach out.

## License

FSL-1.1-ALv2 (Functional Source License 1.1, Apache 2.0 Future License). See [LICENSE](LICENSE).

You can use, modify, and self-host AppCrane freely — the only restriction
is offering it as a competing commercial product or hosted service. Each
release automatically converts to Apache 2.0 two years after its release date.
