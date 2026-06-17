// Single comprehensive AppCrane docs page (v2.8.6). Merges the old static
// docs/index.html reference into the modern dashboard app: overview, the full
// MCP tool surface, the app email service, the REST API families, the
// deployhub.json manifest, and the operator CLI — one place, in-app.

const TOOL_GROUPS: { cat: string; tools: [string, string][] }[] = [
  { cat: "Discovery & info", tools: [
    ["appcrane_list_apps", "List all AppCrane apps the current user has access to"],
    ["appcrane_get_app", "Detailed info for a single app: URLs, current versions per env, recent deployments, health state"],
    ["appcrane_get_health", "Fetch the deployed app's health endpoint server-side, bypassing the auth proxy"],
    ["appcrane_get_logs", "Recent runtime logs from a running app container (docker logs)"],
    ["appcrane_get_deploy_log", "Read the deploy/build log for a deployment — clone / install / build / health-validate output"],
    ["appcrane_list_releases", "Deploy/release history for an app + env, newest first (id, version, commit, status, who)"],
    ["appcrane_top_apps", "Top apps by distinct active users in a lookback window"],
    ["appcrane_top_users", "Top users by distinct apps opened in a lookback window"],
  ] },
  { cat: "Deploy lifecycle", tools: [
    ["appcrane_deploy", "Trigger a deployment — this IS how you update an env to the latest"],
    ["appcrane_wait_deploy", "Block until a deployment reaches a terminal state, then return its final status"],
    ["appcrane_rollback", "Roll an env back to a prior release"],
    ["appcrane_promote", "Promote the current live SANDBOX release to production (the gated sandbox->prod path)"],
    ["appcrane_list_cron", "List the scheduled jobs declared in an app's deployhub.json cron array"],
    ["appcrane_run_cron_now", "Trigger a scheduled cron job right now, regardless of its schedule"],
  ] },
  { cat: "App management", tools: [
    ["appcrane_create_app", "Register a new app in AppCrane from a GitHub repository"],
    ["appcrane_create_managed_app", "Create an app using AppCrane's GitHub service-account (no user PAT needed)"],
    ["appcrane_update_app", "Patch fields on an existing app (github_url, branch, token, source_type, resource limits)"],
    ["appcrane_set_app_meta", "Owner self-service fields: category, visibility, auth_mode, auth_bypass_paths"],
    ["appcrane_set_app_icon", "Set the tile icon for an app (Dashboard, Launcher cards, Manage table, frame topbar)"],
  ] },
  { cat: "Env, files & data", tools: [
    ["appcrane_get_env", "Get all environment variables for an app, decrypted"],
    ["appcrane_set_env", "Set or update an environment variable on an app"],
    ["appcrane_set_data_blob", "Write a blob straight to the app's persistent /data volume — no container/GitHub round-trip"],
    ["appcrane_ls", "List files inside a running app container at a path"],
    ["appcrane_cat", "Print the contents of a file inside a running app container"],
    ["appcrane_push_staged_file", "Move a previously-staged file into a running container under /app or /data"],
    ["appcrane_push_to_managed_app", "Push a batch of files to a managed app's repo via the service-account credential"],
  ] },
  { cat: "Access control", tools: [
    ["appcrane_list_app_members", "List everyone with access to an app + their per-app role"],
    ["appcrane_grant_app_access", "Grant a user access to an app at a specific per-app role"],
    ["appcrane_revoke_app_access", "Remove a user's access from an app entirely"],
    ["appcrane_list_access_requests", "List pending access requests from the portal's Request-access button"],
    ["appcrane_approve_access_request", "Approve a pending access request and grant access at a role"],
    ["appcrane_deny_access_request", "Deny a pending access request without granting access"],
  ] },
  { cat: "Requests & guides", tools: [
    ["appcrane_list_requests", "List enhancement requests filed against an app via the intake form"],
    ["appcrane_set_request_status", "Move a request through triage -> in_progress -> shipped -> validated"],
    ["appcrane_get_guide", "Fetch the latest playbook: onboarding, operations, or email"],
  ] },
];

const REST_FAMILIES: { name: string; rows: [string, string, string][] }[] = [
  { name: "Apps", rows: [
    ["GET", "/api/apps", "List apps you can see"],
    ["POST", "/api/apps", "Create an app from a GitHub repo"],
    ["GET", "/api/apps/:slug", "App detail: versions, deploys, health"],
    ["PUT", "/api/apps/:slug", "Update meta (name, visibility, auth_mode, auth_bypass_paths, email_from_name)"],
    ["DELETE", "/api/apps/:slug", "Delete the app"],
    ["POST", "/api/apps/:slug/rename", "Rename the slug (keeps redirects)"],
    ["PUT", "/api/apps/:slug/users", "Set the app's members"],
    ["POST", "/api/apps/:slug/icon", "Upload the tile icon"],
  ] },
  { name: "Deploy", rows: [
    ["POST", "/api/apps/:slug/deploy/:env", "Deploy latest from GitHub"],
    ["POST", "/api/apps/:slug/deploy/upload", "Deploy an uploaded artifact (.zip/.tar.gz)"],
    ["GET", "/api/apps/:slug/deployments/:env", "Deploy history"],
    ["GET", "/api/apps/:slug/deployments/:env/:id/log", "Build log for one deployment"],
    ["POST", "/api/apps/:slug/restart/:env", "Recreate the container with fresh env"],
    ["POST", "/api/apps/:slug/rollback/:env", "Roll back to a prior release"],
    ["POST", "/api/apps/:slug/promote", "Promote live sandbox to production"],
  ] },
  { name: "Environment variables", rows: [
    ["GET", "/api/apps/:slug/env/:env", "List vars (?reveal=true to decrypt)"],
    ["PUT", "/api/apps/:slug/env/:env", "Upsert vars { vars: { KEY: value } }"],
    ["DELETE", "/api/apps/:slug/env/:env/:key", "Delete one var"],
  ] },
  { name: "Health", rows: [
    ["GET", "/api/apps/:slug/health/:env", "Health state"],
    ["PUT", "/api/apps/:slug/health/:env", "Health config (endpoint)"],
    ["POST", "/api/apps/:slug/health/:env/test", "Probe the endpoint now"],
    ["GET", "/api/apps/:slug/live-version/:env", "Version the running container reports"],
  ] },
  { name: "Requests", rows: [
    ["POST", "/api/enhancements", "File an enhancement request"],
    ["GET", "/api/enhancements", "All requests (admin)"],
    ["GET", "/api/enhancements/owned", "Requests for apps you own/admin"],
    ["PUT", "/api/enhancements/:id/bucket", "Move lifecycle: triage/in_progress/shipped/validated"],
  ] },
  { name: "Identity", rows: [
    ["GET", "/api/me", "Caller identity + the apps they can see"],
    ["GET", "/api/identity/me", "Current session identity"],
  ] },
  { name: "App email (internal-only)", rows: [
    ["POST", "/api/service/email", "Send email from an app's server (service-token auth)"],
  ] },
  { name: "Backups", rows: [
    ["POST", "/api/apps/:slug/backup/:env", "Snapshot the /data volume"],
    ["GET", "/api/apps/:slug/backups", "List snapshots"],
    ["POST", "/api/apps/:slug/restore/:id", "Restore a snapshot"],
  ] },
  { name: "Server", rows: [
    ["GET", "/api/info", "Version + status (public)"],
    ["GET", "/api/server/health", "System + apps overview (admin)"],
  ] },
];

const NAV = [
  ["connect", "Connect"],
  ["mcp", "MCP Tools"],
  ["email", "App Email"],
  ["rest", "REST API"],
  ["manifest", "deployhub.json"],
  ["cli", "Operator CLI"],
];

export function Docs() {
  return (
    <div className="docs-page">
      <style>{`
.docs-page { color: var(--text); line-height: 1.7; font-size: 15px; }
.docs-page * { box-sizing: border-box; }
.docs-layout { display: grid; grid-template-columns: 180px 1fr; gap: 32px; max-width: 1000px; margin: 0 auto; padding: 28px 20px 80px; }
.docs-nav { position: sticky; top: 16px; align-self: start; display: flex; flex-direction: column; gap: 2px; }
.docs-nav a { color: var(--dim); text-decoration: none; font-size: .85rem; padding: 4px 8px; border-radius: 5px; }
.docs-nav a:hover { color: var(--accent); background: var(--surface); }
.docs-page h1 { font-size: 1.9rem; margin: 0 0 4px; }
.docs-page h1 span { color: var(--accent); }
.docs-page .sub { color: var(--dim); margin-bottom: 32px; }
.docs-page h2 { font-size: 1.25rem; margin: 36px 0 10px; color: var(--accent); border-bottom: 1px solid var(--border); padding-bottom: 6px; scroll-margin-top: 16px; }
.docs-page h3 { font-size: .95rem; margin: 18px 0 6px; color: var(--text); }
.docs-page p, .docs-page li { color: var(--dim); margin: 6px 0; }
.docs-page ul { padding-left: 20px; }
.docs-page code { background: var(--surface2, #1e2130); padding: 1px 5px; border-radius: 3px; font-size: .88em; font-family: 'SF Mono', Monaco, monospace; color: var(--text); }
.docs-page pre { background: var(--surface2, #1e2130); border: 1px solid var(--border); border-radius: 6px; padding: 14px; overflow-x: auto; margin: 10px 0; font-size: .82rem; line-height: 1.5; color: var(--text); }
.docs-page pre code { background: none; padding: 0; }
.docs-page .pill { display: inline-block; padding: 1px 7px; border-radius: 3px; font-size: .72rem; background: rgba(245,158,11,.15); color: #fbbf24; border: 1px solid rgba(245,158,11,.4); font-family: monospace; }
.docs-tbl { width: 100%; border-collapse: collapse; font-size: .82rem; margin: 6px 0 18px; }
.docs-tbl td { padding: 5px 8px; border-bottom: 1px solid var(--border); vertical-align: top; }
.docs-tbl .m { font-family: monospace; color: var(--accent); white-space: nowrap; width: 56px; font-size: .76rem; }
.docs-tbl .p { font-family: monospace; color: var(--text); white-space: nowrap; }
.docs-tbl .n { color: var(--dim); }
.tool-grp { margin: 6px 0 16px; }
.tool-row { display: grid; grid-template-columns: 230px 1fr; gap: 10px; padding: 3px 0; font-size: .82rem; }
.tool-row code { background: none; padding: 0; color: var(--accent); }
.tool-row .td { color: var(--dim); }
.docs-footer { margin-top: 56px; padding-top: 20px; border-top: 1px solid var(--border); color: var(--dim); font-size: .85rem; }
@media (max-width: 768px) {
  .docs-layout { grid-template-columns: 1fr; gap: 8px; }
  .docs-nav { position: static; flex-direction: row; flex-wrap: wrap; margin-bottom: 8px; }
  .tool-row { grid-template-columns: 1fr; gap: 0; }
}
      `}</style>

      <div className="docs-layout">
        <nav className="docs-nav">
          {NAV.map(([id, label]) => <a key={id} href={`#${id}`}>{label}</a>)}
        </nav>

        <div>
          <h1>App<span>Crane</span> Docs</h1>
          <p className="sub">
            AppCrane is MCP-first. AI agents operate the platform through the
            <code> appcrane_*</code> tool surface; humans use this dashboard; the
            <code> crane</code> CLI covers box-local ops. Everything is on this page.
          </p>

          <h2 id="connect">Connect an agent</h2>
          <p>One command wires AppCrane into a local Claude Code session — it then has all 35 tools below (plus a GitHub passthrough if you supply a PAT):</p>
          <pre><code>{`claude mcp add --transport http appcrane https://your-host/api/mcp \\
  --header "X-API-Key: <your AppCrane key>" \\
  --header "X-Github-Token: <your GitHub PAT>"`}</code></pre>
          <p>
            The agent fetches the live playbook itself:
            <code> appcrane_get_guide(topic="onboarding")</code> (new-app),
            <code> appcrane_get_guide(topic="operations")</code> (full ops + tool reference),
            <code> appcrane_get_guide(topic="email")</code> (sending mail).
          </p>

          <h2 id="mcp">MCP Tools</h2>
          <p>Every <code>appcrane_*</code> tool, grouped by purpose. The authoritative input schema for each is on the tool itself (your MCP client shows it).</p>
          {TOOL_GROUPS.map(g => (
            <div className="tool-grp" key={g.cat}>
              <h3>{g.cat}</h3>
              {g.tools.map(([name, d]) => (
                <div className="tool-row" key={name}>
                  <code>{name}</code>
                  <span className="td">{d}</span>
                </div>
              ))}
            </div>
          ))}

          <h2 id="email">App Email</h2>
          <p>
            Any hosted app can send email through AppCrane — server-side only, async, and only to
            <b> registered platform users</b> (never an arbitrary address). Nothing to enable: every deploy
            auto-injects <code>APPCRANE_SERVICE_TOKEN</code> and <code>CRANE_INTERNAL_URL</code> into the
            container. From the app's server (never the browser):
          </p>
          <pre><code>{`await fetch(\`\${process.env.CRANE_INTERNAL_URL}/api/service/email\`, {
  method: "POST",
  headers: {
    "Content-Type": "application/json",
    "X-AppCrane-Service-Token": process.env.APPCRANE_SERVICE_TOKEN,
  },
  body: JSON.stringify({ to: userEmail, subject: "Hi", text: "Hello" }),
});
// 202 { queued: true } -- delivered async, 5 retries + backoff`}</code></pre>
          <p>
            Recipient must be a registered user (a <code>400</code> otherwise). The logged-in user's email
            arrives on every request as the <code>x-appcrane-user-email</code> header — use it as
            <code> to</code>. Sender is the mailbox set in <code>Settings -&gt; Mail</code>; apps set only the
            display name and reply-to. Full reference: <code>appcrane_get_guide(topic="email")</code>.
          </p>

          <h2 id="rest">REST API</h2>
          <p>
            For scripting from outside (CI/CD, webhooks). Authenticate with the <code>X-API-Key</code> header
            (your AppCrane key). Agents should prefer the MCP tools above; these are the same operations over HTTP.
          </p>
          {REST_FAMILIES.map(f => (
            <div key={f.name}>
              <h3>{f.name}</h3>
              <table className="docs-tbl"><tbody>
                {f.rows.map(([m, p, n]) => (
                  <tr key={m + p}><td className="m">{m}</td><td className="p">{p}</td><td className="n">{n}</td></tr>
                ))}
              </tbody></table>
            </div>
          ))}

          <h2 id="manifest">deployhub.json manifest</h2>
          <p>Committed at the repo root; tells AppCrane how to build and run the app.</p>
          <pre><code>{`{
  "name": "My App",
  "be": { "entry": "node server/index.js", "health": "/api/health" },
  "data_dirs": ["data/"],
  "env_example": ".env.example",
  "cron": [
    { "name": "rebuild", "schedule": "0 0 * * *", "command": "python /app/build.py" }
  ]
}`}</code></pre>
          <p>
            Health endpoint must return <code>200</code> + JSON with <code>status</code> and <code>version</code>.
            <code> cron</code> jobs run host-side via <code>docker exec</code>; <code>/data</code> is the only
            path that survives a redeploy.
          </p>

          <h2 id="cli">Operator CLI</h2>
          <p>The <code>crane</code> CLI covers what MCP can't reach — anything needing filesystem or systemd access on the host:</p>
          <ul>
            <li><code>crane init</code> — first-time admin bootstrap</li>
            <li><code>crane setup-https</code> — Caddy + Let's Encrypt</li>
            <li><code>crane caddy</code> — show or reload the generated Caddyfile</li>
            <li><code>crane update</code> — git pull + systemctl restart</li>
            <li><code>crane regenerate-key</code> — recover a lost admin key</li>
            <li><code>crane reconcile</code> — register orphaned filesystem apps into the DB</li>
            <li><code>crane status</code> — server health + app summary</li>
          </ul>

          <div className="docs-footer">
            AppCrane — Self-service app hosting and deployment.
          </div>
        </div>
      </div>
    </div>
  )
}
