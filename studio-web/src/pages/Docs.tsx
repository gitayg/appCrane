export function Docs() {
  return (
    <div className="docs-page">
      <style>{`
.docs-page { --code-bg: #1e2130; color: var(--text); line-height: 1.7; font-size: 15px; }
.docs-page * { box-sizing: border-box; }
.docs-page .docs-container { max-width: 820px; margin: 0 auto; padding: 32px 20px 80px; }
.docs-page h1 { font-size: 2rem; margin-bottom: 4px; color: var(--text); }
.docs-page h1 span { color: var(--accent); }
.docs-page .sub { color: var(--dim); margin-bottom: 40px; }
.docs-page h2 { font-size: 1.3rem; margin: 40px 0 12px; color: var(--accent); border-bottom: 1px solid var(--border); padding-bottom: 6px; }
.docs-page h3 { font-size: 1rem; margin: 20px 0 6px; color: var(--text); }
.docs-page p, .docs-page li { color: var(--dim); margin: 6px 0; }
.docs-page ul { padding-left: 20px; }
.docs-page code { background: var(--code-bg); padding: 1px 5px; border-radius: 3px; font-size: .9em; font-family: 'SF Mono', Monaco, monospace; color: var(--text); }
.docs-page pre { background: var(--code-bg); border: 1px solid var(--border); border-radius: 6px; padding: 14px; overflow-x: auto; margin: 10px 0; font-size: .85rem; line-height: 1.5; color: var(--text); }
.docs-page pre code { background: none; padding: 0; }
.docs-page .pill { display: inline-block; padding: 1px 7px; border-radius: 3px; font-size: .72rem; background: rgba(245, 158, 11, .15); color: #fbbf24; border: 1px solid rgba(245, 158, 11, .4); font-family: monospace; }
.docs-page .docs-footer { margin-top: 60px; padding-top: 20px; border-top: 1px solid var(--border); color: var(--dim); font-size: .85rem; }
      `}</style>

      <div className="docs-container">

        <h1>App<span>Crane</span> Docs</h1>
        <p className="sub">
          AppCrane is MCP-first. AI agents operate the platform through the
          <code> appcrane_*</code> tool surface. Humans use the dashboard. The
          CLI handles a small set of box-local ops that can't be done remotely.
        </p>

        <h2>For AI agents</h2>
        <p>
          One <code>claude mcp add</code> command wires AppCrane into your local
          Claude Code. The agent then has access to {25}+ <code>appcrane_*</code> tools
          (list, create, deploy, env, logs, access, icons, …) plus a GitHub
          passthrough if you provide a PAT in the header.
        </p>
        <pre><code>{`claude mcp add --transport http appcrane https://your-host/api/mcp \\
  --header "X-API-Key: <your AppCrane key>" \\
  --header "X-Github-Token: <your GitHub PAT>"`}</code></pre>
        <p>
          Then in any Claude Code session, ask the agent to do the thing —
          onboard an app, deploy a change, debug a fast failure, manage
          access. The agent fetches the current playbook itself by calling
          <code> appcrane_get_guide(topic="onboarding")</code> or
          <code> appcrane_get_guide(topic="operations")</code>; you don't have
          to paste anything.
        </p>

        <h3>The two guides</h3>
        <ul>
          <li>
            <span className="pill">onboarding</span> — new-app playbook. Covers paths
            (a) idea, (b) local code, (c) existing GitHub repo, (d) AppCrane-managed
            repo. The agent reads it the first time you ask it to onboard.
          </li>
          <li>
            <span className="pill">operations</span> — post-onboarding ops reference.
            Deploy lifecycle, troubleshooting decision tree, access management,
            tile icons, deploy constraints.
          </li>
        </ul>

        <h2>For operators on the AppCrane host</h2>
        <p>
          The <code>crane</code> CLI covers what MCP can't reach — anything that
          needs filesystem or systemd access on the box where AppCrane runs:
        </p>
        <ul>
          <li><code>crane init</code> — first-time admin bootstrap (creates the seed user directly in the DB)</li>
          <li><code>crane setup-https</code> — Caddy + Let's Encrypt provisioning</li>
          <li><code>crane caddy</code> — show or reload the generated Caddyfile</li>
          <li><code>crane update</code> — git pull + systemctl restart</li>
          <li><code>crane regenerate-key</code> — recover when the admin key is lost</li>
          <li><code>crane reconcile</code> — register orphaned filesystem apps into the DB</li>
          <li><code>crane status</code> — server health + app summary</li>
        </ul>
        <p>
          App-lifecycle commands (<code>crane app create</code>,
          <code> crane app deploy</code>, etc.) were retired in v2.6.0 — those
          operations live on the MCP surface.
        </p>

        <h2>For humans</h2>
        <p>
          Sign in at <code>/login</code> with email + password (or SSO if your
          admin configured it). The dashboard then exposes everything:
          Applications (manage table or Launcher view), per-user and per-app
          access editors, deploy controls, env vars, logs, request triage.
          API keys aren't pasted into anything human-facing anymore — that
          dual-login path was retired in v2.4.0.
        </p>

        <h2>What's NOT here</h2>
        <p>
          Earlier AppCrane versions exposed a comprehensive curl API reference
          on this page. Retired in v2.6.0 — agents shouldn't be writing curl
          commands, and humans shouldn't either. If you need to script
          AppCrane from outside (CI/CD, webhooks), the
          <code> /api/*</code> endpoints still exist and accept the same
          <code> X-API-Key</code> header as before; the comprehensive
          documentation just isn't a primary surface. Read the source under
          <code> server/routes/</code> if you need to see a specific endpoint.
        </p>

        <div className="docs-footer">
          AppCrane — Self-service app hosting and deployment.
        </div>

      </div>
    </div>
  )
}
